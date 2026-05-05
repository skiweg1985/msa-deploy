from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi.security import HTTPBasicCredentials


ROOT_DIR = Path(__file__).resolve().parents[2]
SAT_DIR = ROOT_DIR / "backend" / "mdns-sat"

if str(SAT_DIR) not in sys.path:
    sys.path.insert(0, str(SAT_DIR))

if "websockets" not in sys.modules:
    sys.modules["websockets"] = types.SimpleNamespace(connect=None)

mdns_sat = importlib.import_module("mdns_sat")


def test_sat_ui_auth_disabled_allows_inbound_requests():
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update({"ui_auth_enabled": False})
        auth_ok = mdns_sat.require_ui_auth(None)
        payload = mdns_sat.api_health()
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)

    assert auth_ok is True
    assert payload["status"] == "ok"


def test_sat_ui_auth_enabled_requires_credentials():
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(
            {
                "ui_auth_enabled": True,
                "ui_auth_username": "admin",
                "ui_auth_password": "secret123",
            }
        )

        with pytest.raises(HTTPException) as exc_info:
            mdns_sat.require_ui_auth(None)
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers["WWW-Authenticate"] == "Basic"


def test_sat_ui_auth_enabled_rejects_wrong_credentials():
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(
            {
                "ui_auth_enabled": True,
                "ui_auth_username": "admin",
                "ui_auth_password": "secret123",
            }
        )

        credentials = HTTPBasicCredentials(
            username="admin",
            password="wrong",
        )
        with pytest.raises(HTTPException) as exc_info:
            mdns_sat.require_ui_auth(credentials)
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers["WWW-Authenticate"] == "Basic"


def test_health_endpoint_is_public_even_when_ui_auth_enabled():
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(
            {
                "sat_id": "sat-a",
                "hub_url": "http://hub.local",
                "publish_to_hub": False,
                "hub_register_enabled": False,
                "ui_auth_enabled": True,
                "ui_auth_username": "admin",
                "ui_auth_password": "secret123",
            }
        )

        with TestClient(mdns_sat.app) as client:
            response = client.get("/health")
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)

    assert response.status_code == 200


def test_sat_ui_auth_enabled_accepts_correct_credentials():
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(
            {
                "sat_id": "sat-a",
                "hub_url": "http://hub.local",
                "publish_to_hub": False,
                "hub_register_enabled": False,
                "ui_auth_enabled": True,
                "ui_auth_username": "admin",
                "ui_auth_password": "secret123",
            }
        )

        credentials = HTTPBasicCredentials(
            username="admin",
            password="secret123",
        )
        auth_ok = mdns_sat.require_ui_auth(credentials)
        payload = mdns_sat.api_health()
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)

    assert auth_ok is True
    assert payload["status"] == "ok"
