from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

from fastapi.testclient import TestClient


ROOT_DIR = Path(__file__).resolve().parents[2]
SAT_DIR = ROOT_DIR / "backend" / "mdns-sat"

if str(SAT_DIR) not in sys.path:
    sys.path.insert(0, str(SAT_DIR))

if "websockets" not in sys.modules:
    sys.modules["websockets"] = types.SimpleNamespace(connect=None)

mdns_sat = importlib.import_module("mdns_sat")


def _auth_cfg():
    return {
        "sat_id": "sat-ui",
        "hub_url": "http://hub.local",
        "publish_to_hub": False,
        "hub_register_enabled": False,
        "ui_auth_enabled": True,
        "ui_auth_username": "admin",
        "ui_auth_password": "secret123",
    }


def _auth_headers():
    import base64

    token = base64.b64encode(b"admin:secret123").decode("ascii")
    return {"Authorization": f"Basic {token}"}


def test_ui_root_redirects_to_service_overview_html():
    original = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(_auth_cfg())

        with TestClient(mdns_sat.app) as client:
            unauth = client.get("/ui")
            assert unauth.status_code == 401

            ok = client.get("/ui", headers=_auth_headers())
            assert ok.status_code == 200
            body = ok.text
            # Shared topbar + service overview markers
            assert "MSA" in body
            assert "Service-Übersicht" in body or "Services" in body
            # Must still expose the service table columns
            assert "Instance" in body
            assert "Service" in body
            assert "Host / IPs" in body
            assert "Last Seen" in body
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original)


def test_ui_root_slash_also_serves_service_overview():
    original = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(_auth_cfg())

        with TestClient(mdns_sat.app) as client:
            unauth = client.get("/")
            assert unauth.status_code == 401

            ok = client.get("/", headers=_auth_headers())
            assert ok.status_code == 200
            # Default page must contain the service table heading
            assert "Erfasste mDNS" in ok.text
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original)


def test_ui_admin_route_serves_admin_html_with_auth():
    original = dict(mdns_sat.SAT_CONFIG)
    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(_auth_cfg())

        with TestClient(mdns_sat.app) as client:
            unauth = client.get("/ui/admin")
            assert unauth.status_code == 401

            ok = client.get("/ui/admin", headers=_auth_headers())
            assert ok.status_code == 200
            body = ok.text
            # Admin UI must contain structured sections (not JSON-only)
            assert "Overview" in body
            assert "Spoofing" in body
            assert "Metrics" in body
            assert "Settings" in body
            assert "Actions" in body
            # Restart confirm + advanced JSON fallback present
            assert "restartConfirmOverlay" in body
            assert "Advanced" in body
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original)
