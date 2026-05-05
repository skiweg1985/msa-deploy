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


def _reset_cfg():
    mdns_sat.SAT_CONFIG.clear()
    mdns_sat.SAT_CONFIG.update(
        {
            "sat_id": "sat-1",
            "hub_url": "http://hub.local",
            "publish_to_hub": True,
            "hub_register_enabled": True,
            "hub_ws_enabled": True,
            "config_poll_interval": 10,
            "mdns_query_interval": 5,
            "mdns_resolve_interval": 15,
            "mdns_resolve_unicast": True,
            "excluded_services": ["_airplay._tcp.local"],
            "manage_vlan_interfaces": True,
            "ui_auth_enabled": True,
            "ui_auth_username": "admin",
            "ui_auth_password": "secret123",
            "shared_secret": "topsecret",
        }
    )


def _auth_headers():
    import base64

    token = base64.b64encode(b"admin:secret123").decode("ascii")
    return {"Authorization": f"Basic {token}"}


def test_admin_endpoints_require_auth_and_health_is_public(tmp_path, monkeypatch):
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    original_path = mdns_sat.SAT_CONFIG_PATH
    try:
        _reset_cfg()
        mdns_sat.SAT_CONFIG_PATH = tmp_path / "sat_config.yaml"

        with TestClient(mdns_sat.app) as client:
            assert client.get("/health").status_code == 200
            assert client.get("/admin/overview").status_code == 401

            ok = client.get("/admin/overview", headers=_auth_headers())
            assert ok.status_code == 200
            assert "workers" in ok.json()
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)
        mdns_sat.SAT_CONFIG_PATH = original_path


def test_admin_settings_update_validates_and_redacts_secrets(tmp_path):
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    original_path = mdns_sat.SAT_CONFIG_PATH
    try:
        _reset_cfg()
        mdns_sat.SAT_CONFIG_PATH = tmp_path / "sat_config.yaml"

        with TestClient(mdns_sat.app) as client:
            before = client.get("/admin/settings", headers=_auth_headers())
            assert before.status_code == 200
            readonly = before.json().get("readonly", {})
            assert readonly.get("shared_secret") == "***redacted***"
            assert readonly.get("ui_auth_password") == "***redacted***"

            bad = client.put(
                "/admin/settings",
                headers=_auth_headers(),
                json={"settings": {"sat_id": "forbidden"}, "apply_now": False},
            )
            assert bad.status_code == 400

            good = client.put(
                "/admin/settings",
                headers=_auth_headers(),
                json={
                    "settings": {
                        "publish_to_hub": False,
                        "mdns_query_interval": 9,
                        "excluded_services": ["_ipp._tcp.local"],
                    },
                    "apply_now": False,
                },
            )
            assert good.status_code == 200
            payload = good.json()
            assert payload["changed"]["publish_to_hub"] is False
            assert payload["changed"]["mdns_query_interval"] == 9
            assert mdns_sat.SAT_CONFIG["mdns_query_interval"] == 9
            assert mdns_sat.SAT_CONFIG_PATH.exists()
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)
        mdns_sat.SAT_CONFIG_PATH = original_path


def test_restart_action_response_shape(tmp_path, monkeypatch):
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    original_path = mdns_sat.SAT_CONFIG_PATH
    original_restart = mdns_sat.restart_workers_from_runtime_config
    try:
        _reset_cfg()
        mdns_sat.SAT_CONFIG_PATH = tmp_path / "sat_config.yaml"

        def _fake_restart(reason: str = "manual"):
            return {
                "status": "ok",
                "reason": reason,
                "started_workers": 2,
                "stopped_workers": 1,
                "duration_ms": 12,
                "time": "2026-01-01T00:00:00Z",
            }

        monkeypatch.setattr(mdns_sat, "restart_workers_from_runtime_config", _fake_restart)

        with TestClient(mdns_sat.app) as client:
            resp = client.post("/admin/actions/restart-workers", headers=_auth_headers())
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "ok"
            assert body["reason"] == "admin_action"
            assert "started_workers" in body
            assert "duration_ms" in body
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)
        mdns_sat.SAT_CONFIG_PATH = original_path
        mdns_sat.restart_workers_from_runtime_config = original_restart
