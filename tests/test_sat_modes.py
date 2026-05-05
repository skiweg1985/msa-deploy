from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest


ROOT_DIR = Path(__file__).resolve().parents[2]
SAT_DIR = ROOT_DIR / "backend" / "mdns-sat"

if str(SAT_DIR) not in sys.path:
    sys.path.insert(0, str(SAT_DIR))

if "websockets" not in sys.modules:
    sys.modules["websockets"] = types.SimpleNamespace(connect=None)

mdns_assignments = importlib.import_module("mdns_assignments")
mdns_mode = importlib.import_module("mdns_mode")
mdns_sat = importlib.import_module("mdns_sat")
mdns_utils = importlib.import_module("mdns_utils")
sat_ws = importlib.import_module("sat_ws")


def test_load_config_applies_mode_defaults(tmp_path: Path):
    cfg_file = tmp_path / "sat_config.yaml"
    cfg_file.write_text(
        'sat_id: "sat-a"\n'
        'hub_url: "http://hub.local"\n'
        'shared_secret: "secret"\n',
        encoding="utf-8",
    )

    cfg = mdns_sat.load_config(cfg_file)

    assert cfg["publish_to_hub"] is True
    assert cfg["hub_register_enabled"] is True


def test_load_config_rejects_publish_without_register(tmp_path: Path):
    cfg_file = tmp_path / "sat_config.yaml"
    cfg_file.write_text(
        'sat_id: "sat-a"\n'
        'publish_to_hub: true\n'
        'hub_register_enabled: false\n',
        encoding="utf-8",
    )

    with pytest.raises(SystemExit):
        mdns_sat.load_config(cfg_file)


def test_load_config_allows_local_only_without_hub_credentials(tmp_path: Path):
    cfg_file = tmp_path / "sat_config.yaml"
    cfg_file.write_text(
        'sat_id: "sat-local"\n'
        'publish_to_hub: false\n'
        'hub_register_enabled: false\n'
        'local_interfaces:\n'
        '  - name: "eth0"\n'
        '    mode: "scan"\n',
        encoding="utf-8",
    )

    cfg = mdns_sat.load_config(cfg_file)

    assert cfg["hub_register_enabled"] is False
    assert cfg["publish_to_hub"] is False
    assert mdns_mode.resolve_interface_configs(cfg) == [{"name": "eth0", "mode": "scan"}]


def test_push_services_to_hub_is_skipped_when_publish_is_disabled(monkeypatch: pytest.MonkeyPatch):
    called = False

    def fake_post(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("requests.post darf bei publish_to_hub=false nicht aufgerufen werden")

    monkeypatch.setattr(mdns_sat.requests, "post", fake_post)

    mdns_sat.push_services_to_hub(
        {
            "sat_id": "sat-a",
            "hub_url": "http://hub.local",
            "shared_secret": "secret",
            "publish_to_hub": False,
            "hub_register_enabled": True,
        }
    )

    assert called is False


def test_build_service_snapshot_is_empty_when_publish_is_disabled():
    cfg = {
        "publish_to_hub": False,
        "hub_register_enabled": True,
        "hub_config": {
            "interfaces": [
                {"name": "eth0", "mode": "scan"},
            ]
        },
    }

    original_cache = mdns_utils.SERVICE_CACHE
    mdns_utils.SERVICE_CACHE = {
        "printer._ipp._tcp.local": {
            "service_name": "_ipp._tcp.local",
            "instance_name": "printer._ipp._tcp.local",
            "addresses": {"10.0.0.25"},
            "src_ips": {"10.0.0.25"},
            "src_ifaces": {"eth0"},
            "txt": [],
        }
    }

    try:
        assert mdns_utils.build_service_snapshot(cfg) == []
    finally:
        mdns_utils.SERVICE_CACHE = original_cache


def test_ws_client_disables_service_snapshots_when_publish_is_disabled():
    client = sat_ws.SatWebSocketClient(
        {
            "sat_id": "sat-a",
            "shared_secret": "secret",
            "hub_url": "http://hub.local",
            "publish_to_hub": False,
            "hub_register_enabled": True,
            "hub_ws_enabled": True,
            "hub_ws_send_services": True,
        },
        on_message=lambda msg: None,
        stop_event=importlib.import_module("threading").Event(),
    )

    assert client.send_services is False


def test_fetch_assignments_returns_empty_without_hub_registration(monkeypatch: pytest.MonkeyPatch):
    def fake_get(*args, **kwargs):
        raise AssertionError("requests.get darf ohne Hub-Registrierung nicht aufgerufen werden")

    monkeypatch.setattr(mdns_assignments.requests, "get", fake_get)

    assignments = mdns_assignments.fetch_assignments(
        {
            "sat_id": "sat-local",
            "publish_to_hub": False,
            "hub_register_enabled": False,
        }
    )

    assert assignments == []


def test_api_health_reports_local_only_as_ok():
    original_cfg = dict(mdns_sat.SAT_CONFIG)
    original_status = dict(mdns_sat.HUB_STATUS)

    try:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(
            {
                "sat_id": "sat-local",
                "publish_to_hub": False,
                "hub_register_enabled": False,
                "local_interfaces": [{"name": "eth0", "mode": "scan"}],
            }
        )
        mdns_sat.HUB_STATUS["last_ok"] = None
        mdns_sat.HUB_STATUS["last_error"] = None

        payload = mdns_sat.api_health()
    finally:
        mdns_sat.SAT_CONFIG.clear()
        mdns_sat.SAT_CONFIG.update(original_cfg)
        mdns_sat.HUB_STATUS.clear()
        mdns_sat.HUB_STATUS.update(original_status)

    assert payload["status"] == "ok"
    assert payload["mode"] == "local_only"
    assert payload["hub_status"] == "disabled"
    assert payload["publish_to_hub"] is False
    assert payload["hub_register_enabled"] is False
    assert payload["interface_config_source"] == "local"


def test_generate_link_local_for_vlan_deterministic():
    assert mdns_sat._generate_link_local_for_vlan(1) == "169.254.0.2/16"
    assert mdns_sat._generate_link_local_for_vlan(222) == "169.254.0.223/16"
    assert mdns_sat._generate_link_local_for_vlan(300) == "169.254.1.47/16"
    assert mdns_sat._generate_link_local_for_vlan(4094) == "169.254.16.31/16"
