from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Response
import pytest
from starlette.requests import Request
import starlette.templating as starlette_templating


REPO_ROOT = Path(__file__).resolve().parents[2]
HUB_DIR = REPO_ROOT / "backend" / "mdns-hub"


class DummyTemplates:
    def __init__(self, *args, **kwargs):
        pass

    def TemplateResponse(self, *args, **kwargs):  # pragma: no cover - not used in auth tests
        raise RuntimeError("Template rendering is not available in auth tests")


def build_request(
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    client_host: str = "127.0.0.1",
) -> Request:
    raw_headers = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "headers": raw_headers,
        "query_string": b"",
        "client": (client_host, 12345),
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope)


def session_cookie_from_response(response: Response) -> str:
    set_cookie = response.headers["set-cookie"]
    return set_cookie.split(";", 1)[0]


def load_hub_module(tmp_path: Path):
    config_path = tmp_path / "hub_config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "security:",
                "  shared_secret: 'shared-secret'",
                "  ui_auth_enabled: true",
                "  admin_username: 'admin'",
                "  admin_password: 'secret123'",
                "  session_secret: 'session-secret-for-tests'",
                "  session_ttl_seconds: 3600",
                "  allowed_origins:",
                "    - 'http://testserver'",
            ]
        ),
        encoding="utf-8",
    )

    os.environ["MDNS_HUB_CONFIG"] = str(config_path)
    sys.path.insert(0, str(HUB_DIR))
    starlette_templating.Jinja2Templates = DummyTemplates
    for module_name in ("hub_config", "auth", "logging_config", "models", "mdns_profiles"):
        sys.modules.pop(module_name, None)

    module_name = f"hub_main_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, HUB_DIR / "main.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    module.DATA_DIR = data_dir
    module.SATELLITES_FILE = data_dir / "satellites.json"
    module.SAT_CONFIGS_FILE = data_dir / "sat_configs.json"
    module.SAT_GROUPS_FILE = data_dir / "sat_groups.json"
    module.SERVICE_REGISTRY_FILE = data_dir / "service_registry.json"
    module.HUB_UI_SETTINGS_FILE = data_dir / "hub_ui_settings.json"

    module.SATELLITES.clear()
    module.SATELLITE_CONFIGS.clear()
    module.SAT_GROUPS.clear()
    module.INGESTED_SERVICES_BY_SAT.clear()
    module.SERVICE_REGISTRY.clear()
    module.ACTIVE_SAT_WEBSOCKETS.clear()
    module.ACTIVE_UI_WEBSOCKETS.clear()
    module.SAT_WS_STATE.clear()

    return module


def test_login_session_logout_flow(tmp_path: Path):
    module = load_hub_module(tmp_path)

    anonymous_request = build_request("/api/v1/auth/session")
    anonymous_session = module.auth_session(anonymous_request)
    assert anonymous_session["authRequired"] is True
    assert anonymous_session["authenticated"] is False

    bad_request = build_request("/api/v1/auth/login", method="POST")
    bad_response = Response()
    try:
        asyncio.run(module.auth_login(bad_request, bad_response, {"username": "admin", "password": "wrong"}))
        raise AssertionError("Expected invalid login to raise")
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401

    login_request = build_request("/api/v1/auth/login", method="POST")
    login_response = Response()
    login_payload = asyncio.run(
        module.auth_login(login_request, login_response, {"username": "admin", "password": "secret123"})
    )
    assert login_payload["authenticated"] is True
    assert "set-cookie" in login_response.headers

    cookie_header = session_cookie_from_response(login_response)
    session_request = build_request("/api/v1/auth/session", headers={"cookie": cookie_header})
    session_payload = module.auth_session(session_request)
    assert session_payload["authenticated"] is True
    assert session_payload["username"] == "admin"
    assert session_payload["csrfToken"]

    logout_request = build_request(
        "/api/v1/auth/logout",
        method="POST",
        headers={"cookie": cookie_header, "x-csrf-token": session_payload["csrfToken"]},
    )
    logout_response = Response()
    logout_payload = asyncio.run(module.auth_logout(logout_request, logout_response))
    assert logout_payload["authenticated"] is False

    cleared_request = build_request("/api/v1/auth/session", headers={"cookie": cookie_header})
    cleared_payload = module.auth_session(cleared_request)
    assert cleared_payload["authenticated"] is False


def test_mutation_requires_session_and_csrf(tmp_path: Path):
    module = load_hub_module(tmp_path)

    request_without_session = build_request("/api/v1/satellites/sat-01/config", method="PUT")
    try:
        asyncio.run(module.require_ui_mutation_session(request_without_session))
        raise AssertionError("Expected missing session to raise")
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401

    login_request = build_request("/api/v1/auth/login", method="POST")
    login_response = Response()
    login_payload = asyncio.run(
        module.auth_login(login_request, login_response, {"username": "admin", "password": "secret123"})
    )
    cookie_header = session_cookie_from_response(login_response)
    csrf_token = login_payload["csrfToken"]

    missing_csrf_request = build_request(
        "/api/v1/satellites/sat-01/config",
        method="PUT",
        headers={"cookie": cookie_header},
    )
    try:
        asyncio.run(module.require_ui_mutation_session(missing_csrf_request))
        raise AssertionError("Expected missing CSRF token to raise")
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 403

    valid_request = build_request(
        "/api/v1/satellites/sat-01/config",
        method="PUT",
        headers={
            "cookie": cookie_header,
            "x-csrf-token": csrf_token,
        },
    )
    session = asyncio.run(module.require_ui_mutation_session(valid_request))
    config = module.SatConfig(
        satellite_id="sat-01",
        interfaces=[
            module.SatInterface(
                name="eth0",
                mode="scan",
                vlan_id=None,
                ip_mode="dhcp",
                ip_address=None,
            )
        ],
    )
    saved = asyncio.run(module.set_sat_config(valid_request, "sat-01", config, session))
    assert saved.satellite_id == "sat-01"


def test_api_access_guard_deny_by_default(tmp_path: Path):
    module = load_hub_module(tmp_path)

    async def call_next(_request):
        return Response(status_code=200)

    unauth_request = build_request("/api/v1/services", method="GET")
    unauth_response = asyncio.run(module.api_access_guard(unauth_request, call_next))
    assert unauth_response.status_code == 401

    auth_session_request = build_request("/api/v1/auth/session", method="GET")
    auth_session_response = asyncio.run(module.api_access_guard(auth_session_request, call_next))
    assert auth_session_response.status_code == 200

    sat_token_request = build_request(
        "/api/v1/services",
        method="GET",
        headers={"x-satellite-token": "shared-secret"},
    )
    sat_token_response = asyncio.run(module.api_access_guard(sat_token_request, call_next))
    assert sat_token_response.status_code == 200


def test_sat_interface_parent_interface_is_optional_and_exposed_in_api(tmp_path: Path):
    module = load_hub_module(tmp_path)

    legacy_cfg = module.SatConfig.model_validate(
        {
            "satellite_id": "sat-legacy",
            "interfaces": [
                {
                    "name": "ens160",
                    "mode": "scan",
                    "ip_mode": "dhcp",
                },
                {
                    "name": "ens160.230",
                    "mode": "advertise",
                    "vlan_id": 230,
                    "description": "Mobile",
                },
            ],
        }
    )

    assert legacy_cfg.interfaces[1].parent_interface is None

    module.SATELLITES["sat-legacy"] = module.SatMeta(
        hostname="sat-legacy.local",
        mgmt_interface="ens160",
    )
    module.SATELLITE_CONFIGS["sat-legacy"] = module.SatConfig(
        satellite_id="sat-legacy",
        interfaces=[
            module.SatInterface(
                name="ens160",
                mode="scan",
                ip_mode="dhcp",
                ip_address=None,
                description="Mgmt",
            ),
            module.SatInterface(
                name="ens160.230",
                parent_interface="ens160",
                mode="advertise",
                vlan_id=230,
                ip_mode="none",
                ip_address=None,
                description="Mobile",
            ),
        ],
    )

    payload = module.api_sat_interfaces()
    sat_payload = next(item for item in payload if item["sat_id"] == "sat-legacy")

    assert sat_payload["interfaces"][0]["parent_interface"] is None
    assert sat_payload["interfaces"][0]["description"] == "Mgmt"
    assert sat_payload["interfaces"][1]["parent_interface"] == "ens160"
    assert sat_payload["interfaces"][1]["description"] == "Mobile"


def test_api_sat_interfaces_exposes_mgmt_ip_and_client_ip(tmp_path: Path):
    module = load_hub_module(tmp_path)

    # Case 1: explicit mgmt_ip_address + client_ip recorded in SatMeta.
    module.SATELLITES["sat-explicit"] = module.SatMeta(
        hostname="sat-explicit.local",
        mgmt_interface="eth0",
        mgmt_ip_address="10.0.0.10",
        mgmt_ip_mode="static",
        client_ip="10.0.0.99",
    )
    module.SATELLITE_CONFIGS["sat-explicit"] = module.SatConfig(
        satellite_id="sat-explicit",
        interfaces=[
            module.SatInterface(
                name="eth0",
                mode="scan",
                ip_mode="static",
                ip_address="10.0.0.10",
                description="Mgmt",
            ),
        ],
    )

    # Case 2: no explicit mgmt_ip_address - fallback must use the interface
    # entry whose name matches the mgmt interface.
    module.SATELLITES["sat-fallback"] = module.SatMeta(
        hostname="sat-fallback.local",
        mgmt_interface="ens160",
    )
    module.SATELLITE_CONFIGS["sat-fallback"] = module.SatConfig(
        satellite_id="sat-fallback",
        interfaces=[
            module.SatInterface(
                name="ens160",
                mode="scan",
                ip_mode="static",
                ip_address="192.168.1.42",
                description="Mgmt",
            ),
        ],
    )

    # Case 3: no mgmt IP at all - must be reported as None, not missing.
    module.SATELLITES["sat-blank"] = module.SatMeta(
        hostname="sat-blank.local",
        mgmt_interface=None,
    )

    payload = module.api_sat_interfaces()
    by_id = {item["sat_id"]: item for item in payload}

    explicit = by_id["sat-explicit"]
    assert "mgmt_ip_address" in explicit
    assert "client_ip" in explicit
    assert explicit["mgmt_ip_address"] == "10.0.0.10"
    assert explicit["client_ip"] == "10.0.0.99"

    fallback = by_id["sat-fallback"]
    # Derived from the matching interface as documented inline in
    # api_sat_interfaces (safe fallback for legacy registrations).
    assert fallback["mgmt_ip_address"] == "192.168.1.42"
    assert fallback["client_ip"] is None

    blank = by_id["sat-blank"]
    assert blank["mgmt_ip_address"] is None
    assert blank["client_ip"] is None


def test_per_sat_ttl_keeps_registry_online_when_another_sat_has_fresh_service(tmp_path: Path):
    module = load_hub_module(tmp_path)

    now = datetime.now(timezone.utc)
    stale_seen = now - timedelta(minutes=20)
    fresh_seen = now - timedelta(minutes=1)

    stale_instance = module.ServiceInstance(
        service_name="_ipp._tcp.local",
        instance_name="Office Printer._ipp._tcp.local",
        hostname="printer.local",
        addresses=["10.0.0.20"],
        port=631,
        last_seen=stale_seen,
    )
    fresh_instance = module.ServiceInstance(
        service_name="_ipp._tcp.local",
        instance_name="Office Printer._ipp._tcp.local",
        hostname="printer.local",
        addresses=["10.0.1.20"],
        port=631,
        last_seen=fresh_seen,
    )
    service_key = module.service_key(fresh_instance)

    module.INGESTED_SERVICES_BY_SAT["sat-stale"] = {service_key: stale_instance}
    module.INGESTED_SERVICES_BY_SAT["sat-fresh"] = {service_key: fresh_instance}
    module.SERVICE_REGISTRY[service_key] = module.ServiceRegistryEntry(
        service_key=service_key,
        last_instance=fresh_instance,
        last_seen=fresh_seen,
        last_sat_id="sat-fresh",
        online=True,
        spoof_enabled=True,
        spoof_targets=[module.SpoofTarget(sat_id="sat-target")],
    )

    request = build_request("/api/v1/satellites/sat-stale/services", method="POST")
    response = module.ingest_services(
        "sat-stale",
        module.ServiceIngestRequest(satellite_id="sat-stale", services=[]),
        request,
        True,
    )

    assert response["known_for_sat"] == 0
    assert service_key not in module.INGESTED_SERVICES_BY_SAT["sat-stale"]

    entry = module.SERVICE_REGISTRY[service_key]
    assert entry.online is True
    assert entry.last_instance == fresh_instance
    assert entry.last_sat_id == "sat-fresh"
    assert entry.last_seen == fresh_seen

    assignments = module.build_spoof_assignments_for_sat("sat-target")
    assert [assignment.service_key for assignment in assignments] == [service_key]


def test_assignment_broadcast_timeout_does_not_block_other_satellites(tmp_path: Path, monkeypatch):
    module = load_hub_module(tmp_path)
    sent_to: list[str] = []

    class SlowSocket:
        async def send_json(self, _message):
            await asyncio.sleep(0.05)
            sent_to.append("slow")

    class FastSocket:
        async def send_json(self, _message):
            sent_to.append("fast")

    module.ACTIVE_SAT_WEBSOCKETS["slow"] = SlowSocket()
    module.ACTIVE_SAT_WEBSOCKETS["fast"] = FastSocket()
    monkeypatch.setattr(module, "WS_SEND_TIMEOUT_SECONDS", 0.01)

    asyncio.run(module.broadcast_assignments_to_all_sats())

    assert sent_to == ["fast"]
    assert "slow" not in module.ACTIVE_SAT_WEBSOCKETS
    assert "fast" in module.ACTIVE_SAT_WEBSOCKETS


def test_satellite_register_updates_named_mgmt_interface_not_first_interface(tmp_path: Path):
    module = load_hub_module(tmp_path)

    module.SATELLITES["sat-01"] = module.SatMeta(
        hostname="sat-01.local",
        mgmt_interface="ens160",
        mgmt_ip_address="192.168.1.10/24",
        mgmt_ip_mode="static",
    )
    module.SATELLITE_CONFIGS["sat-01"] = module.SatConfig(
        satellite_id="sat-01",
        interfaces=[
            module.SatInterface(
                name="ens160.230",
                parent_interface="ens160",
                vlan_id=230,
                mode="advertise",
                ip_mode="none",
                description="Mobile",
            ),
            module.SatInterface(
                name="ens160",
                mode="scan",
                ip_mode="static",
                ip_address="192.168.1.10/24",
                description="Mgmt",
            ),
        ],
    )

    request = build_request("/api/v1/satellites/register", method="POST")
    response = module.register_sat(
        module.SatRegisterRequest(
            satellite_id="sat-01",
            hostname="sat-01.local",
            auth_token="ignored",
            mgmt_interface="ens160",
            mgmt_ip_address="192.168.1.20/24",
            mgmt_ip_mode="static",
        ),
        request,
        True,
    )

    interfaces = response.assigned_config.interfaces
    assert interfaces[0].name == "ens160.230"
    assert interfaces[0].ip_address is None
    assert interfaces[1].name == "ens160"
    assert interfaces[1].ip_address == "192.168.1.20/24"


def test_sat_interface_rejects_invalid_values(tmp_path: Path):
    module = load_hub_module(tmp_path)

    invalid_payloads = [
        {"name": "", "mode": "scan", "ip_mode": "none"},
        {"name": "ens160", "mode": "bad", "ip_mode": "none"},
        {"name": "ens160", "mode": "scan", "ip_mode": "bad"},
        {"name": "ens160.5000", "parent_interface": "ens160", "vlan_id": 5000, "mode": "scan", "ip_mode": "none"},
        {"name": "ens160", "mode": "scan", "ip_mode": "static", "ip_address": "not-an-ip"},
    ]

    for payload in invalid_payloads:
        with pytest.raises(Exception):
            module.SatInterface(**payload)

    valid = module.SatInterface(
        name="ens160.230",
        parent_interface="ens160",
        vlan_id=230,
        mode="scan_and_advertise",
        ip_mode="static",
        ip_address="192.168.230.2/24",
    )
    assert valid.name == "ens160.230"
    assert valid.vlan_id == 230
