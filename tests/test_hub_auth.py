from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import uuid
from pathlib import Path

from fastapi import Response
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
