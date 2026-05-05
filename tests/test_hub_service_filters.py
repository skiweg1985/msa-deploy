from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
HUB_DIR = ROOT_DIR / "backend" / "mdns-hub"
FRONTEND_ASSETS_DIR = HUB_DIR / "frontend" / "assets"

FRONTEND_ASSETS_DIR.mkdir(parents=True, exist_ok=True)

if str(HUB_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_DIR))

hub_models = importlib.import_module("models")
hub_main = importlib.import_module("main")


def test_normalize_service_type_list_trims_deduplicates_and_drops_empty():
    assert hub_models.normalize_service_type_list(
        [" _airplay._tcp.local ", "", "_ipp._tcp.local", "_airplay._tcp.local", None]
    ) == [
        "_airplay._tcp.local",
        "_ipp._tcp.local",
    ]


def test_build_available_service_type_options_merges_static_observed_and_saved():
    options = hub_main.build_available_service_type_options(
        static_default_service_types=["_airplay._tcp.local", "_ipp._tcp.local"],
        observed_service_types=["_ipp._tcp.local", "_sonos._tcp.local"],
        include_service_types=["_custom._tcp.local", "_airplay._tcp.local"],
    )

    assert [(option.name, option.source) for option in options] == [
        ("_airplay._tcp.local", "static+saved"),
        ("_custom._tcp.local", "saved"),
        ("_ipp._tcp.local", "static+observed"),
        ("_sonos._tcp.local", "observed"),
    ]


def test_hub_service_filter_routes_are_registered():
    routes = {
        (route.path, tuple(sorted(getattr(route, "methods", []) or [])))
        for route in hub_main.app.routes
        if hasattr(route, "path")
    }
    assert ("/api/v1/ui/service-filters", ("GET",)) in routes
    assert ("/api/v1/ui/service-filters", ("PUT",)) in routes


def test_get_service_filters_uses_config_defaults_when_file_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(hub_main, "HUB_UI_SETTINGS_FILE", tmp_path / "hub_ui_settings.json")
    monkeypatch.setattr(
        hub_main,
        "get_ui_value",
        lambda key, default=None: {"default_include_service_types": [" _airplay._tcp.local ", "_ipp._tcp.local"]}
        if key == "service_filters"
        else default,
    )

    hub_main.SERVICE_REGISTRY = {
        "service-a": hub_models.ServiceRegistryEntry(
            service_key="service-a",
            last_instance=hub_models.ServiceInstance(
                service_name="_sonos._tcp.local",
                instance_name="Living Room._sonos._tcp.local",
            ),
        )
    }
    hub_main.load_hub_ui_settings()

    payload = hub_main.get_ui_service_filters().model_dump(mode="json")

    assert payload["include_service_types"] == ["_airplay._tcp.local", "_ipp._tcp.local"]
    assert payload["static_default_service_types"] == ["_airplay._tcp.local", "_ipp._tcp.local"]
    assert payload["observed_service_types"] == ["_sonos._tcp.local"]
    assert payload["available_service_types"] == [
        {"name": "_airplay._tcp.local", "source": "static+saved"},
        {"name": "_ipp._tcp.local", "source": "static+saved"},
        {"name": "_sonos._tcp.local", "source": "observed"},
    ]


def test_put_service_filters_persists_normalized_state_and_empty_list(tmp_path, monkeypatch):
    settings_file = tmp_path / "hub_ui_settings.json"

    monkeypatch.setattr(hub_main, "HUB_UI_SETTINGS_FILE", settings_file)
    monkeypatch.setattr(
        hub_main,
        "get_ui_value",
        lambda key, default=None: {"default_include_service_types": ["_airplay._tcp.local"]}
        if key == "service_filters"
        else default,
    )

    hub_main.SERVICE_REGISTRY = {
        "service-a": hub_models.ServiceRegistryEntry(
            service_key="service-a",
            last_instance=hub_models.ServiceInstance(
                service_name="_sonos._tcp.local",
                instance_name="Living Room._sonos._tcp.local",
            ),
        )
    }
    hub_main.load_hub_ui_settings()

    response = hub_main.update_ui_service_filters(
        hub_models.ServiceFilterConfigUpdate(
            include_service_types=[
                " _custom._tcp.local ",
                "_custom._tcp.local",
                "",
                "_sonos._tcp.local",
            ]
        )
    )

    assert response.model_dump(mode="json")["include_service_types"] == [
        "_custom._tcp.local",
        "_sonos._tcp.local",
    ]

    persisted = json.loads(settings_file.read_text(encoding="utf-8"))
    assert persisted == {
        "service_filters": {
            "include_service_types": [
                "_custom._tcp.local",
                "_sonos._tcp.local",
            ]
        }
    }

    empty_response = hub_main.update_ui_service_filters(
        hub_models.ServiceFilterConfigUpdate(include_service_types=[])
    )
    assert empty_response.model_dump(mode="json")["include_service_types"] == []

    get_response = hub_main.get_ui_service_filters()
    assert get_response.model_dump(mode="json")["include_service_types"] == []

    persisted_after_empty = json.loads(settings_file.read_text(encoding="utf-8"))
    assert persisted_after_empty == {
        "service_filters": {
            "include_service_types": []
        }
    }
