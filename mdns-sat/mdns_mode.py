from __future__ import annotations

from typing import Any, Dict, List


CONFIG_DEFAULTS: Dict[str, Any] = {
    "publish_to_hub": True,
    "hub_register_enabled": True,
    "ui_auth_enabled": False,
    "ui_auth_username": "admin",
    "ui_auth_password": "",
}


def apply_sat_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(cfg)
    for key, value in CONFIG_DEFAULTS.items():
        merged.setdefault(key, value)
    return merged


def is_publish_to_hub_enabled(cfg: Dict[str, Any]) -> bool:
    return bool(cfg.get("publish_to_hub", True))


def is_hub_registration_enabled(cfg: Dict[str, Any]) -> bool:
    return bool(cfg.get("hub_register_enabled", True))


def is_ui_auth_enabled(cfg: Dict[str, Any]) -> bool:
    return bool(cfg.get("ui_auth_enabled", False))


def get_ui_auth_username(cfg: Dict[str, Any]) -> str:
    return str(cfg.get("ui_auth_username", "admin") or "").strip()


def get_ui_auth_password(cfg: Dict[str, Any]) -> str:
    return str(cfg.get("ui_auth_password", "") or "")


def is_monitor_only_mode(cfg: Dict[str, Any]) -> bool:
    return (not is_publish_to_hub_enabled(cfg)) and is_hub_registration_enabled(cfg)


def is_local_only_mode(cfg: Dict[str, Any]) -> bool:
    return (not is_publish_to_hub_enabled(cfg)) and (not is_hub_registration_enabled(cfg))


def get_mode_key(cfg: Dict[str, Any]) -> str:
    if is_local_only_mode(cfg):
        return "local_only"
    if is_monitor_only_mode(cfg):
        return "monitor_only"
    return "normal"


def get_mode_label(cfg: Dict[str, Any]) -> str:
    mode_key = get_mode_key(cfg)
    if mode_key == "monitor_only":
        return "Monitor-only"
    if mode_key == "local_only":
        return "Local-only"
    return "Normalbetrieb"


def get_mode_description(cfg: Dict[str, Any]) -> str:
    mode_key = get_mode_key(cfg)
    if mode_key == "monitor_only":
        return "Lokale Discovery und UI aktiv, Hub-Registrierung aktiv, Service-Publish deaktiviert."
    if mode_key == "local_only":
        return "Lokale Discovery und UI aktiv, keine Hub-Registrierung und kein Hub-Publish."
    return "Hub-Registrierung, Hub-Config und Service-Publish aktiv."


def is_ws_enabled(cfg: Dict[str, Any]) -> bool:
    return is_hub_registration_enabled(cfg) and bool(cfg.get("hub_ws_enabled", False))


def validate_sat_config(cfg: Dict[str, Any]) -> None:
    if not cfg.get("sat_id"):
        raise ValueError("Fehlender Pflichtparameter in config: sat_id")

    if is_ui_auth_enabled(cfg):
        if not get_ui_auth_username(cfg):
            raise ValueError(
                "Ungültige Konfiguration: ui_auth_enabled=true erfordert ui_auth_username."
            )
        if not get_ui_auth_password(cfg):
            raise ValueError(
                "Ungültige Konfiguration: ui_auth_enabled=true erfordert ui_auth_password."
            )

    publish_enabled = is_publish_to_hub_enabled(cfg)
    register_enabled = is_hub_registration_enabled(cfg)

    if publish_enabled and not register_enabled:
        raise ValueError(
            "Ungültige Konfiguration: publish_to_hub=true erfordert hub_register_enabled=true."
        )

    if register_enabled:
        for key in ("hub_url", "shared_secret"):
            if not cfg.get(key):
                raise ValueError(f"Fehlender Pflichtparameter in config: {key}")


def resolve_interface_configs(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    hub_cfg = cfg.get("hub_config") or {}
    hub_interfaces = hub_cfg.get("interfaces") or []
    if hub_interfaces:
        return hub_interfaces

    local_interfaces = cfg.get("local_interfaces") or []
    return local_interfaces if isinstance(local_interfaces, list) else []


def get_interface_config_source(cfg: Dict[str, Any]) -> str:
    hub_cfg = cfg.get("hub_config") or {}
    if hub_cfg.get("interfaces"):
        return "hub"
    if cfg.get("local_interfaces"):
        return "local"
    return "none"
