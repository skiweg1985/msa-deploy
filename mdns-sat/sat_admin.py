from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml


REDACTED_VALUE = "***redacted***"

EDITABLE_SETTINGS_SCHEMA: Dict[str, Dict[str, Any]] = {
    "publish_to_hub": {"type": "bool"},
    "hub_register_enabled": {"type": "bool"},
    "hub_ws_enabled": {"type": "bool"},
    "config_poll_interval": {"type": "int", "min": 1},
    "mdns_query_interval": {"type": "int", "min": 1},
    "mdns_resolve_interval": {"type": "int", "min": 1},
    "mdns_resolve_unicast": {"type": "bool"},
    "excluded_services": {"type": "list[str]"},
    "manage_vlan_interfaces": {"type": "bool"},
}

READ_ONLY_SETTINGS_KEYS = (
    "sat_id",
    "shared_secret",
    "hub_url",
    "ui_auth_password",
    "ui_auth_username",
    "ui_auth_enabled",
)

SECRET_SETTINGS_KEYS = {
    "shared_secret",
    "ui_auth_password",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AdminStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, Any] = {
            "queries_sent_total": 0,
            "queries_received_total": 0,
            "responses_sent_total": 0,
            "spoof_announces_total": 0,
            "spoof_goodbyes_total": 0,
            "hub_push_ok_total": 0,
            "hub_push_error_total": 0,
            "worker_restart_total": 0,
            "errors_total": 0,
            "last_worker_restart_at": None,
            "started_at": utc_now_iso(),
        }

    def increment(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] = int(self._counters.get(key, 0)) + amount

    def mark_worker_restart(self) -> None:
        with self._lock:
            self._counters["worker_restart_total"] = int(
                self._counters.get("worker_restart_total", 0)
            ) + 1
            self._counters["last_worker_restart_at"] = utc_now_iso()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._counters)


ADMIN_STATS = AdminStats()


def _normalize_bool(key: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"Ungültiger Typ für '{key}': erwartet bool.")


def _normalize_int(key: str, value: Any, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Ungültiger Typ für '{key}': erwartet int.")
    if minimum is not None and value < minimum:
        raise ValueError(f"Ungültiger Wert für '{key}': muss >= {minimum} sein.")
    return value


def _normalize_list_str(key: str, value: Any) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f"Ungültiger Typ für '{key}': erwartet list[str].")

    normalized: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"Ungültiger Typ für '{key}': erwartet list[str].")
        trimmed = item.strip()
        if trimmed:
            normalized.append(trimmed)

    return normalized


def validate_admin_settings_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Ungültiges Settings-Payload: erwartet Objekt.")

    normalized: Dict[str, Any] = {}
    for key, value in payload.items():
        schema = EDITABLE_SETTINGS_SCHEMA.get(key)
        if schema is None:
            raise ValueError(f"Setting '{key}' ist nicht editierbar.")

        field_type = schema["type"]
        if field_type == "bool":
            normalized[key] = _normalize_bool(key, value)
        elif field_type == "int":
            normalized[key] = _normalize_int(key, value, schema.get("min"))
        elif field_type == "list[str]":
            normalized[key] = _normalize_list_str(key, value)
        else:
            raise ValueError(f"Unbekannter Schema-Typ für '{key}'.")

    return normalized


def redact_setting(key: str, value: Any) -> Any:
    if key in SECRET_SETTINGS_KEYS and value not in (None, ""):
        return REDACTED_VALUE
    return value


def build_admin_settings_payload(cfg: Dict[str, Any]) -> Dict[str, Any]:
    editable = {
        key: cfg.get(key)
        for key in EDITABLE_SETTINGS_SCHEMA
    }
    readonly = {
        key: redact_setting(key, cfg.get(key))
        for key in READ_ONLY_SETTINGS_KEYS
        if key in cfg
    }
    schema = {
        key: {"type": meta["type"]}
        for key, meta in EDITABLE_SETTINGS_SCHEMA.items()
    }
    return {
        "editable": editable,
        "readonly": readonly,
        "schema": schema,
    }


def persist_sat_config(path: Path, cfg: Dict[str, Any]) -> None:
    persisted = dict(cfg)
    persisted.pop("hub_config", None)
    persisted.pop("ws_assignments", None)
    persisted.pop("assignments_updated_at", None)
    persisted.pop("ws_assignments_received_at", None)

    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            persisted,
            handle,
            allow_unicode=False,
            sort_keys=False,
            default_flow_style=False,
        )
