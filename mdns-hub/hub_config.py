"""
Central configuration loader for the mDNS Hub.

This module provides access to hub_config.yaml with support for
nested sections (e.g. logging, security, spoofing, enrichment).
"""

from __future__ import annotations
from typing import Any, Dict
from pathlib import Path
import os
import logging 

from logging_config import LOGGING_CONFIG, get_logger
logger = get_logger(f"mdns_hub.config")

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "hub_config.yaml"

def _load_config() -> Dict[str, Any]:
    """
    Loads the hub configuration file (YAML). Returns an empty dictionary
    if the file is missing, unreadable or PyYAML is not available.
    """
    config_path_str = os.getenv("MDNS_HUB_CONFIG", str(DEFAULT_CONFIG_PATH))
    config_path = Path(config_path_str)

    if not config_path.exists():
        logger.info(
            "No hub_config.yaml found at %s; using empty configuration",
            config_path,
        )
        return {}

    if yaml is None:
        logger.info(
            "PyYAML is not available; cannot load %s, using empty configuration",
            config_path,
        )
        return {}

    logger.info("Loading hub configuration from %s", config_path)

    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
            logger.warning(
                "hub_config.yaml root element is not a dict; using empty configuration"
            )
    except Exception as exc:
        logger.warning(
            "Failed to load hub configuration from %s (%s); using empty configuration",
            config_path,
            exc,
        )

    return {}

_CONFIG = _load_config()


def get_section(name: str) -> Dict[str, Any]:
    """
    Returns a subsection of the configuration, such as 'security',
    'logging', 'hub', 'spoofing', etc.
    """
    section = _CONFIG.get(name)
    return section if isinstance(section, dict) else {}



def get_security_value(key: str, default: Any = None) -> Any:
    security = get_section("security")
    if key in security:
        logger.info("Security value '%s' loaded from config", key)
        return security[key]

    logger.info(
        "Security value '%s' not found in config; using default value", key
    )
    return default


def get_security_bool(key: str, default: bool = False) -> bool:
    value = get_security_value(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def get_security_int(key: str, default: int) -> int:
    value = get_security_value(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_security_list(key: str, default: list[str] | None = None) -> list[str]:
    value = get_security_value(key, default or [])
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return list(default or [])


def get_ui_value(key: str, default: Any = None) -> Any:
    ui = get_section("ui")
    if key in ui:
        logger.info("UI value '%s' loaded from config", key)
        return ui[key]

    logger.info(
        "UI value '%s' not found in config; using default value", key
    )
    return default
