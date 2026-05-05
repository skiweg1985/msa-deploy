"""
Central logging configuration for the mDNS Hub application.

This module loads log level settings from a YAML configuration file
(hub_config.yaml) and builds a unified logging setup for Uvicorn and
application-level loggers.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # Fallback if PyYAML is not installed


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "hub_config.yaml"


def _load_hub_config() -> Dict[str, Any]:
    """
    Loads hub configuration from a YAML file.

    The path can be overridden by the environment variable
    MDNS_HUB_CONFIG. If the file does not exist or cannot be parsed,
    an empty configuration is returned.
    """
    config_path_str = os.getenv("MDNS_HUB_CONFIG", str(DEFAULT_CONFIG_PATH))
    config_path = Path(config_path_str)

    if not config_path.exists():
        return {}

    if yaml is None:
        # PyYAML is not available, return empty config
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        # Any parsing or IO error falls back to empty config
        return {}

    return {}


_HUB_CONFIG = _load_hub_config()


def _get_logging_section() -> Dict[str, Any]:
    """
    Returns the logging section from the hub configuration.

    If no logging section is present, an empty dict is returned.
    """
    logging_cfg = _HUB_CONFIG.get("logging", {})
    if isinstance(logging_cfg, dict):
        return logging_cfg
    return {}


def _to_level(value: str, default: str = "INFO") -> str:
    """
    Normalizes a string to a valid logging level name.

    If the provided value is not a valid level, the default is returned.
    """
    valid_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
    if not value:
        return default
    upper = str(value).upper()
    if upper not in valid_levels:
        return default
    return upper


def _level_from_config(key: str, default: str) -> str:
    """
    Reads a log level from the hub_config logging section.

    If the key is missing or invalid, the provided default level is used.
    """
    logging_section = _get_logging_section()
    raw = logging_section.get(key)
    if raw is None:
        return default
    return _to_level(str(raw), default)


# Resolve levels from configuration (with sane defaults)
ROOT_LEVEL = _level_from_config("root_level", "INFO")
MDNS_HUB_LEVEL = _level_from_config("mdns_hub_level", "INFO")
UVICORN_LEVEL = _level_from_config("uvicorn_level", "INFO")
UVICORN_ERROR_LEVEL = _level_from_config("uvicorn_error_level", "INFO")
UVICORN_ACCESS_LEVEL = _level_from_config("uvicorn_access_level", "INFO")


# Unified logging configuration used by Uvicorn and application modules.
LOGGING_CONFIG: Dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "default": {
            "format": "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        },
    },

    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },

    "loggers": {
        # Uvicorn internal loggers
        "uvicorn": {
            "handlers": ["default"],
            "level": UVICORN_LEVEL,
            "propagate": False,
        },
        "uvicorn.error": {
            "handlers": ["default"],
            "level": UVICORN_ERROR_LEVEL,
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": ["default"],
            "level": UVICORN_ACCESS_LEVEL,
            "propagate": False,
        },

        # Application logger root
        "mdns_hub": {
            "handlers": ["default"],
            "level": MDNS_HUB_LEVEL,
            "propagate": False,
        },
    },

    # Fallback for any logger without an explicit configuration
    "root": {
        "handlers": ["default"],
        "level": ROOT_LEVEL,
    },
}


def get_logger(name: str = "mdns_hub") -> logging.Logger:
    """
    Returns a logger instance that follows the central logging configuration.

    Parameters
    ----------
    name : str
        The logger name to retrieve.

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    return logging.getLogger(name)