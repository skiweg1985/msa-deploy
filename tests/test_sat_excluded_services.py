from __future__ import annotations

import importlib
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
SAT_DIR = ROOT_DIR / "backend" / "mdns-sat"

if str(SAT_DIR) not in sys.path:
    sys.path.insert(0, str(SAT_DIR))

mdns_utils = importlib.import_module("mdns_utils")


def test_build_service_snapshot_keeps_sat_excluded_services_semantics():
    cfg = {
        "excluded_services": ["_homekit._tcp.local"],
        "hub_config": {
            "interfaces": [
                {"name": "eth0", "mode": "scan"},
            ]
        },
    }

    original_cache = mdns_utils.SERVICE_CACHE
    mdns_utils.SERVICE_CACHE = {
        "allowed._airplay._tcp.local": {
            "service_name": "_airplay._tcp.local",
            "instance_name": "allowed._airplay._tcp.local",
            "addresses": {"10.0.0.10"},
            "src_ips": {"10.0.0.10"},
            "src_ifaces": {"eth0"},
            "txt": [],
        },
        "blocked._homekit._tcp.local": {
            "service_name": "_homekit._tcp.local",
            "instance_name": "blocked._homekit._tcp.local",
            "addresses": {"10.0.0.11"},
            "src_ips": {"10.0.0.11"},
            "src_ifaces": {"eth0"},
            "txt": [],
        },
    }

    try:
        snapshot = mdns_utils.build_service_snapshot(cfg)
    finally:
        mdns_utils.SERVICE_CACHE = original_cache

    assert [item["service_name"] for item in snapshot] == ["_airplay._tcp.local"]
