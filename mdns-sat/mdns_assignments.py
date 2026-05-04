# mdns_assignments.py

import time
import logging
from typing import Any, Dict, List, Optional

import requests
from mdns_mode import is_hub_registration_enabled

logger = logging.getLogger("mdns-sat.assignments")


def get_hub_base_url(cfg: Dict[str, Any]) -> str:
    """
    Basis-URL des Hubs (ohne abschließenden Slash).
    Erwartet Konfig-Schlüssel 'hub_url'.
    """
    return cfg["hub_url"].rstrip("/")


def sat_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    """
    HTTP-Header für Requests des Satelliten an den Hub.
    Erwartet Konfig-Schlüssel 'shared_secret'.
    """
    return {
        "Content-Type": "application/json",
        "X-Satellite-Token": cfg["shared_secret"],
    }


def fetch_assignments(cfg: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Holt Spoof-Assignments:
      1. Bevorzugt aus dem WebSocket-Cache (cfg["ws_assignments"]), wenn frisch
      2. Fallback via HTTP, wenn WS-Cache leer oder älter als N Sekunden
    """
    if not is_hub_registration_enabled(cfg):
        logger.info("Hub-Assignments deaktiviert, da hub_register_enabled=false gesetzt ist.")
        return []

    ws_assignments = cfg.get("ws_assignments", None)
    ws_ts = cfg.get("ws_assignments_received_at", 0.0)
    now = time.time()
    max_ws_age = int(cfg.get("ws_assignments_max_age", 60))  # z.B. 60 Sekunden

    # 1) Frischer WS-Cache → benutzen
    if ws_assignments is not None and now - ws_ts <= max_ws_age:
        logger.debug(
            "Nutze Spoof-Assignments aus WS-Cache (%d Einträge, age=%.1fs).",
            len(ws_assignments),
            now - ws_ts,
        )
        return ws_assignments

    if ws_assignments is not None:
        logger.warning(
            "WS-Assignments veraltet oder leer (age=%.1fs, count=%d) – hole per HTTP neu.",
            now - ws_ts,
            len(ws_assignments),
        )

    # 2) Fallback: HTTP
    base_url = get_hub_base_url(cfg)
    sat_id = cfg["sat_id"]
    url = f"{base_url}/api/v1/satellites/{sat_id}/spoof-assignments"
    logger.debug("Hole Spoof-Assignments via HTTP von %s", url)

    try:
        resp = requests.get(url, headers=sat_headers(cfg), timeout=10)
        resp.raise_for_status()
    except Exception as e:
        logger.error("HTTP-Fehler beim Abruf der Assignments: %s", e)
        return None

    data = resp.json()
    if isinstance(data, dict) and "assignments" in data:
        return data["assignments"]
    if isinstance(data, list):
        return data

    logger.warning("Unerwartetes JSON-Format für Assignments: %s", data)
    return []


def assignment_matches_iface(assignment: Dict[str, Any], iface: Optional[str]) -> bool:
    """
    Prüft, ob ein Assignment zu einem Interface gehört.

    spoof_target.iface kann sein:
      - None
      - "ens160"
      - "ens160,ens192"
      - ["ens160", "ens192"]

    Wenn iface=None → wir nehmen nur Assignments ohne iface-Spezifikation.
    """
    target = assignment.get("spoof_target") or {}
    iface_field = target.get("iface")

    if iface is None:
        # Prozess ohne spezifisches Interface → nur Assignments ohne iface-Feld
        return iface_field in (None, "", [])

    if iface_field is None:
        # Assignment ist "global" – auf allen Interfaces gültig
        return True

    if isinstance(iface_field, list):
        return iface in iface_field

    if isinstance(iface_field, str):
        parts = [p.strip() for p in iface_field.split(",") if p.strip()]
        return iface in parts

    return False
