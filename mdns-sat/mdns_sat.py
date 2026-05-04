#!/usr/bin/env python3
import logging
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import uvicorn
import yaml
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse

from mdns_utils import (
    SERVICE_CACHE,
    CACHE_LOCK,
    DISCOVERED_SERVICE_TYPES,
    build_service_snapshot,
    wants_sniff,
    wants_advertise,
    is_service_reported_to_hub,
)
from mdns_worker import MdnsInterfaceWorker
import threading

import signal
import atexit

from sat_ws import SatWebSocketClient
from mdns_mode import (
    apply_sat_defaults,
    get_interface_config_source,
    get_mode_description,
    get_mode_key,
    get_mode_label,
    is_hub_registration_enabled,
    is_publish_to_hub_enabled,
    is_ws_enabled,
    resolve_interface_configs,
    validate_sat_config,
)

ws_client: Optional[SatWebSocketClient] = None
ws_stop_event: Optional[threading.Event] = None


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = Path("sat_config.yaml")

MCAST_GRP = "224.0.0.251"
MDNS_PORT = 5353

# VLAN-Interfaces, die von diesem Sat verwaltet werden, markieren wir mit diesem Alias
MANAGED_VLAN_ALIAS = "mdns-sat-managed-vlan"

# Einfacher Status zur letzten Kommunikation mit dem Hub
HUB_STATUS: Dict[str, Any] = {
    "last_ok": None,        # ISO-Timestamp der letzten erfolgreichen Hub-Kommunikation
    "last_error": None,     # {"time": ..., "msg": "..."} der letzten Fehlersituation
}

SAT_CONFIG: Dict[str, Any] = {}


# Worker-State: pro Interface ein MdnsInterfaceWorker
mdns_workers: Dict[str, Dict[str, Any]] = {}

# Globales Flag: wurde ein Shutdown angefordert?
SHUTDOWN_REQUESTED = False


logging.basicConfig(
    level=logging.DEBUG,  # oder DEBUG, wenn du mehr sehen willst
    stream=sys.stdout,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("mdns-sat")


# ─────────────────────────────────────────────
# Signal Handler und Global Shutdown
# ─────────────────────────────────────────────


def shutdown_workers():
    """
    Stoppt alle MdnsInterfaceWorker sauber.
    Diese Funktion kann mehrfach aufgerufen werden (idempotent).
    """
    global mdns_workers

    if not mdns_workers:
        return

    logger.info("[SHUTDOWN] Stoppe alle MdnsInterfaceWorker ...")
    for iface, worker in list(mdns_workers.items()):
        logger.info(f"[SHUTDOWN] Stoppe MdnsInterfaceWorker auf Interface {iface}")
        try:
            worker["stop_event"].set()
            if worker["thread"].is_alive():
                worker["thread"].join(timeout=5)
        except Exception as e:
            logger.warning(f"[SHUTDOWN] Fehler beim Stoppen von Worker {iface}: {e}")

    mdns_workers.clear()
    logger.info("[SHUTDOWN] Alle MdnsInterfaceWorker gestoppt.")


def handle_termination(signum, frame):
    """
    Wird bei SIGINT / SIGTERM aufgerufen.
    Setzt nur das Shutdown-Flag – die eigentliche Aufräumarbeit
    passiert in main() / shutdown_workers().
    """
    global SHUTDOWN_REQUESTED
    logger.info(f"Signal {signum} empfangen – Shutdown angefordert.")
    SHUTDOWN_REQUESTED = True

# ─────────────────────────────────────────────
# FastAPI-App für lokalen Sat-HTTP-Server
# ─────────────────────────────────────────────

app = FastAPI(
    title="mDNS Sat",
    description="Lokales API/Debug-Interface für mDNS-Satelliten",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später einschränken
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/debug/service-types")
def api_service_types():
    """
    Debug-Endpoint: zeigt alle aktuell gelernten Service-Typen.
    """
    with CACHE_LOCK:
        types = sorted(list(DISCOVERED_SERVICE_TYPES))
    return {
        "count": len(types),
        "service_types": types,
    }

@app.get("/debug/ws-assignments")
def api_debug_ws_assignments():
    """
    Zeigt, welche Assignments zuletzt über WebSocket empfangen wurden.
    Falls noch keine WS-Daten angekommen sind → None.
    """
    assignments = SAT_CONFIG.get("ws_assignments", None)
    return {
        "count": len(assignments) if isinstance(assignments, list) else None,
        "assignments": assignments,
    }

@app.get("/health")
def api_health():
    # Basis: Prozess lebt
    base_status = "ok"
    register_enabled = is_hub_registration_enabled(SAT_CONFIG)
    publish_enabled = is_publish_to_hub_enabled(SAT_CONFIG)
    mode_key = get_mode_key(SAT_CONFIG)

    # Hub-Status ableiten
    hub_ok = HUB_STATUS.get("last_ok") is not None if register_enabled else None
    hub_status = "ok" if hub_ok else ("unknown" if register_enabled else "disabled")
    last_ok = HUB_STATUS.get("last_ok")
    last_error = HUB_STATUS.get("last_error")

    if register_enabled and last_error:
        base_status = "degraded"

    return {
        "status": base_status,
        "time": datetime.now(timezone.utc).isoformat(),
        "sat_id": SAT_CONFIG.get("sat_id"),
        "hub_url": SAT_CONFIG.get("hub_url"),
        "mode": mode_key,
        "mode_label": get_mode_label(SAT_CONFIG),
        "mode_description": get_mode_description(SAT_CONFIG),
        "publish_to_hub": publish_enabled,
        "hub_register_enabled": register_enabled,
        "interface_config_source": get_interface_config_source(SAT_CONFIG),
        "hub_ok": hub_ok,
        "hub_status": hub_status,
        "hub_last_ok": last_ok,
        "hub_last_error": last_error,
    }


@app.get("/config/local")
def api_config_local():
    cfg = dict(SAT_CONFIG)
    cfg.pop("shared_secret", None)
    return cfg


@app.get("/services")
def api_services(
    type: Optional[str] = Query(None, alias="type"),
):
    """
    Liefert eine Liste der bekannten Service-Instanzen.
    Optional filterbar über ?type=_sonos._tcp.local etc.
    """
    result: List[Dict[str, Any]] = []
    with CACHE_LOCK:
        for inst_name, inst in SERVICE_CACHE.items():
            service_name = inst.get("service_name")
            if type and service_name != type:
                continue

            # Prüfe, ob Service an Hub gemeldet wird
            reported_to_hub = is_service_reported_to_hub(inst_name, inst, SAT_CONFIG)

            result.append({
                "instance_name": inst_name,
                "service_name": service_name,
                "hostname": inst.get("hostname"),
                "addresses": list(inst.get("addresses", [])),
                "port": inst.get("port"),
                "txt": inst.get("txt", []),
                "src_ips": list(inst.get("src_ips", [])),
                "last_seen": inst.get("last_seen"),
                "src_ifaces": list(inst.get("src_ifaces", [])),
                "source_iface": inst.get("iface"),

                # NEU:
                "mac": inst.get("mac"),
                "src_macs": sorted(list(inst.get("src_macs", []))) if inst.get("src_macs") else [],
                "reported_to_hub": reported_to_hub,
            })

    return {
        "count": len(result),
        "services": result,
    }


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
def ui_root():
    ui_path = BASE_DIR / "ui.html"
    if ui_path.exists():
        return FileResponse(str(ui_path))
    return HTMLResponse("<h1>UI file ui.html not found</h1>", status_code=404)


def start_api_server():
    """
    Startet den lokalen FastAPI-Server im Sat.
    Läuft in einem eigenen Thread (daemon=True).
    """
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")


# ─────────────────────────────────────────────
# Sat Host Network Helpers
# ─────────────────────────────────────────────

def interface_exists(iface: str) -> bool:
    """
    Prüft, ob ein Interface im System existiert (egal ob UP oder DOWN).
    """
    if not iface:
        return False

    try:
        subprocess.check_output(
            ["ip", "link", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        logger.warning(f"[IFCHECK] Fehler bei interface_exists('{iface}'): {e}")
        return False


def parse_vlan_iface(iface_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Versucht aus einem Interface-Config-Block VLAN-Infos zu holen.

    Erwartet:
      - name: z.B. 'ens160.222'
      - optional: vlan_id (int)
      - optional: parent_interface

    Rückgabe: dict mit parent, name, vlan_id oder None, falls kein VLAN-IF.
    """
    name = iface_cfg.get("name")
    if not name:
        return None

    vlan_id = iface_cfg.get("vlan_id")
    parent = iface_cfg.get("parent_interface")

    # vlan_id aus Namen ableiten: ens160.222 -> vlan_id=222
    if vlan_id is None and "." in name:
        base, _, suffix = name.partition(".")
        if suffix.isdigit():
            vlan_id = int(suffix)
            if not parent:
                parent = base

    if vlan_id is None:
        return None

    if not parent and "." in name:
        parent = name.split(".", 1)[0]

    if not parent:
        logger.warning(f"[VLAN] Konnte Parent-Interface für {name} nicht ermitteln.")
        return None

    return {
        "name": name,
        "parent": parent,
        "vlan_id": vlan_id,
    }


def _get_ipv4_addresses_for_iface(iface: str) -> List[str]:
    """
    Liefert alle aktuellen IPv4-Adressen (mit Prefix, z.B. '192.168.222.111/24')
    auf einem Interface zurück.
    """
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError:
        return []
    except Exception as e:
        logger.warning(f"[IPCFG] Konnte IPv4-Adressen für '{iface}' nicht ermitteln: {e}")
        return []

    addrs: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        # typische Zeile: "inet 192.168.222.111/24 brd 192.168.222.255 scope global dynamic ens160.222"
        if line.startswith("inet "):
            parts = line.split()
            if len(parts) >= 2:
                addrs.append(parts[1])   # CIDR-Notation
    return addrs


def ensure_ipv4_for_iface(iface: str, ip_mode: Optional[str], ip_address: Optional[str]) -> None:
    """
    Stellt sicher, dass das Interface eine passende IPv4-Adresse hat,
    wenn ip_mode = 'static' und ip_address gesetzt ist.

    Logik:
    - wenn ip_mode != static → nichts tun
    - aktuelle IPv4-Adressen ermitteln
    - wenn gewünschte ip_address bereits konfiguriert ist → fertig
    - sonst: zunächst alle bestehenden IPv4-Adressen flushen, dann gewünschte setzen
    """
    if ip_mode != "static" or not ip_address:
        if ip_mode and ip_mode != "none":
            logger.info(
                f"[IPCFG] Interface '{iface}' ip_mode={ip_mode}, "
                f"automatische IP-Konfiguration derzeit nur für 'static'."
            )
        return

    try:
        current_addrs = _get_ipv4_addresses_for_iface(iface)

        if ip_address in current_addrs:
            logger.info(f"[IPCFG] Interface '{iface}' hat bereits IPv4 {ip_address}.")
            return

        if current_addrs:
            logger.info(
                f"[IPCFG] Interface '{iface}' hat andere IPv4-Adressen {current_addrs} – "
                f"flushe IPv4-Adressen vor Setzen von {ip_address}."
            )
            try:
                # nur IPv4 flushen, IPv6 bleibt unberührt
                subprocess.check_call(
                    ["ip", "-4", "addr", "flush", "dev", iface],
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"[IPCFG] Fehler beim Flush von IPv4-Adressen auf '{iface}': {e}")
                # wir versuchen trotzdem, die neue Adresse zu setzen

        logger.info(f"[IPCFG] Setze IPv4 {ip_address} auf Interface '{iface}' ...")
        subprocess.check_call(
            ["ip", "addr", "add", ip_address, "dev", iface],
            stderr=subprocess.DEVNULL,
        )

    except subprocess.CalledProcessError as e:
        logger.error(f"[IPCFG] Fehler beim Setzen der IPv4 {ip_address} auf '{iface}': {e}")
    except Exception as e:
        logger.error(f"[IPCFG] Unerwarteter Fehler bei IPv4-Konfiguration für '{iface}': {e}")


def ensure_vlan_subinterface(iface_cfg: Dict[str, Any]) -> None:
    """
    Stellt sicher, dass ein VLAN-Subinterface existiert, UP ist
    und bei static-Config eine IP-Adresse gesetzt hat.
    """
    parsed = parse_vlan_iface(iface_cfg)
    if not parsed:
        # Kein VLAN-IF, nichts zu tun
        return

    name = parsed["name"]
    parent = parsed["parent"]
    vlan_id = parsed["vlan_id"]

    if not interface_exists(parent):
        logger.warning(
            f"[VLAN] Parent-Interface '{parent}' existiert nicht – "
            f"VLAN-Interface '{name}' kann nicht erzeugt werden."
        )
        return

    created = False

    if interface_exists(name):
        logger.info(f"[VLAN] VLAN-Interface '{name}' existiert bereits.")
    else:
        logger.info(
            f"[VLAN] Erzeuge VLAN-Interface '{name}' "
            f"(parent={parent}, vlan_id={vlan_id}) ..."
        )
        try:
            subprocess.check_call(
                ["ip", "link", "add", "link", parent, "name", name, "type", "vlan", "id", str(vlan_id)],
                stderr=subprocess.DEVNULL,
            )
            created = True
        except subprocess.CalledProcessError as e:
            logger.error(f"[VLAN] Fehler beim Anlegen des VLAN-Interfaces '{name}': {e}")
            return

    # Wenn wir das Interface selbst angelegt haben, mit Alias markieren
    if created:
        try:
            subprocess.check_call(
                ["ip", "link", "set", "dev", name, "alias", MANAGED_VLAN_ALIAS],
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"[VLAN] Interface '{name}' als '{MANAGED_VLAN_ALIAS}' markiert.")
        except Exception as e:
            logger.warning(
                f"[VLAN] Konnte Alias für Interface '{name}' nicht setzen: {e}"
            )

    # Interface UP setzen
    try:
        subprocess.check_call(["ip", "link", "set", "dev", name, "up"], stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.error(f"[VLAN] Konnte Interface '{name}' nicht UP setzen: {e}")

    # IP-Konfiguration prüfen/setzen
    ensure_ipv4_for_iface(name, iface_cfg.get("ip_mode"), iface_cfg.get("ip_address"))
    
   

def cleanup_vlan_subinterfaces(interfaces_cfg: List[Dict[str, Any]]) -> None:
    """
    Löscht VLAN-Subinterfaces, die von diesem Sat verwaltet werden (Alias),
    aber nicht mehr in der aktuellen Hub-Konfiguration vorkommen.

    - Es werden nur VLAN-IFs mit alias == MANAGED_VLAN_ALIAS betrachtet.
    - desired_names = alle VLAN-Namen, die per Hub-Config definiert sind.
    - alles andere mit diesem Alias wird gelöscht.
    """
    # 1) Soll-Zustand aus der Hub-Config bestimmen
    desired_names: set[str] = set()
    for iface_cfg in interfaces_cfg:
        parsed = parse_vlan_iface(iface_cfg)
        if parsed:
            desired_names.add(parsed["name"])

    # 2) Alle VLAN-Interfaces mit unserem Alias finden
    try:
        out = subprocess.check_output(
            ["ip", "-o", "link", "show", "type", "vlan"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
    except subprocess.CalledProcessError as e:
        logger.error(f"[VLAN] Fehler beim Auflisten der VLAN-Interfaces: {e}")
        return
    except Exception as e:
        logger.error(f"[VLAN] Unerwarteter Fehler bei VLAN-Auflistung: {e}")
        return

    for line in out.splitlines():
        # typischer Output:
        # "7: ens160.222@ens160: <BROADCAST,...> mtu ... qdisc ... state UP ... alias mdns-sat-managed-vlan"
        if MANAGED_VLAN_ALIAS not in line:
            continue

        # Name ist zwischen "index: " und "@"
        try:
            _, rest = line.split(": ", 1)
            name_part = rest.split(":", 1)[0]  # "ens160.222@ens160"
            ifname = name_part.split("@", 1)[0]
        except ValueError:
            continue

        if ifname not in desired_names:
            logger.info(
                f"[VLAN] VLAN-Interface '{ifname}' ist als '{MANAGED_VLAN_ALIAS}' markiert, "
                f"aber nicht mehr in der Hub-Config – lösche Interface."
            )
            try:
                subprocess.check_call(
                    ["ip", "link", "delete", "dev", ifname],
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"[VLAN] Fehler beim Löschen des VLAN-Interfaces '{ifname}': {e}")
            except Exception as e:
                logger.error(f"[VLAN] Unerwarteter Fehler beim Löschen von '{ifname}': {e}")
                
    


# ─────────────────────────────────────────────
# Konfig laden / HTTP zum Hub
# ─────────────────────────────────────────────

def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    if not path.exists():
        logger.error(f"Konfigurationsdatei nicht gefunden: {path}")
        sys.exit(1)

    with path.open("r", encoding="utf-8") as f:
        cfg = apply_sat_defaults(yaml.safe_load(f) or {})

    try:
        validate_sat_config(cfg)
    except ValueError as exc:
        logger.error(str(exc))
        sys.exit(1)

    return cfg


def get_hub_base_url(cfg: Dict[str, Any]) -> str:
    return cfg["hub_url"].rstrip("/")


def sat_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Satellite-Token": cfg["shared_secret"],
    }


def detect_ip_mode_for_iface(iface: Optional[str]) -> str:
    if not iface:
        return "none"

    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")

        if "inet " not in out:
            return "none"

        if "dynamic" in out:
            return "dhcp"

        return "static"
    except Exception as e:
        logger.warning(f"[AUTO-IF] Konnte IP-Mode für Interface '{iface}' nicht ermitteln: {e}")
        return "none"


def detect_primary_ip_and_iface(hub_url: str):
    ip_detected = None
    iface_detected = None

    try:
        from urllib.parse import urlparse
        parsed = urlparse(hub_url)
        target_host = parsed.hostname or "1.1.1.1"
        target_port = parsed.port or 80

        logger.info(f"[AUTO-IF] Versuche primäre IP über UDP-Connect an {target_host}:{target_port} zu bestimmen ...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target_host, target_port))
        ip_detected = sock.getsockname()[0]
        sock.close()

        logger.info(f"[AUTO-IF] Primäre IP erkannt → {ip_detected}")
    except Exception as e:
        logger.warning(f"[AUTO-IF] Fehler bei primärer IP-Bestimmung: {e}")

    try:
        logger.info("[AUTO-IF] Versuche Default-Interface über 'ip route get 1.1.1.1' zu bestimmen ...")
        out = subprocess.check_output(
            ["ip", "route", "get", "1.1.1.1"],
            stderr=subprocess.DEVNULL
        ).decode().strip()

        logger.info(f"[AUTO-IF] Ausgabe von 'ip route get': {out}")

        parts = out.split()
        if "dev" in parts:
            iface_detected = parts[parts.index("dev") + 1]
            logger.info(f"[AUTO-IF] Default-Interface erkannt → {iface_detected}")
        else:
            logger.warning("[AUTO-IF] In der Ausgabe wurde kein 'dev' gefunden.")
    except Exception as e:
        logger.warning(f"[AUTO-IF] Fehler bei Default-Interface-Erkennung: {e}")

    logger.info(f"[AUTO-IF] Ergebnis: IP={ip_detected}, Interface={iface_detected}")
    return {
        "ip": ip_detected,
        "iface": iface_detected
    }


def register_sat(cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    global HUB_STATUS
    if not is_hub_registration_enabled(cfg):
        logger.info("Hub-Registrierung deaktiviert (hub_register_enabled=false) – überspringe Register-Call.")
        return None

    base_url = get_hub_base_url(cfg)
    url = f"{base_url}/api/v1/satellites/register"

    sat_id = cfg["sat_id"]

    # Auto-Detection
    auto = detect_primary_ip_and_iface(cfg["hub_url"])
    auto_ip = auto.get("ip")
    auto_iface = auto.get("iface")

    logger.info(
        f"[AUTO-IF] Finale Entscheidung: ip={auto_ip}, iface={auto_iface}"
    )

    cfg["auto_ip"] = auto_ip
    cfg["auto_iface"] = auto_iface

    mgmt_iface = cfg.get("mgmt_interface") or auto_iface
    mgmt_ip = cfg.get("mgmt_ip_address") or auto_ip

    mgmt_ip_mode = detect_ip_mode_for_iface(mgmt_iface)
    cfg["auto_ip_mode"] = mgmt_ip_mode

    payload = {
        "satellite_id": sat_id,
        "hostname": cfg.get("hostname"),
        "auth_token": cfg["shared_secret"],
        "mgmt_interface": mgmt_iface,
        "mgmt_ip_address": mgmt_ip,
        "mgmt_ip_mode": mgmt_ip_mode,
        "software_version": cfg.get("software_version", "0.2.0"),
    }

    logger.info(
        f"Registriere Sat bei {url} als ID {sat_id} "
        f"(mgmt_interface={mgmt_iface}, mgmt_ip={mgmt_ip}, ip_mode={mgmt_ip_mode}) ..."
    )

    try:
        resp = requests.post(url, json=payload, headers=sat_headers(cfg), timeout=10)
    except Exception as e:
        logger.error(f"Fehler bei der Registrierung: {e}")
        HUB_STATUS["last_error"] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"register_sat exception: {e}",
        }
        return None

    if resp.status_code != 200:
        logger.error(f"Registrierung fehlgeschlagen: HTTP {resp.status_code} - {resp.text}")
        HUB_STATUS["last_error"] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"register_sat HTTP {resp.status_code}",
        }
        return None

    data = resp.json()
    logger.info("Registrierung erfolgreich.")
    HUB_STATUS["last_ok"] = datetime.now(timezone.utc).isoformat()
    HUB_STATUS["last_error"] = None
    return data


def fetch_sat_config(cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    global HUB_STATUS
    if not is_hub_registration_enabled(cfg):
        logger.info("Hub-Config deaktiviert (hub_register_enabled=false) – überspringe Config-Abruf.")
        return None

    base_url = get_hub_base_url(cfg)
    sat_id = cfg["sat_id"]
    url = f"{base_url}/api/v1/satellites/{sat_id}/config"

    logger.info(f"Hole Config für Sat {sat_id} von {url} ...")

    try:
        resp = requests.get(url, headers=sat_headers(cfg), timeout=10)
    except Exception as e:
        logger.error(f"Fehler beim Abruf der Config: {e}")
        HUB_STATUS["last_error"] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"fetch_sat_config exception: {e}",
        }
        return None

    if resp.status_code != 200:
        logger.error(f"Config-Abruf fehlgeschlagen: HTTP {resp.status_code} - {resp.text}")
        HUB_STATUS["last_error"] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"fetch_sat_config HTTP {resp.status_code}",
        }
        return None

    data = resp.json()
    logger.info("Config erfolgreich abgerufen.")
    HUB_STATUS["last_ok"] = datetime.now(timezone.utc).isoformat()
    HUB_STATUS["last_error"] = None
    return data


def push_services_to_hub(cfg: Dict[str, Any]):
    global HUB_STATUS
    if not is_publish_to_hub_enabled(cfg):
        logger.info("Service-Publish zum Hub deaktiviert (publish_to_hub=false) – Snapshot wird nicht gesendet.")
        return

    base_url = get_hub_base_url(cfg)
    sat_id = cfg["sat_id"]
    url = f"{base_url}/api/v1/satellites/{sat_id}/services"

    services = build_service_snapshot(cfg)
    payload = {
        "satellite_id": sat_id,
        "services": services,
    }

    logger.info(f"Sende Service-Snapshot an Hub ({len(services)} Services) ...")

    try:
        resp = requests.post(
            url,
            headers=sat_headers(cfg),
            json=payload,
            timeout=10,
        )
    except Exception as e:
        logger.error(f"Fehler beim Service-Ingest zum Hub: {e}")
        HUB_STATUS["last_error"] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"push_services_to_hub exception: {e}",
        }
        return

    if resp.status_code != 200:
        logger.error(
            f"Service-Ingest fehlgeschlagen: HTTP {resp.status_code} - {resp.text}"
        )
        HUB_STATUS["last_error"] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"push_services_to_hub HTTP {resp.status_code}",
        }
        return

    try:
        data = resp.json()
    except Exception:
        data = {}

    HUB_STATUS["last_ok"] = datetime.now(timezone.utc).isoformat()
    HUB_STATUS["last_error"] = None

    ingested = data.get("ingested")
    total = data.get("total")
    logger.info(
        f"Service-Ingest erfolgreich: ingested={ingested} total={total}"
    )


def interface_is_ready(iface: str) -> bool:
    if not iface:
        return False

    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", "dev", iface],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")

        lines = out.splitlines()
        if not lines:
            logger.warning(f"[IFCHECK] Keine Ausgabe für Interface '{iface}'.")
            return False

        first = lines[0]
        is_up = "state UP" in first or "UP," in first
        has_ipv4 = any("inet " in l for l in lines)

        if not is_up:
            logger.warning(f"[IFCHECK] Interface '{iface}' ist nicht UP – kein mDNS-Worker.")
            return False
        if not has_ipv4:
            logger.warning(f"[IFCHECK] Interface '{iface}' hat keine IPv4-Adresse – kein mDNS-Worker.")
            return False

        return True

    except Exception as e:
        logger.warning(f"[IFCHECK] Konnte Status für Interface '{iface}' nicht ermitteln: {e}")
        return False



# ─────────────────────────────────────────────
# Websocket Handling
# ─────────────────────────────────────────────

def handle_ws_message(msg: Dict[str, Any]):
    """
    Wird vom WS-Client aufgerufen, wenn der Hub eine Nachricht sendet.
    Hier kannst du später hub.config.update, hub.assignments.update etc. behandeln.
    """
    mtype = msg.get("type")
    payload = msg.get("payload") or {}

    if mtype == "hub.config.update":
        logger.info("[WS] hub.config.update empfangen – Config wird aktualisiert.")
        # z.B. globale SAT_CONFIG["hub_config"] setzen und Flag/ Event
        SAT_CONFIG["hub_config"] = payload.get("config")
        # TODO: Event setzen, damit main() sofort neu ausrollt (ohne auf poll_interval zu warten)

    elif mtype == "hub.assignments.update":
        assignments = payload.get("assignments") or []
        SAT_CONFIG["ws_assignments"] = assignments
        SAT_CONFIG["assignments_updated_at"] = time.time()
        SAT_CONFIG["ws_assignments_received_at"] = time.time()
        logger.info(
            "[WS] hub.assignments.update empfangen – %d Assignments im WS-Cache.",
            len(assignments),
        )

    else:
        logger.info(f"[WS] Unbekannter Nachrichtentyp vom Hub: {mtype}, payload={payload}")
        

# ─────────────────────────────────────────────
# Hauptloop
# ─────────────────────────────────────────────

def main():
    global SAT_CONFIG, mdns_workers, SHUTDOWN_REQUESTED, ws_client, ws_stop_event

    # Signal-Handler registrieren
    signal.signal(signal.SIGINT, handle_termination)
    signal.signal(signal.SIGTERM, handle_termination)

    # atexit: falls der Prozess "normal" endet, werden Worker auch gestoppt
    atexit.register(shutdown_workers)

    cfg = load_config()
    SAT_CONFIG = cfg

    # WS-Assignments-Cache: wird vom WebSocket befüllt
    SAT_CONFIG["ws_assignments"] = None
    # Zeigt dem Worker an, dass Assignments aktualisiert wurden und er updaten muss
    SAT_CONFIG["assignments_updated_at"] = 0.0

    poll_interval = int(cfg.get("config_poll_interval", 300))
    register_enabled = is_hub_registration_enabled(cfg)
    publish_enabled = is_publish_to_hub_enabled(cfg)

    logger.info("mDNS-Sat-Agent startet.")
    logger.info(f"Sat ID   : {cfg['sat_id']}")
    logger.info(f"Modus    : {get_mode_label(cfg)} ({get_mode_key(cfg)})")
    logger.info(f"Modus-Info: {get_mode_description(cfg)}")
    logger.info(f"Hub-Reg. : {'aktiv' if register_enabled else 'deaktiviert'}")
    logger.info(f"Hub-Pub. : {'aktiv' if publish_enabled else 'deaktiviert'}")
    logger.info(f"Hub URL  : {cfg.get('hub_url', '–')}")
    logger.info(f"Poll-Intervall für Config: {poll_interval} Sekunden")

    # Lokales API in eigenem Thread starten
    api_thread = threading.Thread(target=start_api_server, daemon=True)
    api_thread.start()
    logger.info("Lokales Sat-API (FastAPI) in Hintergrundthread gestartet (Port 8080).")

    # WebSocket-Client zum Hub starten (optional)
    if is_ws_enabled(cfg):
        ws_stop_event = threading.Event()
        ws_client = SatWebSocketClient(
            cfg,
            on_message=handle_ws_message,
            stop_event=ws_stop_event,
        )
        ws_client.start()
        logger.info("WS-Client zum Hub gestartet.")
    else:
        logger.info("WS-Client zum Hub ist deaktiviert.")

    cfg["hub_config"] = None

    try:
        while not SHUTDOWN_REQUESTED:
            if register_enabled:
                reg_result = register_sat(cfg)
                if reg_result is None:
                    logger.warning("Registrierung fehlgeschlagen, versuche später erneut.")
                else:
                    assigned_cfg = reg_result.get("assigned_config")
                    if assigned_cfg:
                        logger.info("Vom Hub zugewiesene Config (aus Register-Response):")
                        logger.info(assigned_cfg)

                hub_cfg = fetch_sat_config(cfg)
                if hub_cfg is not None:
                    logger.info("Aktuelle Hub-Config:")
                    logger.info(hub_cfg)
                    cfg["hub_config"] = hub_cfg

            interfaces = resolve_interface_configs(cfg)
            interface_source = get_interface_config_source(cfg)
            logger.info(
                "Aktive Interface-Konfiguration: Quelle=%s, Interfaces=%d",
                interface_source,
                len(interfaces),
            )

            # VLAN-Subinterfaces gemäß Hub-Config verwalten
            if cfg.get("manage_vlan_interfaces", True):
                for iface_cfg in interfaces:
                    ensure_vlan_subinterface(iface_cfg)

            # Welche Interfaces brauchen überhaupt einen Worker?
            desired_ifaces: List[str] = []

            for iface_cfg in interfaces:
                name = iface_cfg.get("name")
                mode = iface_cfg.get("mode") or "none"
                if not name:
                    continue

                if wants_sniff(mode) or wants_advertise(mode):
                    if interface_is_ready(name):
                        desired_ifaces.append(name)
                    else:
                        logger.warning(
                            f"Interface {name} ist in einem aktiven Mode "
                            f"(scan/sniff/advertise), aber nicht bereit "
                            f"(DOWN oder keine IPv4) – kein mDNS-Worker."
                        )

            # Worker verwalten
            current_ifaces = set(mdns_workers.keys())
            desired_set = set(desired_ifaces)

            # nicht mehr benötigte Worker stoppen
            for iface in list(current_ifaces):
                if iface not in desired_set:
                    worker = mdns_workers.get(iface)
                    if worker:
                        logger.info(
                            f"Stoppe MdnsInterfaceWorker auf Interface {iface} "
                            f"(nicht mehr im relevanten Mode oder nicht bereit)."
                        )
                        try:
                            worker["stop_event"].set()
                            if worker["thread"].is_alive():
                                worker["thread"].join(timeout=5)
                        except Exception as e:
                            logger.warning(
                                f"[SHUTDOWN] Fehler beim Stoppen von Worker {iface}: {e}"
                            )
                    mdns_workers.pop(iface, None)

            # neue Worker starten / laufende Worker ggf. bei Mode-Wechsel neu starten
            for iface_cfg in interfaces:
                name = iface_cfg.get("name")
                mode = iface_cfg.get("mode") or "none"
                if not name:
                    continue

                if name not in desired_set:
                    continue

                new_mode = (mode or "none").lower()
                existing = mdns_workers.get(name)

                # Fall 1: Es gibt schon einen lebenden Worker → Mode prüfen
                if existing and existing["thread"].is_alive():
                    worker_obj = existing["worker"]
                    old_mode = (existing.get("mode") or worker_obj.mode or "none").lower()

                    if old_mode != new_mode:
                        logger.info(
                            f"Mode-Wechsel erkannt (Restart) für Interface {name}: "
                            f"{old_mode} → {new_mode}"
                        )
                        # alten Worker sauber stoppen → der schickt im finally seine Goodbyes
                        try:
                            existing["stop_event"].set()
                            existing["thread"].join(timeout=5)
                        except Exception as e:
                            logger.warning(
                                f"Fehler beim Stoppen von Worker {name} beim Mode-Wechsel: {e}"
                            )
                        mdns_workers.pop(name, None)
                    else:
                        # Mode unverändert → Worker weiterlaufen lassen
                        continue

                # Fall 2: Kein (mehr) laufender Worker → neuen starten
                logger.info(
                    f"Interface {name} im relevanten Mode '{new_mode}' "
                    f"→ starte MdnsInterfaceWorker ..."
                )
                stop_event = threading.Event()
                worker_obj = MdnsInterfaceWorker(
                    cfg,
                    iface=name,
                    mode=new_mode,
                    stop_event=stop_event,
                )
                thread = threading.Thread(
                    target=worker_obj.run,
                    daemon=True,
                )
                thread.start()
                mdns_workers[name] = {
                    "thread": thread,
                    "stop_event": stop_event,
                    "worker": worker_obj,
                    "mode": new_mode,
                }

            # VLAN-Cleanup nach Worker-Handling (optional)
            if cfg.get("manage_vlan_interfaces", True):
                cleanup_vlan_subinterfaces(interfaces)


            # Logging über aktuellen Service-Cache
            with CACHE_LOCK:
                total = len(SERVICE_CACHE)
                logger.info(f"Aktueller Service-Cache: {total} Instanzen")
                max_show = 5
                if total > 0:
                    logger.info("Beispiel-Instanzen aus dem Cache:")
                    for i, (inst_name, inst) in enumerate(SERVICE_CACHE.items()):
                        if i >= max_show:
                            break
                        svc = inst.get("service_name", "?")
                        addrs = list(inst.get("addresses", []))
                        host = inst.get("hostname")
                        logger.info(
                            f"  - {inst_name} "
                            f"(Service: {svc}, Host: {host}, IPs: {addrs})"
                        )

            try:
                push_services_to_hub(cfg)
            except Exception as e:
                logger.error(f"Unerwarteter Fehler beim Service-Ingest: {e}")

            logger.info(f"Warte {poll_interval} Sekunden bis zum nächsten Config-Abruf ...")

            # Sleep abbrechbar machen
            slept = 0
            while slept < poll_interval and not SHUTDOWN_REQUESTED:
                time.sleep(1)
                slept += 1

    except Exception:
        logger.exception("Unerwarteter Fehler im Hauptloop – fahre kontrolliert herunter.")
    finally:
        logger.info("Hauptloop beendet – stoppe alle Worker ...")
        shutdown_workers()
        logger.info("mDNS-Sat-Agent beendet.")


if __name__ == "__main__":
    main()
