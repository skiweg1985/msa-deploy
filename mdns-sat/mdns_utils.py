#!/usr/bin/env python3
import socket
import struct
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
import logging
import subprocess
import time
from mdns_dns import ensure_fqdn, strip_dot
from mdns_mode import is_publish_to_hub_enabled, resolve_interface_configs


logger = logging.getLogger("mdns-sat.utils")
#logger.setLevel(logging.INFO)


# ─────────────────────────────────────────────
# Konstanten & globale Datenstrukturen
# ─────────────────────────────────────────────

SERVICE_BROWSER = "_services._dns-sd._udp.local"


# Services, die noch "aufgelöst" werden müssen (fehlender Host/Port/IP)
PENDING_RESOLVE: Dict[str, Dict[str, Any]] = {}

# Optional: Seed-Services, falls kein Gerät im Netz den Service-Browser beantwortet.
STATIC_SERVICE_SEEDS = [
    "_sonos._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_ipps._tcp.local",
    "_ipp._tcp.local",
    "_spotify-connect._tcp.local",
]

# Dynamisch gelernte Servicetypen aus _services._dns-sd._udp.local
DISCOVERED_SERVICE_TYPES: Set[str] = set()

# Gemeinsamer Cache für erkannte Services
SERVICE_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_LOCK = threading.Lock()


# Cache für IP→MAC-Lookups (pro Interface)
NEIGHBOR_CACHE: Dict[str, Dict[str, Any]] = {}
NEIGHBOR_TTL = 60.0       # Sekunden Gültigkeit für positive Einträge


# ─────────────────────────────────────────────
# IP --> MAC Lookup Cache Helper
# ─────────────────────────────────────────────

def lookup_mac_via_ip_neigh(ip: str, iface: Optional[str] = None) -> Optional[str]:
    """
    Lookup MAC for an IP by checking `ip neigh`.
    Wenn keine MAC vorhanden:
      - genau EINEN fping-Request senden
      - danach erneut `ip neigh` prüfen

    KEIN Fallback auf ping oder arping.
    Wenn fping fehlt → jedes Mal error loggen.
    """
    if not ip:
        return None

    now = time.time()

    # 1) Cache prüfen
    entry = NEIGHBOR_CACHE.get(ip)
    if entry and (now - entry["ts"] < NEIGHBOR_TTL):
        mac = entry["mac"]
        logger.debug(f"[NEIGH] Cache-Hit für {ip}: {mac}")
        return mac

    logger.debug(f"[NEIGH] Cache-Miss für {ip}, starte Lookup (iface={iface!r})")

    def _ip_neigh() -> Optional[str]:
        try:
            if iface:
                out = subprocess.check_output(
                    ["ip", "neigh", "show", "to", ip, "dev", iface],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            else:
                out = subprocess.check_output(
                    ["ip", "neigh", "show", ip],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
        except Exception as e:
            logger.debug(f"[NEIGH] ip neigh show für {ip} fehlgeschlagen: {e}")
            return None

        for line in out.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                return parts[parts.index("lladdr") + 1].lower()
        return None

    # 2) Direktversuch
    mac = _ip_neigh()
    if mac:
        logger.debug(f"[NEIGH] Direkt aus ip neigh für {ip}: {mac}")
        NEIGHBOR_CACHE[ip] = {"mac": mac, "ts": now}
        return mac

    # 3) Kein Eintrag → fping anstoßen
    try:
        cmd = ["fping", "-c1", "-t50", ip]
        logger.debug(f"[NEIGH] Sende fping für {ip}: {cmd}")
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        logger.error(
            "[NEIGH] fping ist NICHT installiert oder nicht im PATH – "
            f"MAC-Lookup für {ip} nicht möglich! Bitte fping nachinstallieren."
        )
        NEIGHBOR_CACHE[ip] = {"mac": None, "ts": now}
        return None
    except Exception as e:
        logger.error(f"[NEIGH] Fehler beim Ausführen von fping für {ip}: {e}")
        NEIGHBOR_CACHE[ip] = {"mac": None, "ts": now}
        return None

    # 4) Nach fping erneut prüfen
    mac = _ip_neigh()
    if mac:
        logger.debug(f"[NEIGH] Nach fping für {ip}: MAC={mac}")
    else:
        logger.debug(f"[NEIGH] Nach fping keine MAC für {ip}")

    NEIGHBOR_CACHE[ip] = {"mac": mac, "ts": now}
    return mac


# ─────────────────────────────────────────────
# Service-Typ-Erkennung / Subtypes
# ─────────────────────────────────────────────

def derive_service_type_and_instance_fqdn(service: Dict[str, Any]) -> Tuple[str, str]:
    """
    Versucht, aus den Feldern eines Service-Objekts einen sauberen Service-Typ
    (_sonos._tcp.local) und einen vollständigen Instance-FQDN zu bauen.
    """
    raw_instance = (service.get("instance_name") or "").strip(".")
    raw_service = (service.get("service_name") or "").strip(".")

    svc_type: Optional[str] = None

    # 1) Versuch: Aus instance_name ableiten (Standard mDNS: *.local)
    if raw_instance:
        labels = raw_instance.split(".")
        if len(labels) >= 4 and labels[-2] in ("_tcp", "_udp") and labels[-1] == "local":
            svc_type = ".".join(labels[-3:])

    # 2) Fallback: service_name verwenden, falls der schon nach Service-Typ aussieht
    if not svc_type and raw_service:
        if raw_service.startswith("_") and any(s in raw_service for s in ("._tcp.", "._udp.")):
            svc_type = raw_service

    # 3) Ultimate Fallback
    if not svc_type:
        svc_type = "_unknown._tcp.local"

    svc_type_nodot = svc_type.strip(".")
    if raw_instance:
        if raw_instance.endswith(svc_type_nodot):
            instance_fqdn = raw_instance
        else:
            instance_fqdn = f"{raw_instance}.{svc_type_nodot}"
    else:
        instance_fqdn = f"Unnamed.{svc_type_nodot}"

    return ensure_fqdn(svc_type), ensure_fqdn(instance_fqdn)


def split_service_and_subtype(service_name: str) -> Tuple[str, Optional[str]]:
    """
    Zerlegt einen Service-Namen in Basis-Service und optionalen Subtype.

    Beispiele:
      "_universal._sub._ipps._tcp.local" ->
         ("_ipps._tcp.local", "_universal._sub._ipps._tcp.local")

      "_airplay._tcp.local" ->
         ("_airplay._tcp.local", None)
    """
    service_name = (service_name or "").strip(".")
    if not service_name:
        return "", None

    if "._sub." not in service_name:
        return service_name, None

    # Format: <sub>._sub._service._tcp.local
    before, after = service_name.split("._sub.", 1)
    base = after  # z.B. "_ipps._tcp.local"
    subtype = service_name  # kompletter Name mit _sub

    return base, subtype


# ─────────────────────────────────────────────
# Service-Cache Logik
# ─────────────────────────────────────────────
def is_instance_complete(inst: Dict[str, Any]) -> bool:
    """
    Prüft, ob wir genug Infos haben, um sauber zu spoofen:
      - hostname (SRV)
      - port
      - mindestens eine IPv4-Adresse
    """
    if not inst:
        return False

    hostname = inst.get("hostname")
    port = inst.get("port")
    addrs = inst.get("addresses") or set() or []

    return bool(hostname) and bool(port) and bool(addrs)


def infer_service_name_from_instance(instance_fqdn: str) -> Optional[str]:
    """
    Versucht aus einem FQDN wie
    'RINCON_xxx@Küche._sonos._tcp.local'
    den Service-Teil '_sonos._tcp.local' abzuleiten.
    """
    if not instance_fqdn:
        return None
    parts = instance_fqdn.split(".", 1)
    if len(parts) == 2:
        return parts[1]
    return None


def is_reverse_dns_name(name: str) -> bool:
    """
    Prüft, ob ein Name ein Reverse-DNS-Name ist (z.B. 88.4.30.172.in-addr.arpa).
    Diese sollten nicht als Service-Instanzen behandelt werden.
    """
    if not name:
        return False
    name_lower = name.lower()
    return name_lower.endswith(".ip6.arpa") or name_lower.endswith(".in-addr.arpa")


def update_service_cache_from_records(records: List[Dict[str, Any]], src_ip: str, src_iface: str):
    """
    Baut aus den DNS-Records einen einfachen Service-Cache auf.
    Key ist i.d.R. der Instanz-FQDN (PTR-Ziel bzw. SRV-Name).
    """
    now = datetime.now(timezone.utc).isoformat()
    prev_size = len(SERVICE_CACHE)

    new_instances: List[tuple[str, Dict[str, Any]]] = []

    for r in records:
        rtype = r["type"]
        name = r["name"]

        # Reverse-DNS ignorieren
        if name.lower().endswith(".ip6.arpa") or name.lower().endswith(".in-addr.arpa"):
            continue

        # Service Browser: nur Typen lernen, nicht im Cache speichern
        if rtype == 12 and name == SERVICE_BROWSER and "ptr" in r:
            svc_type = r["ptr"]
            if (
                svc_type.startswith("_")
                and (svc_type.endswith("._tcp.local") or svc_type.endswith("._udp.local"))
            ):
                if svc_type not in DISCOVERED_SERVICE_TYPES:
                    DISCOVERED_SERVICE_TYPES.add(svc_type)
                # sonst: schon bekannt
            continue

        # PTR: service_name -> instance_fqdn
        if rtype == 12 and "ptr" in r:
            service_name = name
            instance_fqdn = r["ptr"]

            # Reverse-DNS-Namen als instance_name ignorieren
            if is_reverse_dns_name(instance_fqdn):
                continue

            is_new = instance_fqdn not in SERVICE_CACHE
            if is_new:
                inst = {
                    "service_name": service_name,
                    "instance_name": instance_fqdn,
                    "hostname": None,
                    "addresses": set(),
                    "first_seen": now,
                    "last_seen": now,
                    "port": None,
                    "txt": [],
                    "src_ips": set(),
                    "src_ifaces": set(),
                    "iface": src_iface,
                    "ttl": {
                        "ptr": None,
                        "srv": None,
                        "txt": None,
                        "a": None,
                    },
                    "raw_records": [],
                    "src_macs": set(),
                    "mac": None,
                }
                SERVICE_CACHE[instance_fqdn] = inst
                new_instances.append((instance_fqdn, inst))
            else:
                inst = SERVICE_CACHE[instance_fqdn]
                inst["last_seen"] = now

            inst["service_name"] = service_name
            inst["last_seen"] = now
            inst["src_ips"].add(src_ip)
            inst.setdefault("src_ifaces", set()).add(src_iface)
            inst["iface"] = src_iface
            inst["raw_records"].append({"type": "PTR", "data": r})

            mac = lookup_mac_via_ip_neigh(src_ip, src_iface)
            if mac:
                inst.setdefault("src_macs", set()).add(mac)
                inst["mac"] = mac


        # SRV
        elif rtype == 33 and "srv" in r:
            instance_fqdn = name
            srv = r["srv"]
            target = srv["target"]
            port = srv["port"]

            is_new = instance_fqdn not in SERVICE_CACHE
            if is_new:
                inst = {
                    "service_name": None,
                    "instance_name": instance_fqdn,
                    "hostname": target,
                    "addresses": set(),
                    "first_seen": now,
                    "last_seen": now,
                    "raw_records": [],
                    "port": None,
                    "txt": [],
                    "src_ips": set(),
                    "src_ifaces": set(),
                    "iface": src_iface,
                    "ttl": {
                        "ptr": None,
                        "srv": None,
                        "txt": None,
                        "a": None,
                    },
                    "src_macs": set(),
                    "mac": None,                    
                }
                SERVICE_CACHE[instance_fqdn] = inst
                new_instances.append((instance_fqdn, inst))
            else:
                inst = SERVICE_CACHE[instance_fqdn]
                inst["last_seen"] = now

            inst["hostname"] = target
            inst["port"] = port
            inst["last_seen"] = now
            inst["src_ips"].add(src_ip)
            inst.setdefault("src_ifaces", set()).add(src_iface)
            inst["iface"] = src_iface
            inst["raw_records"].append({"type": "SRV", "data": r})

            mac = lookup_mac_via_ip_neigh(src_ip, src_iface)
            if mac:
                inst.setdefault("src_macs", set()).add(mac)
                inst["mac"] = mac

            if not inst.get("service_name"):
                inferred = infer_service_name_from_instance(instance_fqdn)
                if inferred:
                    inst["service_name"] = inferred

        # TXT
        elif rtype == 16 and "txt" in r:
            instance_fqdn = name

            is_new = instance_fqdn not in SERVICE_CACHE
            if is_new:
                inst = {
                    "service_name": None,
                    "instance_name": instance_fqdn,
                    "hostname": None,
                    "addresses": set(),
                    "first_seen": now,
                    "last_seen": now,
                    "raw_records": [],
                    "port": None,
                    "txt": [],
                    "src_ips": set(),
                    "src_ifaces": set(),
                    "iface": src_iface,
                    "ttl": {
                        "ptr": None,
                        "srv": None,
                        "txt": None,
                        "a": None,
                    },
                    "src_macs": set(),
                    "mac": None,                       
                    
                }
                SERVICE_CACHE[instance_fqdn] = inst
                new_instances.append((instance_fqdn, inst))
            else:
                inst = SERVICE_CACHE[instance_fqdn]
                inst["last_seen"] = now

            inst["txt"] = r["txt"]
            inst["last_seen"] = now
            inst["src_ips"].add(src_ip)
            inst.setdefault("src_ifaces", set()).add(src_iface)
            inst["iface"] = src_iface
            inst["raw_records"].append({"type": "TXT", "data": r})

            mac = lookup_mac_via_ip_neigh(src_ip, src_iface)
            if mac:
                inst.setdefault("src_macs", set()).add(mac)
                inst["mac"] = mac

            if not inst.get("service_name"):
                inferred = infer_service_name_from_instance(instance_fqdn)
                if inferred:
                    inst["service_name"] = inferred

        # A: Hostname -> IPv4
        elif rtype == 1 and "a" in r:
            host = name
            ip = r["a"]

            for inst in SERVICE_CACHE.values():
                if inst.get("hostname") == host:
                    inst["addresses"].add(ip)

                    inst["src_ips"].add(src_ip)
                    inst.setdefault("src_ifaces", set()).add(src_iface)
                    inst["iface"] = src_iface
                    mac = lookup_mac_via_ip_neigh(src_ip, src_iface)
                    if mac:
                        inst.setdefault("src_macs", set()).add(mac)
                        inst["mac"] = mac

        # AAAA: derzeit nur in raw_records relevant
        elif rtype == 28 and "aaaa" in r:
            # optional: speichern, falls du das später brauchst
            pass

    new_size = len(SERVICE_CACHE)
    # Logging hier bewusst minimal gehalten; detailliertes Logging im Hauptprozess
    _ = prev_size, new_size, new_instances  # hier nur zur Vollständigkeit
    
    
    if new_instances:
        logger.info(
            f"Neu erkannte Service-Instanzen (+{len(new_instances)}; Gesamt jetzt {new_size} Instanzen):"
        )
        max_log = 10
        for name, inst in new_instances[:max_log]:
            svc = inst.get("service_name") or infer_service_name_from_instance(name) or "?"
            host = inst.get("hostname")
            srcs = sorted(list(inst.get("src_ips", [])))
            src_str = ", ".join(srcs) if srcs else src_ip
            mac = inst.get("mac")
            logger.info(
                f"  - {name} "
                f"(Service: {svc}, Host: {host}, src_ip: {src_str}, mac: {mac})"
            )
        if len(new_instances) > max_log:
            logger.info(
                f"  ... {len(new_instances) - max_log} weitere neue Instanzen nicht geloggt"
            )


    # ─────────────────────────────────────────
    # Konsolidierung: pro (service_name, mac) nur eine Instanz behalten
    # ─────────────────────────────────────────
    canonical: Dict[tuple[str, str], tuple[str, str]] = {}

    # 1) Gewinner pro (service_name, mac) bestimmen (nach last_seen)
    for inst_name, inst in list(SERVICE_CACHE.items()):
        svc = inst.get("service_name")
        mac = inst.get("mac")

        if not svc or not mac:
            continue

        key = (svc, mac)
        last_seen_inst = inst.get("last_seen") or ""

        if key not in canonical:
            canonical[key] = (inst_name, last_seen_inst)
        else:
            winner_name, winner_last_seen = canonical[key]
            if last_seen_inst > winner_last_seen:
                canonical[key] = (inst_name, last_seen_inst)

    # 2) Alle Verlierer-Instanzen mit gleicher (service_name, mac) entfernen
    winner_names = {name for (name, _) in canonical.values()}

    for inst_name, inst in list(SERVICE_CACHE.items()):
        svc = inst.get("service_name")
        mac = inst.get("mac")

        if not svc or not mac:
            continue

        key = (svc, mac)

        # Wenn diese Instanz NICHT der Gewinner für ihr (svc, mac) ist → löschen
        if key in canonical and inst_name not in winner_names:
            logger.info(
                "Service-Instanz wird wegen Namenswechsel/Konsolidierung entfernt: "
                "%s (service=%s, mac=%s)",
                inst_name,
                svc,
                mac,
            )
            SERVICE_CACHE.pop(inst_name, None)
            PENDING_RESOLVE.pop(inst_name, None)


    # ─────────────────────────────────────────
    # Pending-Resolve-Map pflegen
    # ─────────────────────────────────────────
    # Alles, was noch nicht vollständig ist, in PENDING_RESOLVE aufnehmen
    for inst_name, inst in SERVICE_CACHE.items():
        if not is_instance_complete(inst):
            entry = PENDING_RESOLVE.get(inst_name) or {}
            entry.setdefault("last_tried", 0.0)
            entry.setdefault("try_count", 0)
            PENDING_RESOLVE[inst_name] = entry

    # Vollständig aufgelöste Instanzen aus PENDING_RESOLVE entfernen
    done = [name for name, inst in SERVICE_CACHE.items() if is_instance_complete(inst)]
    for name in done:
        if name in PENDING_RESOLVE:
            PENDING_RESOLVE.pop(name, None)




# ─────────────────────────────────────────────
# Mode-Helper + Snapshot für Hub
# ─────────────────────────────────────────────

def wants_sniff(mode: Optional[str]) -> bool:
    """
    Interfaces, die im Sinne von „Sniff/Scan“ arbeiten und zum Hub reporten dürfen.
    """
    if not mode:
        return False
    mode = mode.lower()
    if mode in ("scan", "sniff_only", "scan_and_advertise"):
        return True
    if "scan" in mode:
        return True
    return False


def wants_advertise(mode: Optional[str]) -> bool:
    """
    Interfaces, auf denen Spoofing/Advertising stattfinden soll.
    """
    if not mode:
        return False
    mode = mode.lower()
    if mode in ("advertise", "scan_and_advertise"):
        return True
    return False


def get_reporting_ifaces(cfg: Dict[str, Any]) -> Set[str]:
    """
    Liefert die Menge von Interfaces, deren Services an den Hub reported
    werden sollen. Das sind nur Interfaces, deren Mode „sniff/scan“-fähig ist.
    (advertise-only wird hier explizit ausgeschlossen.)
    """
    reporting: Set[str] = set()
    if not is_publish_to_hub_enabled(cfg):
        return reporting

    for iface_cfg in resolve_interface_configs(cfg):
        name = iface_cfg.get("name")
        mode = (iface_cfg.get("mode") or "").lower()
        if not name:
            continue
        if wants_sniff(mode):
            reporting.add(name)
    return reporting


def get_excluded_services(cfg: Dict[str, Any]) -> Set[str]:
    """
    Liefert die Menge von Service-Namen, die von der Discovery ausgeschlossen
    werden sollen. Liest aus der Sat-Config.

    WICHTIG:
    - Diese Liste greift auf dem Sat vor dem Hub-Ingest.
    - Ein hier ausgeschlossener Service erreicht den Hub nie.
    - Hub-UI-Include-Defaults koennen solche Services spaeter nicht
      "wieder einblenden", weil sie gar nicht persistiert/ingestiert werden.
    """
    excluded = cfg.get("excluded_services", [])
    return set(excluded) if excluded else set()


def is_service_reported_to_hub(inst_name: str, inst: Dict[str, Any], cfg: Dict[str, Any]) -> bool:
    """
    Prüft, ob ein Service an den Hub gemeldet wird.
    Verwendet die gleiche Logik wie build_service_snapshot().

    SAT-Abgrenzung:
    `excluded_services` ist ein Discovery-/Ingest-Filter auf Sat-Seite.
    Der neue Hub-Include-Filter ist davon fachlich getrennt und wirkt erst
    in der Hub-UI auf bereits ingestierte Services.
    """
    service_name = inst.get("service_name")

    if not is_publish_to_hub_enabled(cfg):
        return False
    
    # Excluded services werden nicht gemeldet
    excluded_services = get_excluded_services(cfg)
    if service_name in excluded_services:
        return False
    
    # Reverse-DNS-Namen als instance_name werden nicht gemeldet
    instance_name = inst.get("instance_name", inst_name)
    if is_reverse_dns_name(instance_name):
        return False
    
    # Service muss auf einem reporting interface gesehen worden sein
    reporting_ifaces = get_reporting_ifaces(cfg)
    src_ifaces: Set[str] = inst.get("src_ifaces", set()) or set()
    effective_ifaces = src_ifaces & reporting_ifaces
    
    # Wenn Service nur über advertise-only-IFs gesehen wurde → nicht gemeldet
    if not effective_ifaces:
        return False
    
    return True


def build_service_snapshot(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Baut eine Liste von Service-Dicts aus dem lokalen SERVICE_CACHE,
    passend zum ServiceIngestRequest im Hub.

    WICHTIG:
    - Es werden nur Services reported, die mindestens auf einem
      „reporting interface“ (sniff/scan/scan_and_advertise) gesehen wurden.
    - Services, die ausschließlich auf advertise-only-Interfaces auftauchen,
      werden NICHT an den Hub geschickt.
    - Services aus excluded_services werden NICHT an den Hub geschickt.
      Das ist bewusst SAT-seitig und unabhaengig von Hub-UI-Defaults.
    - Services mit Reverse-DNS-Namen als instance_name werden NICHT an den Hub geschickt.
    """
    snapshot: List[Dict[str, Any]] = []

    if not is_publish_to_hub_enabled(cfg):
        return snapshot

    reporting_ifaces = get_reporting_ifaces(cfg)
    excluded_services = get_excluded_services(cfg)

    with CACHE_LOCK:
        for inst_name, inst in SERVICE_CACHE.items():
            service_name = inst.get("service_name")
            
            # Excluded services überspringen
            if service_name in excluded_services:
                continue
            
            # Reverse-DNS-Namen als instance_name ignorieren
            instance_name = inst.get("instance_name", inst_name)
            if is_reverse_dns_name(instance_name):
                continue
            
            src_ifaces: Set[str] = inst.get("src_ifaces", set()) or set()
            # Schnittmenge mit Interfaces, die reporten dürfen
            effective_ifaces = src_ifaces & reporting_ifaces

            # Wenn Service nur über advertise-only-IFs gesehen wurde → skip
            if not effective_ifaces:
                continue

            snapshot.append({
                "service_name": inst.get("service_name"),
                "instance_name": inst.get("instance_name", inst_name),
                "hostname": inst.get("hostname"),
                "addresses": sorted(list(inst.get("addresses", []))),
                "port": inst.get("port"),
                "txt": inst.get("txt", []),
                "src_ips": sorted(list(inst.get("src_ips", []))),
                "src_ifaces": sorted(list(effective_ifaces)),
                "source_iface": sorted(list(effective_ifaces))[0],
                "last_seen": inst.get("last_seen"),
                "mac": inst.get("mac"),
                "src_macs": sorted(list(inst.get("src_macs", []))),                
            })

    return snapshot
