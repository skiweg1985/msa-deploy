#!/usr/bin/env python3
import logging
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import netifaces

from mdns_dns import (
    build_mdns_query,
    build_ptr_record,
    build_srv_record,
    build_txt_record,
    build_a_record,
    parse_mdns_message,
)


from mdns_utils import (
    SERVICE_BROWSER,
    STATIC_SERVICE_SEEDS,
    DISCOVERED_SERVICE_TYPES,
    CACHE_LOCK,
    SERVICE_CACHE,
    PENDING_RESOLVE,
    update_service_cache_from_records,
    derive_service_type_and_instance_fqdn,
    split_service_and_subtype,
)

MCAST_GRP = "224.0.0.251"
MDNS_PORT = 5353

logger = logging.getLogger("mdns-sat.worker")


# ─────────────────────────────────────────────
# HTTP-Helper für Spoof-Assignments
# ─────────────────────────────────────────────

def get_hub_base_url(cfg: Dict[str, Any]) -> str:
    return cfg["hub_url"].rstrip("/")


def sat_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Satellite-Token": cfg["shared_secret"],
    }


import time

def fetch_assignments(cfg: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Holt Spoof-Assignments:
      1. Bevorzugt aus dem WebSocket-Cache (cfg["ws_assignments"]), wenn frisch
      2. Fallback via HTTP, wenn WS-Cache leer oder älter als N Sekunden
    """

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


# ─────────────────────────────────────────────
# Hilfsfunktionen
# ─────────────────────────────────────────────

def get_ipv4_for_iface(iface: str) -> Optional[str]:
    try:
        addrs = netifaces.ifaddresses(iface)
    except ValueError:
        logger.warning("Interface '%s' nicht gefunden für IPv4-Ermittlung.", iface)
        return None
    ipv4 = addrs.get(netifaces.AF_INET, [])
    for e in ipv4:
        addr = e.get("addr")
        if addr:
            return addr
    return None


# ─────────────────────────────────────────────
# Per-Interface Worker (Scan + Sniff + Spoof)
# ─────────────────────────────────────────────

class MdnsInterfaceWorker:
    """
    Kombinierter mDNS-Worker pro Interface:

      - Scannt (PTR-Queries) je nach Mode
      - Snifft Antworten und aktualisiert SERVICE_CACHE
      - Spooft/announced Services (PTR/SRV/TXT/A) für Hub-Assignments
      - Beantwortet Queries für Services, die wir spoofen
      - Erkennung von Konflikten (wenn anderer Host selben Instance-Namen announced)
    """

    def __init__(self, cfg: Dict[str, Any], iface: str, mode: str, stop_event: threading.Event):
        self.cfg = cfg
        self.iface = iface
        self.mode = (mode or "none").lower()
        self.stop_event = stop_event



        # TTL für Announcements (in Sekunden)
        self.default_ttl = int(cfg.get("spoof_ttl", 120))

        # feinere TTL-Konfiguration pro RR-Typ
        self.ttl_ptr_browser = int(cfg.get("spoof_ttl_ptr_browser", 120))
        self.ttl_ptr_service = int(cfg.get("spoof_ttl_ptr_service", 120))
        self.ttl_srv = int(cfg.get("spoof_ttl_srv", 3600))
        self.ttl_txt = int(cfg.get("spoof_ttl_txt", 3600))
        self.ttl_a = int(cfg.get("spoof_ttl_a", 3600))

        # Announcement-Strategie
        self.announce_burst_count = int(cfg.get("spoof_announce_burst_count", 3))
        self.announce_burst_gap = float(cfg.get("spoof_announce_burst_gap", 0.1))
        self.announce_refresh_interval = int(cfg.get("spoof_announce_refresh_interval", 600))

        # Goodbye-Strategie ***
        self.goodbye_burst_count = int(cfg.get("spoof_goodbye_burst_count", 3))
        self.goodbye_burst_gap = float(cfg.get("spoof_goodbye_burst_gap", 0.1))

        # Query-Interval fürs Scanning
        self.query_interval = int(cfg.get("mdns_query_interval", 10))
        self.last_query = 0.0
    

        # Resolve-Interval für SRV/TXT/A-Auflösung unvollständiger Instanzen
        self.resolve_interval = int(cfg.get("mdns_resolve_interval", 5))
        self.last_resolve = 0.0

        # Umschalter für Unicast-Resolve
        self.use_unicast_resolve = bool(cfg.get("mdns_resolve_unicast", False))

        # Poll-Interval für Spoof-Assignments
        self.spoof_poll_interval = int(cfg.get("spoof_poll_interval", 15))
        self.next_spoof_poll = 0.0
        self.last_assignments_apply = 0.0


        # lokale IP des Interfaces
        self.local_ip: Optional[str] = get_ipv4_for_iface(self.iface)

        # Spoof-Assignments / Services
        self.conflict_keys: set[str] = set()
        self.current_services: Dict[str, Dict[str, Any]] = {}
        self.service_state: Dict[str, Dict[str, Any]] = {}

        # Socket
        self.sock = self._create_socket()

    # ─────────────────────────────────────
    # Socket-Erzeugung
    # ─────────────────────────────────────

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(0.5)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError as e:
            logger.warning("SO_REUSEADDR konnte für %s nicht gesetzt werden: %s", self.iface, e)

        # mehrere Prozesse/Threads auf 5353
        try:
            SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
            sock.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        except OSError as e:
            logger.warning("SO_REUSEPORT konnte für %s nicht gesetzt werden: %s", self.iface, e)

        # an Interface binden
        try:
            SO_BINDTODEVICE = 25
            sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.iface.encode())
            logger.info("mDNS-Socket via SO_BINDTODEVICE an Interface '%s' gebunden.", self.iface)
        except OSError as e:
            logger.error(
                "SO_BINDTODEVICE für Interface '%s' fehlgeschlagen: %s. "
                "mDNS-Worker läuft trotzdem weiter, aber Interface-Isolation fehlt.",
                self.iface,
                e,
            )

        # an mDNS-Port binden
        try:
            sock.bind(("", MDNS_PORT))
            logger.info("Socket an 0.0.0.0:%d für Interface '%s' gebunden.", MDNS_PORT, self.iface)
        except OSError as e:
            logger.error("Konnte Socket für Interface %s nicht an Port %d binden: %s",
                         self.iface, MDNS_PORT, e)

        # Multicast IF + Membership
        if self.local_ip:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(self.local_ip),
                )
                logger.info(
                    "IP_MULTICAST_IF für '%s' auf %s gesetzt.",
                    self.iface,
                    self.local_ip,
                )
            except OSError as e:
                logger.warning(
                    "Konnte IP_MULTICAST_IF für '%s' nicht setzen: %s",
                    self.iface,
                    e,
                )

            try:
                mreq = struct.pack(
                    "4s4s",
                    socket.inet_aton(MCAST_GRP),
                    socket.inet_aton(self.local_ip),
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                logger.info(
                    "Multicast-Gruppe %s gejoint (iface=%s, ip=%s).",
                    MCAST_GRP, self.iface, self.local_ip
                )
            except OSError as e:
                logger.warning(
                    "Konnte Multicast-Gruppe %s auf iface %s nicht joinen: %s",
                    MCAST_GRP, self.iface, e
                )

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        return sock

    # ─────────────────────────────────────
    # Fehlerbehandlung
    # ─────────────────────────────────────

    def _handle_socket_send_error(self, e: Exception, context: str):
        import errno
        if isinstance(e, OSError) and e.errno == errno.ENODEV:
            logger.error(
                "[%s] Interface %s nicht mehr vorhanden (ENODEV) – Worker beendet sich.",
                context,
                self.iface,
            )
            self.stop_event.set()
            # Worker-Hauptloop verlassen
            raise SystemExit
        else:
            logger.error("[%s] Socket-Fehler auf iface %s: %s", context, self.iface, e)

    # ─────────────────────────────────────
    # Service-Signaturen für Änderungs-Erkennung
    # ─────────────────────────────────────

    def _service_signature(self, assignment: Dict[str, Any]) -> str:
        svc = assignment.get("service") or {}
        instance_name = svc.get("instance_name")
        service_name = svc.get("service_name")
        hostname = svc.get("hostname")
        port = int(svc.get("port") or 0)

        addresses = svc.get("addresses") or []
        txt_list = svc.get("txt") or []

        sig_tuple = (
            instance_name,
            service_name,
            hostname,
            port,
            tuple(sorted(addresses)),
            tuple(sorted(txt_list)),
        )
        return repr(sig_tuple)

    # ─────────────────────────────────────
    # Paketbau für Antworten/Announcements
    # ─────────────────────────────────────

    def _build_service_response_packet(
        self,
        service: Dict[str, Any],
        include_browser_ptr: bool = True,
        include_service_ptr: bool = True,
        include_srv: bool = True,
        include_txt: bool = True,
        include_a: bool = True,
        include_subtype_ptr: bool = True,
        ttl_override: Optional[int] = None,
    ) -> bytes:
        """
        Baut ein mDNS-Response-Paket für EINEN Service mit selektiv ein-/ausschaltbaren RRs.
        Wird sowohl für Announcements als auch für Antworten auf Queries genutzt.
        """
        svc_type_fqdn, instance_fqdn = derive_service_type_and_instance_fqdn(service)

        hostname = service.get("hostname") or ""
        hostname_fqdn = ensure_fqdn(hostname) if hostname else ""
        port = int(service.get("port") or 0)
        txt_list = service.get("txt") or []

        # Subtype aus service_name ableiten (falls vorhanden)
        raw_service_name = (service.get("service_name") or "").strip(".")
        base_service_name, subtype_name = split_service_and_subtype(raw_service_name)
        subtype_fqdn = ensure_fqdn(subtype_name) if subtype_name else None

        ip_addr = None
        for a in service.get("addresses") or []:
            try:
                socket.inet_aton(a)
                ip_addr = a
                break
            except OSError:
                continue

        answers = []

        # Browser-PTR
        if include_browser_ptr:
            ttl = ttl_override if ttl_override is not None else self.ttl_ptr_browser
            answers.append(
                build_ptr_record(SERVICE_BROWSER, svc_type_fqdn, ttl)
            )

        # Service-PTR
        if include_service_ptr:
            ttl = ttl_override if ttl_override is not None else self.ttl_ptr_service
            answers.append(
                build_ptr_record(svc_type_fqdn, instance_fqdn, ttl)
            )

        # Subtype-PTR
        if include_subtype_ptr and subtype_fqdn:
            ttl = ttl_override if ttl_override is not None else self.ttl_ptr_service
            answers.append(
                build_ptr_record(subtype_fqdn, instance_fqdn, ttl)
            )

        # SRV
        if include_srv and hostname_fqdn and port > 0:
            ttl = ttl_override if ttl_override is not None else self.ttl_srv
            answers.append(
                build_srv_record(instance_fqdn, hostname_fqdn, port, ttl)
            )

        # TXT
        if include_txt and txt_list:
            ttl = ttl_override if ttl_override is not None else self.ttl_txt
            answers.append(
                build_txt_record(instance_fqdn, txt_list, ttl)
            )

        # A
        if include_a and hostname_fqdn and ip_addr:
            ttl = ttl_override if ttl_override is not None else self.ttl_a
            a_rr = build_a_record(hostname_fqdn, ip_addr, ttl)
            if a_rr:
                answers.append(a_rr)

        if not answers:
            return b""

        ancount = len(answers)
        header = struct.pack(
            "!HHHHHH",
            0,          # ID = 0 (mDNS)
            0x8400,     # Flags: QR=1, AA=1
            0,          # QDCOUNT
            ancount,    # ANCOUNT
            0,          # NSCOUNT
            0,          # ARCOUNT
        )
        body = b"".join(answers)
        return header + body

    def _send_service_announcement(self, service: Dict[str, Any], ttl: Optional[int] = None):
        """
        Announce oder Goodbye:
        - ttl is None    -> normale Announce, per-Typ-TTLs (PTR/SRV/TXT/A)
        - ttl == 0       -> Goodbye, alle RRs mit TTL=0
        """

        svc_type_fqdn, instance_fqdn = derive_service_type_and_instance_fqdn(service)

        # Goodbye-Special: hier ist ein echtes Override sinnvoll
        if ttl == 0:
            pkt = self._build_service_response_packet(
                service,
                include_browser_ptr=True,
                include_service_ptr=True,
                include_srv=True,
                include_txt=True,
                include_a=True,
                ttl_override=0,
            )
            log_ttl_info = "0 (goodbye)"
        else:
            # normale Announce → per-Typ-TTLs
            pkt = self._build_service_response_packet(
                service,
                include_browser_ptr=True,
                include_service_ptr=True,
                include_srv=True,
                include_txt=True,
                include_a=True,
                ttl_override=None,
            )
            log_ttl_info = (
                f"ptr_browser={self.ttl_ptr_browser}, "
                f"ptr_service={self.ttl_ptr_service}, "
                f"srv={self.ttl_srv}, "
                f"txt={self.ttl_txt}, "
                f"a={self.ttl_a}"
            )

        if not pkt:
            return

        try:
            logger.info(
                "[TX-ANNOUNCE] iface=%s dst=%s:%d instance=%s service=%s ttls={%s}",
                self.iface, MCAST_GRP, MDNS_PORT, instance_fqdn, svc_type_fqdn, log_ttl_info,
            )
            self.sock.sendto(pkt, (MCAST_GRP, MDNS_PORT))
        except Exception as e:
            self._handle_socket_send_error(e, "TX-ANNOUNCE")
 

    def _send_service_goodbye_burst(self, svc: Dict[str, Any]):
        """
        Sendet ein mDNS-Goodbye (TTL=0) in einem kleinen Burst,
        um Paketverluste auf dem Weg zu kompensieren.
        """
        for i in range(self.goodbye_burst_count):
            self._send_service_announcement(svc, ttl=0)
            if self.goodbye_burst_gap > 0 and i < self.goodbye_burst_count - 1:
                time.sleep(self.goodbye_burst_gap) 
                    
                
    # ─────────────────────────────────────
    # Resolve-Queries (SRV/TXT/A) für unvollständige Services
    # ─────────────────────────────────────

    def _send_resolve_query(self, qname: str, qtype: int, src_ip: Optional[str] = None):
        """
        Sendet eine Resolve-Query (SRV/TXT/A) für einen Namen.
        - Standard: Multicast
        - Optional: Unicast an src_ip, wenn mdns_resolve_unicast=True und src_ip vorhanden ist.
        """
        pkt = build_mdns_query(qname, qtype=qtype)

        if self.use_unicast_resolve and src_ip:
            dest = (src_ip, MDNS_PORT)
        else:
            dest = (MCAST_GRP, MDNS_PORT)

        try:
            logger.debug(
                "[%s] Resolve-Query qname=%s qtype=%d dest=%s",
                self.iface, qname, qtype, dest,
            )
            self.sock.sendto(pkt, dest)
        except Exception as e:
            self._handle_socket_send_error(
                e,
                f"RESOLVE-QUERY {qname} type={qtype}"
            )

    def _send_resolve_query_for_instance(self, instance_name: str):
        """
        Fragt SRV+TXT für eine Instanz an.
        Optional Unicast gegen die zuletzt gesehene Quell-IP.
        """
        with CACHE_LOCK:
            inst = SERVICE_CACHE.get(instance_name)
            src_ips = list(inst.get("src_ips", [])) if inst else []

        src_ip = src_ips[0] if src_ips else None

        # SRV
        self._send_resolve_query(instance_name, qtype=33, src_ip=src_ip)
        # TXT
        self._send_resolve_query(instance_name, qtype=16, src_ip=src_ip)

    def _send_resolve_query_for_hostname(self, hostname: str):
        """
        Fragt A-Record für einen Hostnamen an (für die IP des Targets).
        """
        with CACHE_LOCK:
            # Versuch, eine sinnvolle src_ip aus irgendeiner Instanz zu nehmen,
            # die diesen Hostnamen bereits benutzt (optional).
            src_ip = None
            for inst in SERVICE_CACHE.values():
                if inst.get("hostname") == hostname:
                    src_list = list(inst.get("src_ips", []))
                    if src_list:
                        src_ip = src_list[0]
                        break

        self._send_resolve_query(hostname, qtype=1, src_ip=src_ip)

    def _resolve_pending_instances(self, now: float):
        """
        Läuft alle PENDING_RESOLVE-Einträge durch und schickt gezielt SRV/TXT/A-Queries,
        um Einträge schneller vollständig zu bekommen.
        """
        max_per_round = 5  # um das Netz nicht zuzuspammen

        with CACHE_LOCK:
            pending_items = list(PENDING_RESOLVE.items())[:max_per_round]
            cache_snapshot = dict(SERVICE_CACHE)

        for inst_name, state in pending_items:
            inst = cache_snapshot.get(inst_name)
            if not inst:
                continue

            hostname = inst.get("hostname")
            addresses = inst.get("addresses") or set() or []
            port = inst.get("port")

            # 1) Noch kein Host oder Port → SRV/TXT für Instanz
            if not hostname or not port:
                logger.debug(
                    "[%s] Resolve-Instanz (SRV/TXT) für %s",
                    self.iface, inst_name,
                )
                self._send_resolve_query_for_instance(inst_name)

            # 2) Hostname vorhanden, aber noch keine IP → A-Query
            elif hostname and not addresses:
                logger.debug(
                    "[%s] Resolve-Hostname (A) für %s (%s)",
                    self.iface, inst_name, hostname,
                )
                self._send_resolve_query_for_hostname(hostname)

            # Try-Zähler hochzählen (nur Info)
            state["last_tried"] = now
            state["try_count"] = state.get("try_count", 0) + 1            
            
            
            

    # ─────────────────────────────────────
    # Query-Handling (Antworten auf PTR/A)
    # ─────────────────────────────────────

    def _handle_query(self, questions, addr, known_answers: List[Dict[str, Any]]):
        """
        Antworten auf mDNS-Queries:

        - PTR (_xyz._tcp.local, inkl. Subtypes wie _universal._sub._ipps._tcp.local)
        - A   (Hostname → IPv4-Adresse)

        Low-Traffic-Optimierungen:
          - pro Paket jede (qname, instance/hostname)-Kombination nur einmal beantworten
          - Known-Answer Suppression
        """
        client_ip, client_port = addr

        if not self.current_services:
            return

        # Known-Answers indexieren: (name, type) → True
        known_by_name_type: Dict[tuple[str, int], bool] = {}
        for r in known_answers or []:
            name = r.get("name")
            rtype = r.get("type")
            if not name or rtype is None:
                continue
            known_by_name_type[(name, rtype)] = True

        answered: set[tuple[str, str]] = set()

        for q in questions:
            qname = q["name"]
            qtype = q["qtype"]
            unicast = q["unicast"]

            # 1) PTR-Queries
            if qtype == 12:
                for sk, assignment in self.current_services.items():
                    if sk in self.conflict_keys:
                        continue

                    svc = assignment.get("service") or {}
                    raw_service_name = (svc.get("service_name") or "").rstrip(".")
                    if not raw_service_name:
                        continue

                    base_service_name, subtype_name = split_service_and_subtype(raw_service_name)

                    # Query muss entweder auf Basis-Service oder Subtype passen
                    if qname not in (base_service_name, raw_service_name):
                        continue

                    instance = svc.get("instance_name")
                    if not instance:
                        continue

                    svc_type_fqdn, instance_fqdn = derive_service_type_and_instance_fqdn(svc)
                    svc_type_name_canon = svc_type_fqdn.rstrip(".")
                    instance_name_canon = instance_fqdn.rstrip(".")

                    subtype_name_canon = subtype_name if subtype_name else None

                    hostname = svc.get("hostname") or ""
                    hostname_fqdn = ensure_fqdn(hostname) if hostname else ""
                    hostname_name_canon = hostname_fqdn.rstrip(".") if hostname_fqdn else ""

                    key = (qname, instance_name_canon)
                    if key in answered:
                        continue

                    # Known-Answer-Suppression
                    browser_ptr_known = (SERVICE_BROWSER, 12) in known_by_name_type
                    service_ptr_known_base = (svc_type_name_canon, 12) in known_by_name_type
                    service_ptr_known_sub = (
                        (subtype_name_canon, 12) in known_by_name_type
                        if subtype_name_canon
                        else False
                    )
                    srv_known = (instance_name_canon, 33) in known_by_name_type
                    txt_known = (instance_name_canon, 16) in known_by_name_type
                    a_known = (
                        (hostname_name_canon, 1) in known_by_name_type
                        if hostname_name_canon
                        else False
                    )

                    include_browser_ptr = not browser_ptr_known
                    include_service_ptr = not service_ptr_known_base
                    include_subtype_ptr = bool(subtype_name_canon) and not service_ptr_known_sub

                    include_srv = not srv_known
                    include_txt = bool(svc.get("txt") or []) and not txt_known
                    include_a = bool(hostname_name_canon) and not a_known

                    if not any([
                        include_browser_ptr,
                        include_service_ptr,
                        include_subtype_ptr,
                        include_srv,
                        include_txt,
                        include_a,
                    ]):
                        answered.add(key)
                        continue

                    pkt = self._build_service_response_packet(
                        svc,
                        include_browser_ptr=include_browser_ptr,
                        include_service_ptr=include_service_ptr,
                        include_srv=include_srv,
                        include_txt=include_txt,
                        include_a=include_a,
                        include_subtype_ptr=include_subtype_ptr,
                        ttl_override=None,
                    )
                    if not pkt:
                        continue

                    dest = (client_ip, client_port) if unicast else (MCAST_GRP, MDNS_PORT)
                    try:
                        self.sock.sendto(pkt, dest)
                        answered.add(key)
                    except Exception as e:
                        self._handle_socket_send_error(e, "QUERY-ANSWER-PTR")

            # 2) A-Queries
            elif qtype == 1:
                qname_norm = qname.rstrip(".").lower()

                for sk, assignment in self.current_services.items():
                    if sk in self.conflict_keys:
                        continue

                    svc = assignment.get("service") or {}
                    hostname = (svc.get("hostname") or "").strip(".")
                    if not hostname:
                        continue

                    hostname_fqdn = ensure_fqdn(hostname)
                    hostname_name_canon = hostname_fqdn.rstrip(".")
                    hostname_norm = hostname_name_canon.lower()

                    if qname_norm != hostname_norm:
                        continue

                    key = ("A", hostname_norm)
                    if key in answered:
                        continue

                    a_known = (hostname_name_canon, 1) in known_by_name_type
                    if a_known:
                        answered.add(key)
                        continue

                    pkt = self._build_service_response_packet(
                        svc,
                        include_browser_ptr=False,
                        include_service_ptr=False,
                        include_srv=False,
                        include_txt=False,
                        include_a=True,
                        include_subtype_ptr=False,
                        ttl_override=None,
                    )
                    if not pkt:
                        continue

                    dest = (client_ip, client_port) if unicast else (MCAST_GRP, MDNS_PORT)
                    try:
                        self.sock.sendto(pkt, dest)
                        answered.add(key)
                    except Exception as e:
                        self._handle_socket_send_error(e, "QUERY-ANSWER-A")

    # ─────────────────────────────────────
    # Konflikterkennung
    # ─────────────────────────────────────

    def _check_conflict_from_response(self, records: List[Dict[str, Any]], src_ip: str):
        if not self.current_services:
            return

        if self.local_ip and src_ip == self.local_ip:
            return

        for sk, assignment in self.current_services.items():
            svc = assignment.get("service") or {}
            inst = (svc.get("instance_name") or "").rstrip(".")
            if not inst:
                continue

            for r in records:
                rtype = r["type"]
                cand = None

                if rtype == 12 and "ptr" in r:
                    cand = r["ptr"]
                elif rtype in (33, 16):
                    cand = r["name"]

                if not cand:
                    continue

                if cand.rstrip(".") == inst:
                    logger.warning(
                        "Konflikt erkannt für Service-Key %s (Instance %s) auf iface %s, Quelle %s – markiere als konflikt.",
                        sk, inst, self.iface, src_ip,
                    )
                    self.conflict_keys.add(sk)
                    break


    # ─────────────────────────────────────
    # Shutdown-Goodbyes
    # ─────────────────────────────────────

    def _send_goodbyes_on_shutdown(self):
        """
        Versucht, für alle aktuell über dieses Interface announcten Services
        Goodbyes (TTL=0) in einem gemeinsamen Burst-Loop zu senden, bevor der
        Worker endet.

        Statt pro Service zu schlafen, werden alle Services pro Burst-Runde
        abgearbeitet:
          Runde 1: Goodbye #1 für alle Services
          Runde 2: Goodbye #2 für alle Services
          ...
        """
        if not self.current_services:
            return

        # stabile Kopie der Services machen
        services = []
        for sk, assignment in list(self.current_services.items()):
            svc = assignment.get("service")
            if not svc:
                continue
            services.append((sk, svc))

        if not services:
            return

        logger.info(
            "[SHUTDOWN] Sende Goodbye-Bursts für %d Services auf iface %s "
            "(count=%d, gap=%.2fs)",
            len(services),
            self.iface,
            self.goodbye_burst_count,
            self.goodbye_burst_gap,
        )

        # Gemeinsamer Burst-Loop:
        # in jeder Runde alle Services einmal mit TTL=0 announcen.
        for n in range(self.goodbye_burst_count):

            logger.info(
                "[SHUTDOWN] Goodbye-Runde %d/%d auf iface %s",
                n + 1,
                self.goodbye_burst_count,
                self.iface,
            )

            for sk, svc in services:
                try:
                    logger.debug(
                        "[SHUTDOWN] Goodbye (%d) für Service-Key %s auf iface %s",
                        n + 1,
                        sk,
                        self.iface,
                    )
                    self._send_service_announcement(svc, ttl=0)
                except SystemExit:
                    logger.warning(
                        "[SHUTDOWN] SystemExit beim Goodbye für %s auf %s – "
                        "Interface vermutlich bereits weg.",
                        sk,
                        self.iface,
                    )
                    return
                except Exception as e:
                    logger.error(
                        "[SHUTDOWN] Fehler beim Senden von Goodbye für %s auf %s (Runde %d): %s",
                        sk,
                        self.iface,
                        n + 1,
                        e,
                    )

            # nur zwischen den Runden warten, nicht zwischen den Services
            if self.goodbye_burst_gap > 0 and n < self.goodbye_burst_count - 1:
                time.sleep(self.goodbye_burst_gap)



    # ─────────────────────────────────────
    # Hauptloop
    # ─────────────────────────────────────

    def run(self):
        logger.info(
            "Starte MdnsInterfaceWorker (iface=%s, mode=%s, local_ip=%s)",
            self.iface,
            self.mode,
            self.local_ip,
        )

        last_services: Dict[str, Dict[str, Any]] = {}

        try:
            while not self.stop_event.is_set():
                now = time.time()

                # hat der WS-Handler seit dem letzten Apply etwas Neues geliefert?
                updated_at = float(self.cfg.get("assignments_updated_at", 0.0))
                force_reload = updated_at > self.last_assignments_apply


                # 1) Spoof-Assignments holen & Announcements steuern (nur bei Advertise-Modes)
                if "advertise" in self.mode and (now >= self.next_spoof_poll or force_reload):
                    assignments = fetch_assignments(self.cfg)

                    if assignments is None:
                        # Hub gerade nicht erreichbar → alten Stand behalten
                        logger.warning(
                            "Assignments konnten nicht aktualisiert werden (Hub down?), "
                            "behalte bisherigen Stand (current_services bleibt unverändert)."
                        )
                        # NICHT: Goodbyes schicken, NICHT: last_services leeren
                        self.next_spoof_poll = now + self.spoof_poll_interval
                        continue

                    # Ab hier: assignments ist eine *valide* Liste (auch leer = "Hub sagt: nichts mehr spoofen")
                    filtered: Dict[str, Dict[str, Any]] = {}
                    for a in assignments:
                        if "service_key" not in a:
                            continue
                        if assignment_matches_iface(a, self.iface):
                            filtered[a["service_key"]] = a

                    logger.info(
                        "Assignments vom Hub (iface=%s): total=%d → %d relevant.",
                        self.iface,
                        len(assignments),
                        len(filtered),
                    )

                    self.last_assignments_apply = now
                    self.next_spoof_poll = now + self.spoof_poll_interval

                    # Konflikt-Set einkürzen
                    self.conflict_keys = {k for k in self.conflict_keys if k in filtered}
                    self.current_services = filtered

                    # Goodbye nur, wenn der Hub *bewusst* Services entfernt hat
                    removed_keys = set(last_services.keys()) - set(filtered.keys())
                    for sk in removed_keys:
                        old = last_services[sk]
                        svc = old.get("service")
                        if not svc:
                            continue
                        logger.info(
                            "Sende Goodbye-Burst für entfernten Service: %s (iface=%s, count=%d, gap=%.2fs)",
                            sk,
                            self.iface,
                            self.goodbye_burst_count,
                            self.goodbye_burst_gap,
                        )
                        self._send_service_goodbye_burst(svc)
                        self.service_state.pop(sk, None)


                    # Announcements für aktuelle Services (ohne Konflikte)
                    for sk, assignment in filtered.items():
                        if sk in self.conflict_keys:
                            logger.warning(
                                "Service %s ist als konfliktbehaftet markiert – überspringe Announcement (iface=%s).",
                                sk, self.iface,
                            )
                            continue

                        svc = assignment.get("service")
                        if not svc:
                            logger.warning("Assignment %s ohne 'service'-Objekt; ignoriert.", sk)
                            continue

                        sig = self._service_signature(assignment)
                        state = self.service_state.get(sk)
                        now_ts = now

                        if state is None:
                            # Neuer Service → Burst
                            logger.info(
                                "Announce (NEW) Service: %s | %s → %s (Port=%s, Addr=%s, iface=%s)",
                                sk,
                                svc.get("instance_name"),
                                svc.get("service_name"),
                                svc.get("port"),
                                svc.get("addresses"),
                                self.iface,
                            )
                            for i in range(self.announce_burst_count):
                                self._send_service_announcement(svc, ttl=self.default_ttl)
                                if (
                                    self.announce_burst_gap > 0
                                    and i < self.announce_burst_count - 1
                                ):
                                    time.sleep(self.announce_burst_gap)
                            self.service_state[sk] = {
                                "last_announce": now_ts,
                                "signature": sig,
                            }
                            continue

                        last_announce = state.get("last_announce", 0.0)
                        last_sig = state.get("signature")
                        changed = sig != last_sig
                        age = now_ts - last_announce
                        too_old = age >= self.announce_refresh_interval

                        if changed:
                            logger.info(
                                "Announce (CHANGED) Service: %s | %s → %s (Port=%s, Addr=%s, iface=%s, age=%.1fs)",
                                sk,
                                svc.get("instance_name"),
                                svc.get("service_name"),
                                svc.get("port"),
                                svc.get("addresses"),
                                self.iface,
                                age,
                            )
                            self._send_service_announcement(svc, ttl=self.default_ttl)
                            state["last_announce"] = now_ts
                            state["signature"] = sig
                        elif too_old:
                            logger.info(
                                "Announce (REFRESH) Service: %s | %s → %s (Port=%s, Addr=%s, iface=%s, age=%.1fs)",
                                sk,
                                svc.get("instance_name"),
                                svc.get("service_name"),
                                svc.get("port"),
                                svc.get("addresses"),
                                self.iface,
                                age,
                            )
                            self._send_service_announcement(svc, ttl=self.default_ttl)
                            state["last_announce"] = now_ts

                    last_services = filtered
                    self.next_spoof_poll = now + self.spoof_poll_interval

                # 2) Aktive PTR-Queries (nur wenn Scan-Mode)
                active_scan = self.mode in ("scan", "scan_and_advertise")
                if active_scan and now - self.last_query >= self.query_interval:
                    with CACHE_LOCK:
                        dynamic_types = sorted(list(DISCOVERED_SERVICE_TYPES))

                    all_queries = [SERVICE_BROWSER] + STATIC_SERVICE_SEEDS + dynamic_types
                    seen = []
                    for svc in all_queries:
                        if not svc or svc in seen:
                            continue
                        seen.append(svc)

                    logger.info(
                        "[mDNS-Worker:%s] → Sende PTR-Queries: %s",
                        self.iface,
                        ", ".join(seen),
                    )

                    for svc in seen:
                        pkt = build_mdns_query(svc, qtype=12)
                        try:
                            self.sock.sendto(pkt, (MCAST_GRP, MDNS_PORT))
                        except Exception as e:
                            self._handle_socket_send_error(
                                e,
                                f"ACTIVE-SCAN {svc}"
                            )

                    self.last_query = now


                # (2b) Resolve unvollständige Instanzen
                if self.mode in ("scan", "scan_and_advertise") and now - self.last_resolve >= self.resolve_interval:
                    self._resolve_pending_instances(now)
                    self.last_resolve = now

                # 3) Pakete empfangen / verarbeiten
                try:
                    data, addr = self.sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error("[mDNS-Worker:%s] Fehler beim Empfangen: %s", self.iface, e)
                    continue

                src_ip, src_port = addr

                # Eigene Pakete ignorieren
                if self.local_ip and src_ip == self.local_ip:
                    continue


                # Neues Parsing über mdns_dns.parse_mdns_message
                is_response, questions, records = parse_mdns_message(data)

                # Query → ggf. spoof beantworten
                if not is_response and questions and "advertise" in self.mode:
                    self._handle_query(questions, addr, records)

                # Response → Cache aktualisieren und Konflikte checken
                if is_response and records:
                    with CACHE_LOCK:
                        update_service_cache_from_records(
                            records,
                            src_ip=src_ip,
                            src_iface=self.iface,
                        )
                    self._check_conflict_from_response(records, src_ip)

        except SystemExit:
            # gewolltes Stoppen wegen Interface-Verlust
            pass
        finally:
            # vor dem Schließen des Sockets für alle noch aktiven Services Goodbye senden
            try:
                self._send_goodbyes_on_shutdown()
            except Exception as e:
                logger.error(
                    "[SHUTDOWN] Fehler beim Senden der Shutdown-Goodbyes auf %s: %s",
                    self.iface,
                    e,
                )

            self.sock.close()
            logger.info("MdnsInterfaceWorker (iface=%s) beendet.", self.iface)


# helper für FQDN in diesem Modul
def ensure_fqdn(name: str) -> str:
    if not name:
        return ""
    if not name.endswith("."):
        return name + "."
    return name