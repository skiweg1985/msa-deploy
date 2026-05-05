# mdns_worker.py

#!/usr/bin/env python3
import logging
import socket
import struct
import time
from typing import Any, Dict, List, Optional

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

from mdns_constants import MCAST_GRP, MDNS_PORT
from mdns_assignments import fetch_assignments, assignment_matches_iface
from mdns_socket import get_ipv4_for_iface, create_mdns_socket
from mdns_helpers import (
    ensure_fqdn,
    service_signature,
    format_questions_short,
    format_records_short,
)
from mdns_resolver import resolve_pending_instances
from mdns_query_handler import handle_query
from mdns_conflicts import check_conflict_from_response
from sat_admin import ADMIN_STATS

logger = logging.getLogger("mdns-sat.worker")


class MdnsInterfaceWorker:
    """
    Kombinierter mDNS-Worker pro Interface:

      - Scannt (PTR-Queries) je nach Mode
      - Snifft Antworten und aktualisiert SERVICE_CACHE
      - Spooft/announced Services (PTR/SRV/TXT/A) für Hub-Assignments
      - Beantwortet Queries für Services, die wir spoofen
      - Erkennung von Konflikten (wenn anderer Host selben Instance-Namen announced)
    """

    def __init__(self, cfg: Dict[str, Any], iface: str, mode: str, stop_event):
        self.cfg = cfg
        self.iface = iface
        self.mode = (mode or "none").lower()
        self.stop_event = stop_event


        #MDNS Subtype aliase laden
        self.subtype_aliases: Dict[str, list[str]] = cfg.get("mdns_subtype_aliases", {})

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
        self.announce_refresh_interval = int(
            cfg.get("spoof_announce_refresh_interval", 600)
        )

        # Goodbye-Strategie
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


        # Strategie für Unicast-mDNS-Antworten:
        # - "auto"         → Interface-Socket, außer wenn nur Link-Local/Dummy-IP → globales Socket
        # - "force_default"→ immer globales Socket (Default-Route)
        # - "iface_only"   → immer Interface-Socket (altes Verhalten)
        self.unicast_reply_mode = (
            cfg.get("mdns_unicast_reply_mode", "auto").lower()
        )


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
        self.sock = create_mdns_socket(self.iface, self.local_ip)

    # ─────────────────────────────────────
    # Fehlerbehandlung
    # ─────────────────────────────────────

    def _handle_socket_send_error(self, e: Exception, context: str):
        import errno

        if isinstance(e, OSError):
            if e.errno == errno.ENODEV:
                logger.error(
                    "[%s] Interface %s nicht mehr vorhanden (ENODEV) – Worker beendet sich.",
                    context,
                    self.iface,
                )
                self.stop_event.set()
                raise SystemExit

            # Netzwerk/Route-Probleme ebenfalls als fatal behandeln
            if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL):
                logger.error(
                    "[%s] Netzwerk auf iface %s nicht erreichbar (errno=%s) – Worker beendet sich, "
                    "Main-Loop kann ihn neu aufbauen.",
                    context,
                    self.iface,
                    e.errno,
                )
                self.stop_event.set()
                raise SystemExit

        # alle anderen Fehler nur loggen
        logger.error("[%s] Socket-Fehler auf iface %s: %s", context, self.iface, e)
        
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
        subtype_owner_override: Optional[str] = None,
    ) -> bytes:
        """
        Baut ein mDNS-Response-Paket für EINEN Service mit selektiv ein-/ausschaltbaren RRs.
        Wird sowohl für Announcements als auch für Antworten auf Queries genutzt.

        subtype_owner_override:
          - None  → Subtype-PTR (falls genutzt) hängt am "natürlichen" Subtype-Namen aus service_name
          - "name._sub._xyz._tcp.local" → Subtype-PTR wird mit exakt diesem Owner-Namen gebaut,
            z. B. "_universal._sub._ipp._tcp.local" für AirPrint-Subtypes.
        """
        # FQDNs für Service-Typ und Instanz
        svc_type_fqdn, instance_fqdn = derive_service_type_and_instance_fqdn(service)

        hostname = service.get("hostname") or ""
        hostname_fqdn = ensure_fqdn(hostname) if hostname else ""
        port = int(service.get("port") or 0)
        txt_list = service.get("txt") or []

        # Subtype aus service_name ableiten (falls vorhanden)
        raw_service_name = (service.get("service_name") or "").strip(".")
        base_service_name, subtype_name = split_service_and_subtype(raw_service_name)

        # „natürlicher“ Subtype-Name aus service_name
        subtype_fqdn = ensure_fqdn(subtype_name) if subtype_name else None

        # Falls wir explizit einen Owner für den Subtype-PTR vorgeben wollen
        if subtype_owner_override:
            subtype_owner_name = ensure_fqdn(subtype_owner_override)
        else:
            subtype_owner_name = subtype_fqdn

        # IPv4-Adresse wählen (erste gültige)
        ip_addr = None
        for a in service.get("addresses") or []:
            try:
                socket.inet_aton(a)
                ip_addr = a
                break
            except OSError:
                continue

        answers = []

        # Browser-PTR (_services._dns-sd._udp.local → _ipp._tcp.local)
        if include_browser_ptr:
            ttl = ttl_override if ttl_override is not None else self.ttl_ptr_browser
            answers.append(build_ptr_record(SERVICE_BROWSER, svc_type_fqdn, ttl))

        # Service-PTR (_ipp._tcp.local → Instanz)
        if include_service_ptr:
            ttl = ttl_override if ttl_override is not None else self.ttl_ptr_service
            answers.append(build_ptr_record(svc_type_fqdn, instance_fqdn, ttl))

        # Subtype-PTR (_universal._sub._ipp._tcp.local → Instanz, o. ä.)
        if include_subtype_ptr and subtype_owner_name:
            ttl = ttl_override if ttl_override is not None else self.ttl_ptr_service
            answers.append(build_ptr_record(subtype_owner_name, instance_fqdn, ttl))

        # SRV (Instanz → Hostname:Port)
        if include_srv and hostname_fqdn and port > 0:
            ttl = ttl_override if ttl_override is not None else self.ttl_srv
            answers.append(build_srv_record(instance_fqdn, hostname_fqdn, port, ttl))

        # TXT
        if include_txt and txt_list:
            ttl = ttl_override if ttl_override is not None else self.ttl_txt
            answers.append(build_txt_record(instance_fqdn, txt_list, ttl))

        # A-Record (Hostname → IPv4)
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
            0,       # ID = 0 (mDNS)
            0x8400,  # Flags: QR=1, AA=1
            0,       # QDCOUNT
            ancount, # ANCOUNT
            0,       # NSCOUNT
            0,       # ARCOUNT
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
                self.iface,
                MCAST_GRP,
                MDNS_PORT,
                instance_fqdn,
                svc_type_fqdn,
                log_ttl_info,
            )
            self.sock.sendto(pkt, (MCAST_GRP, MDNS_PORT))
            if ttl == 0:
                ADMIN_STATS.increment("spoof_goodbyes_total")
            else:
                ADMIN_STATS.increment("spoof_announces_total")
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
                if "advertise" in self.mode and (
                    now >= self.next_spoof_poll or force_reload
                ):
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
                                sk,
                                self.iface,
                            )
                            continue

                        svc = assignment.get("service")
                        if not svc:
                            logger.warning(
                                "Assignment %s ohne 'service'-Objekt; ignoriert.", sk
                            )
                            continue

                        sig = service_signature(assignment)
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
                            ADMIN_STATS.increment("queries_sent_total")
                        except Exception as e:
                            self._handle_socket_send_error(e, f"ACTIVE-SCAN {svc}")

                    self.last_query = now

                # (2b) Resolve unvollständige Instanzen
                if (
                    self.mode in ("scan", "scan_and_advertise")
                    and now - self.last_resolve >= self.resolve_interval
                ):
                    resolve_pending_instances(self, now)
                    self.last_resolve = now

                # 3) Pakete empfangen / verarbeiten
                try:
                    data, addr = self.sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(
                        "[mDNS-Worker:%s] Fehler beim Empfangen: %s", self.iface, e
                    )
                    continue

                src_ip, src_port = addr

                # Eigene Pakete ignorieren
                if self.local_ip and src_ip == self.local_ip:
                    continue

                # Neues Parsing über mdns_dns.parse_mdns_message
                is_response, questions, records = parse_mdns_message(data)

                # Debug-Logging der eingehenden Pakete
                if questions or records:
                    logger.debug(
                        "[mDNS:%s] RX %s src=%s:%d q=[%s] rr=[%s]",
                        self.iface,
                        "RESP" if is_response else "QUERY",
                        src_ip,
                        src_port,
                        format_questions_short(questions),
                        format_records_short(records),
                    )

                # Query → ggf. spoof beantworten
                if not is_response and questions and "advertise" in self.mode:
                    handle_query(self, questions, addr, records)

                # Response → Cache aktualisieren und Konflikte checken
                if is_response and records:
                    with CACHE_LOCK:
                        update_service_cache_from_records(
                            records,
                            src_ip=src_ip,
                            src_iface=self.iface,
                        )
                    check_conflict_from_response(self, records, src_ip)

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
