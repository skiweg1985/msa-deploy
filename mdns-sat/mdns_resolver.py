# mdns_resolver.py

import logging
from typing import Optional

from mdns_dns import build_mdns_query
from mdns_utils import CACHE_LOCK, SERVICE_CACHE, PENDING_RESOLVE
from mdns_constants import MCAST_GRP, MDNS_PORT

logger = logging.getLogger("mdns-sat.resolver")


# Begrenzungen für das aktive Resolving
MAX_TRIES =  20       # maximal so viele Resolve-Runden pro Instanz
MAX_AGE = 600.0       # maximal so viele Sekunden im Pending-Status (5 Minuten)


def _send_resolve_query(worker, qname: str, qtype: int, src_ip: Optional[str] = None):
    """
    Sendet eine Resolve-Query (SRV/TXT/A) für einen Namen.
    - Standard: Multicast
    - Optional: Unicast an src_ip, wenn worker.use_unicast_resolve=True und src_ip vorhanden ist.
    """
    pkt = build_mdns_query(qname, qtype=qtype)

    if worker.use_unicast_resolve and src_ip:
        dest = (src_ip, MDNS_PORT)
    else:
        dest = (MCAST_GRP, MDNS_PORT)

    try:
        logger.debug(
            "[%s] Resolve-Query qname=%s qtype=%d dest=%s",
            worker.iface,
            qname,
            qtype,
            dest,
        )
        worker.sock.sendto(pkt, dest)
    except Exception as e:
        worker._handle_socket_send_error(
            e,
            f"RESOLVE-QUERY {qname} type={qtype}",
        )


def _send_resolve_query_for_instance(worker, instance_name: str):
    """
    Fragt SRV+TXT für eine Instanz an.
    Optional Unicast gegen die zuletzt gesehene Quell-IP.
    """
    with CACHE_LOCK:
        inst = SERVICE_CACHE.get(instance_name)
        src_ips = list(inst.get("src_ips", [])) if inst else []

    src_ip = src_ips[0] if src_ips else None

    _send_resolve_query(worker, instance_name, qtype=33, src_ip=src_ip)  # SRV
    _send_resolve_query(worker, instance_name, qtype=16, src_ip=src_ip)  # TXT


def _send_resolve_query_for_hostname(worker, hostname: str):
    """
    Fragt A-Record für einen Hostnamen an (für die IP des Targets).
    Nimmt optional eine src_ip aus dem Cache.
    """
    with CACHE_LOCK:
        src_ip = None
        for inst in SERVICE_CACHE.values():
            if inst.get("hostname") == hostname:
                src_list = list(inst.get("src_ips", []))
                if src_list:
                    src_ip = src_list[0]
                    break

    _send_resolve_query(worker, hostname, qtype=1, src_ip=src_ip)



def resolve_pending_instances(worker, now: float):
    """
    Läuft alle PENDING_RESOLVE-Einträge durch und schickt gezielt SRV/TXT/A-Queries,
    um Einträge schneller vollständig zu bekommen.

    - pro Runde werden max_per_round Einträge behandelt
    - pro Instanz gibt es MAX_TRIES Versuche
    - zusätzlich wird jede Instanz nach MAX_AGE Sekunden quasi „deaktiviert“
      (give_up=True), bleibt aber im PENDING_RESOLVE, damit sie nicht neu
      angelegt wird.
    """
    max_per_round = 5  # um das Netz nicht zuzuspammen

    # Wir arbeiten mit Snapshots, um die Lock-Haltezeit kurz zu halten
    with CACHE_LOCK:
        pending_items = list(PENDING_RESOLVE.items())[:max_per_round]
        cache_snapshot = dict(SERVICE_CACHE)

    if not pending_items:
        return

    to_remove = []

    for inst_name, state in pending_items:
        if state is None:
            # defekter Eintrag, aufräumen
            to_remove.append(inst_name)
            continue

        # Bereits aufgegeben? → nichts mehr tun
        if state.get("give_up"):
            continue

        # first_seen initialisieren, falls nicht gesetzt
        first_seen = state.get("first_seen")
        if first_seen is None:
            first_seen = now
            with CACHE_LOCK:
                st = PENDING_RESOLVE.get(inst_name)
                if st is not None:
                    st.setdefault("first_seen", first_seen)
                    state = st  # Referenz aktualisieren

        try_count = state.get("try_count", 0)
        age = now - first_seen

        # Limit prüfen: MAX_TRIES oder MAX_AGE
        if try_count >= MAX_TRIES or age >= MAX_AGE:
            reason = "MAX_TRIES" if try_count >= MAX_TRIES else "MAX_AGE"
            logger.debug(
                "[%s] Deaktiviere weitere Resolves für %s: %s erreicht (try=%d, age=%.1fs).",
                worker.iface,
                inst_name,
                reason,
                try_count,
                age,
            )
            # NICHT entfernen, sondern markieren
            with CACHE_LOCK:
                st = PENDING_RESOLVE.get(inst_name)
                if st is not None:
                    st["give_up"] = True
                    st["give_up_reason"] = reason
                    st["give_up_at"] = now
            continue

        # Snapshot aus dem Cache holen
        inst = cache_snapshot.get(inst_name)
        if not inst:
            # Instanz existiert im Cache gar nicht mehr → aus Pending entfernen
            logger.debug(
                "[%s] Entferne pending-Instance %s: nicht mehr im SERVICE_CACHE.",
                worker.iface,
                inst_name,
            )
            to_remove.append(inst_name)
            continue

        hostname = inst.get("hostname")
        addresses = inst.get("addresses") or set() or []
        port = inst.get("port")

        # 1) Noch kein Host oder Port → SRV/TXT für Instanz
        if not hostname or not port:
            logger.debug(
                "[%s] Resolve-Instanz (SRV/TXT) für %s (try=%d, age=%.1fs)",
                worker.iface,
                inst_name,
                try_count,
                age,
            )
            _send_resolve_query_for_instance(worker, inst_name)

        # 2) Hostname vorhanden, aber noch keine IP → A-Query
        elif hostname and not addresses:
            logger.debug(
                "[%s] Resolve-Hostname (A) für %s (%s) (try=%d, age=%.1fs)",
                worker.iface,
                inst_name,
                hostname,
                try_count,
                age,
            )
            _send_resolve_query_for_hostname(worker, hostname)

        else:
            # Instanz ist eigentlich vollständig → aus Pending entfernen
            logger.debug(
                "[%s] Entferne pending-Instance %s: bereits vollständig (hostname=%s, port=%s, addrs=%s).",
                worker.iface,
                inst_name,
                hostname,
                port,
                addresses,
            )
            to_remove.append(inst_name)
            continue

        # Try-Zähler & last_tried im globalen State hochzählen
        with CACHE_LOCK:
            st = PENDING_RESOLVE.get(inst_name)
            if st is not None and not st.get("give_up"):
                st["last_tried"] = now
                st["try_count"] = st.get("try_count", 0) + 1
                # first_seen bleibt unverändert

    # Nur „normale“ Aufräumfälle löschen (vollständig oder aus dem Cache verschwunden)
    if to_remove:
        with CACHE_LOCK:
            for inst_name in to_remove:
                PENDING_RESOLVE.pop(inst_name, None)