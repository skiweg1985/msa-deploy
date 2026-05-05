# mdns_outbound.py

import socket
import logging
from typing import Tuple

from sat_admin import ADMIN_STATS

logger = logging.getLogger("mdns-sat.outbound")

# Globales Unicast-Socket (wird Lazy erstellt)
_GLOBAL_UNICAST_SOCK: socket.socket | None = None


def get_unicast_socket() -> socket.socket:
    """
    Liefert ein globales UDP-Socket für Unicast-mDNS-Antworten.
    Kein SO_BINDTODEVICE, keine Multicast-Membership – normales
    UDP-Socket, das die System-Routing-Tabelle nutzt (Default-Route).
    """
    global _GLOBAL_UNICAST_SOCK

    if _GLOBAL_UNICAST_SOCK is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # Optional: etwas nettes Tuning / Logging
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        logger.info("Globales Unicast-UDP-Socket für mDNS initialisiert.")
        _GLOBAL_UNICAST_SOCK = s

    return _GLOBAL_UNICAST_SOCK


def _is_link_local(ip: str | None) -> bool:
    """
    Grobe Erkennung von Link-Local / Dummy-IP (169.254.x.x).
    Kann man später erweitern, wenn man mehr "Dummy-Muster" hat.
    """
    if not ip:
        return False
    return ip.startswith("169.254.")


def send_mdns_response(worker, pkt: bytes, dest: Tuple[str, int], unicast: bool) -> None:
    """
    Versendet eine mDNS-Antwort (pkt) an dest (ip, port).

    - Multicast: immer über worker.sock
    - Unicast: je nach worker.unicast_reply_mode:
        - "auto"         → Interface-Socket, außer wenn nur Link-Local/Dummy-IP → global
        - "force_default"→ immer globales Socket
        - "iface_only"   → immer Interface-Socket (altes Verhalten)
    """
    if not pkt:
        return

    ip, port = dest

    # Multicast-Fall: immer über das Interface-Socket
    if not unicast:
        try:
            worker.sock.sendto(pkt, dest)
            ADMIN_STATS.increment("responses_sent_total")
            logger.debug(
                "[MCAST-REPLY] iface=%s → %s:%d (len=%d)",
                worker.iface,
                ip,
                port,
                len(pkt),
            )
        except Exception as e:
            worker._handle_socket_send_error(e, "MDNS-MCAST-REPLY")
        return

    # Unicast-Fall
    mode = getattr(worker, "unicast_reply_mode", "auto").lower()
    local_ip = getattr(worker, "local_ip", None)

    use_global = False
    if mode == "force_default":
        use_global = True
    elif mode == "iface_only":
        use_global = False
    else:
        # auto
        if not local_ip or _is_link_local(local_ip):
            # Interface hat keine brauchbare IPv4 → globales Socket
            use_global = True
        else:
            use_global = False

    if use_global:
        s = get_unicast_socket()
        try:
            logger.debug(
                "[UNICAST-REPLY] iface=%s mode=%s → globales Socket → %s:%d (len=%d)",
                worker.iface,
                mode,
                ip,
                port,
                len(pkt),
            )
            s.sendto(pkt, dest)
            ADMIN_STATS.increment("responses_sent_total")
        except Exception as e:
            logger.error(
                "[UNICAST-REPLY] Fehler beim Senden über globales Unicast-Socket "
                "(iface=%s dest=%s:%d): %s",
                worker.iface,
                ip,
                port,
                e,
            )
    else:
        try:
            logger.debug(
                "[UNICAST-REPLY] iface=%s mode=%s → Interface-Socket → %s:%d (len=%d)",
                worker.iface,
                mode,
                ip,
                port,
                len(pkt),
            )
            worker.sock.sendto(pkt, dest)
            ADMIN_STATS.increment("responses_sent_total")
        except Exception as e:
            worker._handle_socket_send_error(e, "MDNS-UNICAST-REPLY")
