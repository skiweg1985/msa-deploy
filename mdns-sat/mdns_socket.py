# mdns_socket.py

import socket
import struct
import logging
from typing import Optional

import netifaces

from mdns_constants import MCAST_GRP, MDNS_PORT

logger = logging.getLogger("mdns-sat.socket")


def get_ipv4_for_iface(iface: str) -> Optional[str]:
    """
    Liefert die erste IPv4-Adresse eines Interfaces (oder None).
    """
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


def create_mdns_socket(iface: str, local_ip: Optional[str]) -> socket.socket:
    """
    Erstellt und konfiguriert einen mDNS-Socket für ein bestimmtes Interface.
    Bindet an Port 5353, joint die Multicast-Gruppe usw.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.5)

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError as e:
        logger.warning("SO_REUSEADDR konnte für %s nicht gesetzt werden: %s", iface, e)

    # mehrere Prozesse/Threads auf 5353
    try:
        SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
        sock.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    except OSError as e:
        logger.warning("SO_REUSEPORT konnte für %s nicht gesetzt werden: %s", iface, e)

    # an Interface binden
    try:
        SO_BINDTODEVICE = 25
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
        logger.info("mDNS-Socket via SO_BINDTODEVICE an Interface '%s' gebunden.", iface)
    except OSError as e:
        logger.error(
            "SO_BINDTODEVICE für Interface '%s' fehlgeschlagen: %s. "
            "mDNS-Worker läuft trotzdem weiter, aber Interface-Isolation fehlt.",
            iface,
            e,
        )

    # an mDNS-Port binden
    try:
        sock.bind(("", MDNS_PORT))
        logger.info("Socket an 0.0.0.0:%d für Interface '%s' gebunden.", MDNS_PORT, iface)
    except OSError as e:
        logger.error(
            "Konnte Socket für Interface %s nicht an Port %d binden: %s",
            iface,
            MDNS_PORT,
            e,
        )

    # Multicast IF + Membership
    if local_ip:
        try:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(local_ip),
            )
            logger.info(
                "IP_MULTICAST_IF für '%s' auf %s gesetzt.",
                iface,
                local_ip,
            )
        except OSError as e:
            logger.warning(
                "Konnte IP_MULTICAST_IF für '%s' nicht setzen: %s",
                iface,
                e,
            )

        try:
            mreq = struct.pack(
                "4s4s",
                socket.inet_aton(MCAST_GRP),
                socket.inet_aton(local_ip),
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            logger.info(
                "Multicast-Gruppe %s gejoint (iface=%s, ip=%s).",
                MCAST_GRP,
                iface,
                local_ip,
            )
        except OSError as e:
            logger.warning(
                "Konnte Multicast-Gruppe %s auf iface %s nicht joinen: %s",
                MCAST_GRP,
                iface,
                e,
            )

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    return sock