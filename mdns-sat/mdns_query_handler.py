# mdns_query_handler.py

import logging
from typing import Any, Dict, List, Tuple

from mdns_constants import MCAST_GRP, MDNS_PORT
from mdns_utils import (
    SERVICE_BROWSER,
    split_service_and_subtype,
    derive_service_type_and_instance_fqdn,
)
from mdns_helpers import ensure_fqdn
from mdns_outbound import send_mdns_response

logger = logging.getLogger("mdns-sat.query")


def handle_query(worker, questions, addr, known_answers: List[Dict[str, Any]]):
    """
    Antworten auf mDNS-Queries:

    - PTR (_xyz._tcp.local, inkl. Subtypes wie _universal._sub._ipps._tcp.local)
    - A   (Hostname → IPv4-Adresse)

    Nutzt:
      - worker.current_services
      - worker.conflict_keys
      - worker.sock
      - worker.iface
      - worker._build_service_response_packet(...)
    """
    client_ip, client_port = addr

    if not worker.current_services:
        return

    # Known-Answers indexieren: (name, type) → True
    known_by_name_type: Dict[Tuple[str, int], bool] = {}
    for r in known_answers or []:
        name = r.get("name")
        rtype = r.get("type")
        if not name or rtype is None:
            continue
        known_by_name_type[(name, rtype)] = True

    answered: set[Tuple[str, str]] = set()

    for q in questions:
        qname = q["name"]
        qtype = q["qtype"]
        unicast = q["unicast"]

        # 1) PTR-Queries
        if qtype == 12:
            for sk, assignment in worker.current_services.items():
                if sk in worker.conflict_keys:
                    continue

                svc = assignment.get("service") or {}
                raw_service_name = (svc.get("service_name") or "").rstrip(".")
                if not raw_service_name:
                    continue

                base_service_name, subtype_name = split_service_and_subtype(raw_service_name)

                # Direktmatch (_ipp._tcp.local) oder Subtype-Owner
                is_direct_match = qname in (base_service_name, raw_service_name)
                is_subtype_of_service = (
                    qname.endswith("." + base_service_name)
                    or qname.endswith("." + raw_service_name)
                )

                if not (is_direct_match or is_subtype_of_service):
                    continue

                instance = svc.get("instance_name")
                if not instance:
                    continue

                svc_type_fqdn, instance_fqdn = derive_service_type_and_instance_fqdn(svc)
                svc_type_name_canon = svc_type_fqdn.rstrip(".")
                instance_name_canon = instance_fqdn.rstrip(".")

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
                    (qname, 12) in known_by_name_type if is_subtype_of_service else False
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
                include_subtype_ptr = is_subtype_of_service and not service_ptr_known_sub

                include_srv = not srv_known
                include_txt = bool(svc.get("txt") or []) and not txt_known
                include_a = bool(hostname_name_canon) and not a_known

                if not any(
                    [
                        include_browser_ptr,
                        include_service_ptr,
                        include_subtype_ptr,
                        include_srv,
                        include_txt,
                        include_a,
                    ]
                ):
                    answered.add(key)
                    continue

                pkt = worker._build_service_response_packet(
                    svc,
                    include_browser_ptr=include_browser_ptr,
                    include_service_ptr=include_service_ptr,
                    include_srv=include_srv,
                    include_txt=include_txt,
                    include_a=include_a,
                    include_subtype_ptr=include_subtype_ptr,
                    ttl_override=None,
                    subtype_owner_override=qname if is_subtype_of_service else None,
                )
                if not pkt:
                    continue

                dest = (client_ip, client_port) if unicast else (MCAST_GRP, MDNS_PORT)
                try:
                    send_mdns_response(worker, pkt, dest, unicast=unicast)
                    answered.add(key)
                except Exception as e:
                    worker._handle_socket_send_error(e, "QUERY-ANSWER-PTR")

        # 2) A-Queries
        elif qtype == 1:
            qname_norm = qname.rstrip(".").lower()

            for sk, assignment in worker.current_services.items():
                if sk in worker.conflict_keys:
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

                pkt = worker._build_service_response_packet(
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
                    send_mdns_response(worker, pkt, dest, unicast=unicast)
                    answered.add(key)
                except Exception as e:
                    worker._handle_socket_send_error(e, "QUERY-ANSWER-A")