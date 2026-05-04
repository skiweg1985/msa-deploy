# mdns_conflicts.py

import logging
from typing import Any, Dict, List

logger = logging.getLogger("mdns-sat.conflicts")


def check_conflict_from_response(worker, records: List[Dict[str, Any]], src_ip: str):
    """
    Prüft, ob eine eingehende mDNS-Response im Konflikt mit einem von uns
    gespooften Service steht (gleicher Instance-Name, andere Quelle).
    Markiert konfliktbehaftete Services im worker.conflict_keys.
    """
    if not worker.current_services:
        return

    if worker.local_ip and src_ip == worker.local_ip:
        return

    for sk, assignment in worker.current_services.items():
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
                    "Konflikt erkannt für Service-Key %s (Instance %s) auf iface %s, "
                    "Quelle %s – markiere als konflikt.",
                    sk,
                    inst,
                    worker.iface,
                    src_ip,
                )
                worker.conflict_keys.add(sk)
                break