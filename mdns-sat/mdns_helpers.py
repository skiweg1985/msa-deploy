# mdns_helpers.py

from typing import Any, Dict, List
from mdns_dns import MdnsQuestion, MdnsRecord


def ensure_fqdn(name: str) -> str:
    """
    Stellt sicher, dass ein DNS-Name mit einem Punkt endet.
    """
    if not name:
        return ""
    if not name.endswith("."):
        return name + "."
    return name


def service_signature(assignment: Dict[str, Any]) -> str:
    """
    Erzeugt eine Signatur für einen Service-Assignment-Eintrag, um Änderungen
    zu erkennen (Instance, Service, Hostname, Port, Adressen, TXT-List).
    """
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


# ─────────────────────────────────────────────
# Logging-Helper / Pretty-Print
# ─────────────────────────────────────────────

_QTYPE_NAMES = {
    1: "A",
    12: "PTR",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


def format_questions_short(questions: List[MdnsQuestion], max_items: int = 5) -> str:
    """
    Liefert eine kompakte String-Darstellung der Questions-Liste
    aus parse_mdns_header_and_questions().
    """
    out = []
    for q in (questions or [])[:max_items]:
        name = q.get("name", "?")
        qtype = q.get("qtype")
        qtype_name = _QTYPE_NAMES.get(qtype, str(qtype) if qtype is not None else "?")
        unicast = "U" if q.get("unicast") else "M"
        out.append(f"{name} ({qtype_name}, {unicast})")
    if questions and len(questions) > max_items:
        out.append(f"+{len(questions) - max_items} weitere")
    return ", ".join(out)


def format_records_short(records: List[MdnsRecord], max_items: int = 5) -> str:
    """
    Liefert eine kompakte String-Darstellung der Records-Liste
    aus parse_mdns_records().
    Nutzt die bekannten Keys: ptr, srv, txt, a, aaaa.
    """
    out = []

    for r in (records or [])[:max_items]:
        name = r.get("name", "?")
        rtype = r.get("type")
        ttl = r.get("ttl")
        rtype_name = _QTYPE_NAMES.get(rtype, str(rtype) if rtype is not None else "?")

        desc = None

        if rtype == 12:  # PTR
            desc = f"{name} PTR→ {r.get('ptr', '?')}"

        elif rtype == 33:  # SRV
            srv = r.get("srv") or {}
            desc = (
                f"{name} SRV→ {srv.get('target', '?')}:{srv.get('port', '?')}"
            )

        elif rtype == 16:  # TXT
            txts = r.get("txt") or []
            # optional: ein Beispiel anzeigen
            preview = txts[0] if txts else ""
            if preview and len(preview) > 40:
                preview = preview[:37] + "..."
            if preview:
                desc = f"{name} TXT[{len(txts)}] z.B. \"{preview}\""
            else:
                desc = f"{name} TXT[{len(txts)}]"

        elif rtype == 1:  # A
            desc = f"{name} A→ {r.get('a', '?')}"

        elif rtype == 28:  # AAAA
            desc = f"{name} AAAA→ {r.get('aaaa', '?')}"

        if not desc:
            # Generischer Fallback
            if ttl is not None:
                desc = f"{name} {rtype_name} (ttl={ttl})"
            else:
                desc = f"{name} {rtype_name}"

        out.append(desc)

    if records and len(records) > max_items:
        out.append(f"+{len(records) - max_items} weitere")

    return ", ".join(out)