#!/usr/bin/env python3
"""
mdns_dns.py – Lowlevel-DNS/mDNS-Helfer

Kapselt:
- DNS-/mDNS-Namen (encode/decode)
- Header/Questions/Records parsen
- Queries bauen
- PTR/SRV/TXT/A-Records als Bytes bauen
"""

from __future__ import annotations

import socket
import struct
from typing import Any, Dict, List, Tuple


# ─────────────────────────────────────────────
# Typen
# ─────────────────────────────────────────────

MdnsQuestion = Dict[str, Any]
MdnsRecord = Dict[str, Any]


# ─────────────────────────────────────────────
# Namen & Encoding
# ─────────────────────────────────────────────

def ensure_fqdn(name: str) -> str:
    if not name:
        return ""
    return name if name.endswith(".") else name + "."


def strip_dot(name: str) -> str:
    return name[:-1] if name.endswith(".") else name


def encode_name(name: str) -> bytes:
    """
    Einfacher DNS-Name-Encoder ohne Kompression.
    """
    name = name.strip(".")
    if not name:
        return b"\x00"

    out = b""
    for label in name.split("."):
        b_label = label.encode("utf-8")
        if len(b_label) > 63:
            b_label = b_label[:63]
        out += bytes([len(b_label)]) + b_label
    out += b"\x00"
    return out


def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Dekodiert einen DNS-Namen (inkl. Pointer-Kompression).
    Gibt (name, new_offset) zurück.
    """
    labels: List[str] = []
    jumped = False
    original_offset = offset

    while True:
        if offset >= len(data):
            break

        length = data[offset]

        # Pointer?
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = ptr
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        if offset + length > len(data):
            break
        label = data[offset:offset + length].decode("utf-8", errors="ignore")
        labels.append(label)
        offset += length

    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


# ─────────────────────────────────────────────
# Header/Questions/Records-Parsen
# ─────────────────────────────────────────────

def parse_mdns_header_and_questions(data: bytes):
    """
    Parsed Header + Questions.
    Gibt zurück:
      (is_response, questions, offset, (ancount, nscount, arcount))
    """
    if len(data) < 12:
        return False, [], 0, (0, 0, 0)

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    is_response = bool(flags & 0x8000)
    offset = 12

    questions: List[MdnsQuestion] = []
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype, qclass_raw = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        unicast = bool(qclass_raw & 0x8000)
        qclass = qclass_raw & 0x7FFF
        questions.append({
            "name": name.rstrip("."),
            "qtype": qtype,
            "qclass": qclass,
            "unicast": unicast,
        })

    return is_response, questions, offset, (ancount, nscount, arcount)


def parse_mdns_records(data: bytes, offset: int, total_rr: int) -> List[MdnsRecord]:
    """
    Parsed Antwort-/Authority-/Additional-Records.
    Nur rudimentär (PTR, SRV, TXT, A, AAAA).
    """
    records: List[MdnsRecord] = []

    for _ in range(total_rr):
        if offset >= len(data):
            break

        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_offset = offset
        rdata = data[offset:offset + rdlen]
        offset += rdlen

        rec: MdnsRecord = {
            "name": strip_dot(name),
            "type": rtype,
            "ttl": ttl,
        }

        if rtype == 12:  # PTR
            ptr_name, _ = decode_name(data, rdata_offset)
            rec["ptr"] = strip_dot(ptr_name)

        elif rtype == 33 and rdlen >= 6:  # SRV
            prio, weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = decode_name(data, rdata_offset + 6)
            rec["srv"] = {
                "priority": prio,
                "weight": weight,
                "port": port,
                "target": strip_dot(target),
            }

        elif rtype == 16:  # TXT
            txts: List[str] = []
            i = 0
            while i < len(rdata):
                l = rdata[i]
                i += 1
                if l == 0 or i + l > len(rdata):
                    break
                txts.append(rdata[i:i + l].decode("utf-8", errors="ignore"))
                i += l
            rec["txt"] = txts

        elif rtype == 1 and rdlen == 4:  # A
            rec["a"] = socket.inet_ntoa(rdata)

        elif rtype == 28 and rdlen == 16:  # AAAA (simple Textdarstellung)
            parts = []
            for i in range(0, 16, 2):
                part = (rdata[i] << 8) | rdata[i + 1]
                parts.append(f"{part:x}")
            rec["aaaa"] = ":".join(parts)

        records.append(rec)

    return records


def parse_mdns_message(data: bytes):
    """
    Convenience-Wrapper: parsed ein komplettes mDNS-Paket.

    Rückgabe:
      is_response, questions, records
    """
    is_response, questions, offset, counts = parse_mdns_header_and_questions(data)
    ancount, nscount, arcount = counts
    total_rr = ancount + nscount + arcount
    records = parse_mdns_records(data, offset, total_rr)
    return is_response, questions, records


# ─────────────────────────────────────────────
# Query-Bau
# ─────────────────────────────────────────────

def build_mdns_query(name: str, qtype: int = 12) -> bytes:
    """
    Baut ein einfaches mDNS-Query-Paket:
    - ID = 0
    - Flags = 0 (Standard-Query)
    - 1 Question
    """
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)

    qname = b""
    for label in name.split("."):
        if not label:
            continue
        qname += bytes([len(label)]) + label.encode("ascii", errors="replace")
    qname += b"\x00"

    question = struct.pack("!HH", qtype, 1)
    return header + qname + question


# ─────────────────────────────────────────────
# Record-Bau (PTR/SRV/TXT/A)
# ─────────────────────────────────────────────

def mdns_class(shared: bool) -> int:
    """
    Liefert den mDNS-Class-Wert:
      - shared=True  -> 0x0001 (IN, Cache-Flush-Bit = 0)
      - shared=False -> 0x8001 (IN, Cache-Flush-Bit = 1 für unique records)
    """
    base = 1  # IN
    return base if shared else (0x8000 | base)


def build_ptr_record(service_type: str, instance_fqdn: str, ttl: int) -> bytes:
    name = encode_name(service_type)
    rdata = encode_name(instance_fqdn)
    return (
        name +
        struct.pack("!HHIH", 12, mdns_class(shared=True), ttl, len(rdata)) +
        rdata
    )


def build_srv_record(instance_fqdn: str, target_host: str, port: int, ttl: int) -> bytes:
    name = encode_name(instance_fqdn)
    rdata = struct.pack("!HHH", 0, 0, int(port)) + encode_name(target_host)
    return (
        name +
        struct.pack("!HHIH", 33, mdns_class(shared=False), ttl, len(rdata)) +
        rdata
    )


def build_txt_record(instance_fqdn: str, txt_list: List[str], ttl: int) -> bytes:
    name = encode_name(instance_fqdn)
    rdata = b""
    for entry in txt_list:
        if not entry:
            continue
        b_entry = entry.encode("utf-8")
        if len(b_entry) > 255:
            b_entry = b_entry[:255]
        rdata += bytes([len(b_entry)]) + b_entry
    return (
        name +
        struct.pack("!HHIH", 16, mdns_class(shared=False), ttl, len(rdata)) +
        rdata
    )


def build_a_record(hostname: str, ip: str, ttl: int) -> bytes:
    name = encode_name(hostname)
    try:
        addr = socket.inet_aton(ip)
    except OSError:
        return b""
    return (
        name +
        struct.pack("!HHIH", 1, mdns_class(shared=False), ttl, 4) +
        addr
    )