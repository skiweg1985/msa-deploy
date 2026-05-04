# models.py
from typing import List, Optional, Dict, Any, Union
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


def normalize_service_type_list(values: Any) -> List[str]:
    """
    Normalize service-type lists for persisted hub UI settings.

    Rules:
    - Accept missing/None as empty list
    - Accept strings and lists
    - Trim whitespace
    - Drop empty entries
    - Deduplicate while preserving order
    """
    if values is None:
        return []

    if isinstance(values, str):
        values = [values]

    if not isinstance(values, list):
        raise TypeError(f"Unsupported service type list value: {type(values)}")

    normalized: List[str] = []
    seen = set()

    for raw in values:
        if raw is None:
            continue
        value = str(raw).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)

    return normalized


class SatRegisterRequest(BaseModel):
    satellite_id: str = Field(..., description="Eindeutige ID des Sat")
    hostname: Optional[str] = None
    auth_token: str
    mgmt_interface: Optional[str] = None
    mgmt_ip_address: Optional[str] = None
    mgmt_ip_mode: Optional[str] = None
    software_version: Optional[str] = None


class SatInterface(BaseModel):
    """
    Ein *beliebiges* Interface des Sats: Mgmt, VLAN, Bond, usw.
    """
    name: str                       # z.B. "eth0", "eth0.30"
    parent_interface: Optional[str] = None
    vlan_id: Optional[int] = None   # optional, nur Doku/Zweck
    description: Optional[str] = None

    # IP-Handling durch den Sat (optional, kann auch komplett ignoriert bleiben)
    ip_mode: str = Field(
        "none",
        description="none | dhcp | static",
    )
    ip_address: Optional[str] = Field(
        default=None,
        description="z.B. 10.0.0.10/24, nur bei ip_mode=static",
    )

    # mDNS-Rolle auf diesem Interface:
    # - none             → nix tun
    # - sniff_only       → nur passiv mitlesen (keine Queries senden)
    # - scan             → aktiv Queries senden + Antworten verarbeiten
    # - advertise        → nur announcen (Spoofing), kein Scan
    # - scan_and_advertise → beides
    mode: str = Field(
        "none",
        description="none | sniff_only | scan | advertise | scan_and_advertise",
    )


class SatConfig(BaseModel):
    """
    Einheitliche Config des Sats aus Sicht des Hubs.
    Mgmt-IF ist kein Sonderfall mehr, sondern einfach eins der Interfaces.
    """
    satellite_id: str
    interfaces: List[SatInterface] = Field(default_factory=list)


class SatRegisterResponse(BaseModel):
    satellite_id: str
    assigned_config: SatConfig


class MdnsRecord(BaseModel):
    name: str
    type: int
    ttl: int
    # falls du später PTR/SRV/TXT-Strukturen direkter abbilden willst,
    # kannst du hier von str→Any gehen:
    data: Dict[str, Any] = Field(default_factory=dict)


class ServiceInstance(BaseModel):
    service_name: str
    instance_name: str
    hostname: Optional[str] = None
    addresses: List[str] = Field(default_factory=list)

    port: Optional[int] = None
    txt: List[str] = Field(default_factory=list)
    src_ips: List[str] = Field(default_factory=list)

    # NEU: MAC-Infos vom Sat
    mac: Optional[str] = Field(
        default=None,
        description="Primäre MAC-Adresse des Dienstes (z.B. aus ARP-Table abgeleitet)",
    )
    src_macs: List[str] = Field(
        default_factory=list,
        description="Alle beobachteten MAC-Adressen, falls der Dienst über mehrere Interfaces/Wege gesehen wurde",
    )

    # NEU: Interfaces, auf denen die Instanz gesehen wurde
    src_ifaces: List[str] = Field(
        default_factory=list,
        description="Liste der Interfaces auf dem Sat, auf denen dieser Service gesehen wurde",
    )

    # NEU: „letztes“ Interface (für UI-Hervorhebung, Badge etc.)
    source_iface: Optional[str] = Field(
        default=None,
        description="Interface, über das der Service zuletzt gesehen wurde",
    )

    vlan_id: Optional[int] = None
    location: Optional[str] = None
    last_seen: Optional[datetime] = None
    raw_records: List[MdnsRecord] = Field(default_factory=list)

class ServiceIngestRequest(BaseModel):
    satellite_id: str
    services: List[ServiceInstance]


class HubServiceFilterSettings(BaseModel):
    include_service_types: List[str] = Field(default_factory=list)

    @field_validator("include_service_types", mode="before")
    @classmethod
    def normalize_include_service_types(cls, value: Any) -> List[str]:
        return normalize_service_type_list(value)


class HubUiSettings(BaseModel):
    service_filters: HubServiceFilterSettings = Field(default_factory=HubServiceFilterSettings)


class ServiceTypeOption(BaseModel):
    name: str
    source: str


class ServiceFilterConfigResponse(BaseModel):
    include_service_types: List[str] = Field(default_factory=list)
    static_default_service_types: List[str] = Field(default_factory=list)
    observed_service_types: List[str] = Field(default_factory=list)
    available_service_types: List[ServiceTypeOption] = Field(default_factory=list)


class ServiceFilterConfigUpdate(BaseModel):
    include_service_types: List[str] = Field(default_factory=list)

    @field_validator("include_service_types", mode="before")
    @classmethod
    def normalize_include_service_types(cls, value: Any) -> List[str]:
        return normalize_service_type_list(value)



class ServiceWithMeta(BaseModel):
    service: ServiceInstance
    service_key: str
    meta: Dict[str, Any] = {}
    source_sat: Optional[str] = None  
    

class SpoofTarget(BaseModel):
    sat_id: str
    use_mgmt: bool = False
    vlans: List[int] = []
    # iface kann jetzt Liste sein, wir normalisieren alles auf List[str]
    iface: Optional[List[str]] = None

    @field_validator("iface", mode="before")
    @classmethod
    def normalize_iface(cls, v):
        """
        Erlaubt:
          - None
          - "ens160"
          - "ens160,ens160.222"
          - ["ens160", "ens160.222"]

        Intern wird immer eine Liste von Strings draus gemacht.
        """
        if v is None:
            return None

        # schon Liste -> aufräumen
        if isinstance(v, list):
            cleaned = [str(x).strip() for x in v if str(x).strip()]
            return cleaned or None

        # String (ein Interface oder CSV)
        if isinstance(v, str):
            parts = [p.strip() for p in v.split(",") if p.strip()]
            return parts or None

        # Irgendwas anderes → TypeError, dann siehst du es im Log
        raise TypeError(f"Unsupported type for iface: {type(v)}")


class SpoofConfig(BaseModel):
    service_key: str
    enabled: bool = True
    note: Optional[str] = None
    targets: List[SpoofTarget] = Field(default_factory=list)

class SpoofAssignment(BaseModel):
    service_key: str
    service: ServiceInstance
    spoof_target: SpoofTarget
    

class SatMeta(BaseModel):
    hostname: Optional[str] = None
    software_version: Optional[str] = None

    mgmt_interface: Optional[str] = None
    mgmt_ip_address: Optional[str] = None
    mgmt_ip_mode: Optional[str] = None

    client_ip: Optional[str] = None

    # nur registrierungszeitpunkt persistent
    last_register: Optional[datetime] = None
    
    
class ServiceRegistryEntry(BaseModel):
    """
    Zentrale Sicht auf einen Dienst (pro service_key):

    - Discovery/Status
    - Enrichment-Meta
    - Spoof-Konfiguration
    """
    service_key: str

    # Status / letzte Beobachtung
    last_instance: Optional["ServiceInstance"] = None
    last_seen: Optional[datetime] = None
    last_sat_id: Optional[str] = None
    online: bool = False

    # Meta (normalized, spotify, sonos, …)
    meta: Dict[str, Any] = Field(default_factory=dict)

    # Spoofing
    spoof_enabled: bool = False
    spoof_note: str = ""
    spoof_targets: List["SpoofTarget"] = Field(default_factory=list)
