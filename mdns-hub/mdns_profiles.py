from __future__ import annotations
from typing import Dict, Any, Optional

import requests
import xml.etree.ElementTree as ET

# ─────────────────────────────────────────────
# Global TXT mapping for generic device identity
# ─────────────────────────────────────────────
#
# Applies to all mDNS services. Only fields relevant for
# device-centric views are extracted:
#   - identity.friendly_name
#   - identity.mac
#   - identity.vendor
#   - identity.model
#

GLOBAL_TXT_MAP: Dict[str, Any] = {
    # Name / friendly name
    "ty": "identity.friendly_name",
    "bonjourname": "identity.friendly_name",
    "friendly_name": "identity.friendly_name",

    # Vendor / manufacturer
    "mfg": "identity.vendor",
    "manufacturer": "identity.vendor",
    "usb_MFG": "identity.vendor",

    # Model
    "mdl": "identity.model",
    "usb_MDL": "identity.model",
    "model": "identity.model",
    "board": "identity.model",

    # MAC / unique identifier
    "deviceid": "identity.mac",  # e.g. AirPlay/RAOP
    "mac": "identity.mac",
    "id": "identity.mac",        # generic identifier used by some services
}


# ─────────────────────────────────────────────
# Helpers: TXT parsing and nested assignment
# ─────────────────────────────────────────────

def parse_txt_to_dict(txt_list: list[str]) -> Dict[str, Any]:
    """
    Converts a TXT list such as ["key=value", "flag"] into a dictionary:
        {"key": "value", "flag": True}
    """
    result: Dict[str, Any] = {}
    for entry in txt_list or []:
        if "=" in entry:
            key, value = entry.split("=", 1)
            result[key] = value
        else:
            result[entry] = True
    return result


def set_nested(target: Dict[str, Any], path: str, value: Any) -> None:
    """
    Writes a value into a nested dictionary under a dotted path.

    Example:
        set_nested(d, "identity.vendor", "Sonos")
        → d["identity"]["vendor"] = "Sonos"
    """
    parts = path.split(".")
    current = target

    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]

    current[parts[-1]] = value


def _parse_bool_like(value: Any) -> Any:
    """
    Attempts to interpret a string value as a boolean.

    Returns the original value if no boolean interpretation is possible.
    """
    if isinstance(value, str):
        lowered = value.lower()
        if lowered in ("t", "true", "yes", "y", "on", "1"):
            return True
        if lowered in ("f", "false", "no", "n", "off", "0"):
            return False
    return value


def _parse_int_like(value: Any) -> Any:
    """
    Attempts to interpret a string value as an integer.

    Returns the original value if conversion fails or is not applicable.
    """
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _maybe_parse_csv(value: Any) -> Any:
    """
    Splits a comma-separated string into a list of stripped items.

    Returns the original value if no comma is present or the value is not a string.
    """
    if isinstance(value, str) and "," in value:
        return [v.strip() for v in value.split(",") if v.strip()]
    return value


# ─────────────────────────────────────────────
# Generic TXT normalization
# ─────────────────────────────────────────────

def normalize_txt(service_name: str, txt_list: list[str]) -> Dict[str, Any]:
    """
    Normalizes TXT records into a nested structure based on GLOBAL_TXT_MAP.

    Parameters
    ----------
    service_name : str
        Unused at the moment; kept for compatibility and potential
        service-specific logic in the future.
    txt_list : list[str]
        List of TXT entries as "key=value" or flags without '='.

    Returns
    -------
    Dict[str, Any]
        Nested structure with normalized identity and related fields.
    """
    mapping: Dict[str, Any] = dict(GLOBAL_TXT_MAP)

    txt_kv = parse_txt_to_dict(txt_list)
    result: Dict[str, Any] = {}

    for key, raw_value in txt_kv.items():
        if key not in mapping:
            continue

        path = mapping[key]

        value: Any = raw_value
        value = _parse_bool_like(value)
        value = _parse_int_like(value)

        # Optional CSV handling for specific keys can be enabled here:
        # if key in ("pdl", "rs", "cs", "is"):
        #     value = _maybe_parse_csv(value)

        set_nested(result, path, value)

    return result


# ─────────────────────────────────────────────
# Spotify Zeroconf enrichment (CPath-based trigger)
# ─────────────────────────────────────────────

SPOTIFY_ZEROCONF_INFO_FIELDS: Dict[str, Any] = {
    "remoteName": [
        "spotify.device.remote_name",
        "identity.friendly_name",
    ],
    "deviceID": [
        "spotify.device.device_id",
    ],
    "brandDisplayName": [
        "identity.vendor_display",
        "identity.vendor",
    ],
    "modelDisplayName": [
        "identity.model_display",
        "identity.model",
    ],
    "deviceType": "spotify.device.device_type",
    "productID": "spotify.device.product_id",
    "version": "spotify.zeroconf.version",
    "libraryVersion": "spotify.zeroconf.library_version",
    "resolverVersion": "spotify.zeroconf.resolver_version",
    "groupStatus": "spotify.group.status",
    "tokenType": "spotify.auth.token_type",
    "clientID": "spotify.auth.client_id",
    "supported_capabilities": "spotify.capabilities.mask",
    "supported_drm_media_formats": "spotify.capabilities.drm_formats",
}


def has_spotify_zeroconf_cpath(txt_list: list[str]) -> bool:
    """
    Detects Spotify Zeroconf services by the presence of a TXT entry
    such as 'CPath=/spotifyzc'.
    """
    kv = parse_txt_to_dict(txt_list)
    cpath = kv.get("CPath")
    if not isinstance(cpath, str):
        return False
    return cpath == "/spotifyzc"


def enrich_spotify_zeroconf(
    service: Dict[str, Any],
    target: Dict[str, Any],
    timeout: float = 2.0,
) -> bool:
    """
    Enriches a target dictionary with Spotify Zeroconf metadata.

    Parameters
    ----------
    service : Dict[str, Any]
        Service descriptor containing at least:
        - "addresses": list[str]
        - "port": Optional[int]
        - "txt": list[str]
    target : Dict[str, Any]
        Target dictionary to be enriched (typically a "normalized" block).
    timeout : float
        HTTP request timeout in seconds.

    Returns
    -------
    bool
        True if enrichment succeeded, False otherwise.

    Notes
    -----
    Trigger conditions:
        - TXT contains a CPath entry (e.g. CPath=/spotifyzc).
    Port selection:
        - service["port"] is used if present, otherwise 57621.
    """
    txt_list = service.get("txt", [])
    txt_kv = parse_txt_to_dict(txt_list)

    cpath = txt_kv.get("CPath")
    if not isinstance(cpath, str) or not cpath:
        return False

    addresses = service.get("addresses") or []
    if not addresses:
        return False

    ip = addresses[0]
    # Note: "or 80" is redundant here because 57621 is non-zero and always truthy.
    # It is kept for compatibility with the original implementation.
    port = service.get("port") or 57621 or 80

    if not cpath.startswith("/"):
        cpath = "/" + cpath

    url = f"http://{ip}:{port}{cpath}"

    params: Dict[str, Any] = {"action": "getInfo"}
    method = "GET"

    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params, timeout=timeout)
        else:
            response = requests.request(
                method.upper(), url, params=params, timeout=timeout
            )
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError:
            return False
    except Exception:
        return False

    # Map selected fields from the Zeroconf JSON into the target structure
    for key, dest_path in SPOTIFY_ZEROCONF_INFO_FIELDS.items():
        if key not in data:
            continue
        value = data[key]

        if isinstance(dest_path, (list, tuple)):
            for single_path in dest_path:
                set_nested(target, single_path, value)
        else:
            set_nested(target, dest_path, value)

    # Optional status-related fields
    if "status" in data:
        set_nested(target, "spotify.zeroconf.status_code", data["status"])
    if "statusString" in data:
        set_nested(target, "spotify.zeroconf.status_string", data["statusString"])
    if "spotifyError" in data:
        set_nested(target, "spotify.zeroconf.error_code", data["spotifyError"])

    return True


# ─────────────────────────────────────────────
# Sonos UPnP device_description.xml enrichment
# ─────────────────────────────────────────────

def has_sonos_device_description(txt_list: list[str]) -> bool:
    """
    Detects a Sonos device description endpoint via a TXT entry
    such as 'location=http://.../device_description.xml'.
    """
    kv = parse_txt_to_dict(txt_list)
    location = kv.get("location")
    if not isinstance(location, str):
        return False
    return "device_description.xml" in location


def _et_get_first_text(root: ET.Element, tag_local: str) -> Optional[str]:
    """
    Returns the text content of the first element whose local name matches
    `tag_local`, ignoring XML namespaces.
    """
    for elem in root.iter():
        if elem.tag.endswith(tag_local):
            text = (elem.text or "").strip()
            if text:
                return text
    return None


def enrich_sonos_device_description(
    service: Dict[str, Any],
    target: Dict[str, Any],
    timeout: float = 2.0,
) -> bool:
    """
    Enriches a target dictionary with Sonos UPnP metadata obtained from
    device_description.xml.

    Parameters
    ----------
    service : Dict[str, Any]
        Service descriptor containing at least:
        - "addresses": list[str]
        - "txt": list[str]
    target : Dict[str, Any]
        Target dictionary to be enriched (typically a "normalized" block).
    timeout : float
        HTTP request timeout in seconds.

    Returns
    -------
    bool
        True if enrichment succeeded, False otherwise.

    Notes
    -----
    Trigger conditions:
        - TXT contains 'location=' that points to 'device_description.xml', or
        - the URL is constructed from the first service address and the
          Sonos default port 1400.
    """
    txt_list = service.get("txt", [])
    kv = parse_txt_to_dict(txt_list)

    location = kv.get("location")
    addresses = service.get("addresses") or []
    if not location and not addresses:
        return False

    # Determine device description URL
    if isinstance(location, str) and "device_description.xml" in location:
        url = location
    else:
        ip = addresses[0]
        url = f"http://{ip}:1400/xml/device_description.xml"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.content
    except Exception:
        return False

    try:
        root = ET.fromstring(data)
    except Exception:
        return False

    # Extract relevant fields
    room_name = _et_get_first_text(root, "roomName")
    friendly_name = _et_get_first_text(root, "friendlyName")
    manufacturer = _et_get_first_text(root, "manufacturer")
    model_name = _et_get_first_text(root, "modelName")
    model_desc = _et_get_first_text(root, "modelDescription")
    model_number = _et_get_first_text(root, "modelNumber")
    mac = _et_get_first_text(root, "MACAddress")
    serial = _et_get_first_text(root, "serialNum")

    # Identity name: prefer roomName, then friendlyName
    name = room_name or friendly_name
    if name:
        set_nested(target, "identity.friendly_name", name)

    # Vendor
    if manufacturer:
        set_nested(target, "identity.vendor", manufacturer)

    # Model: select best available description
    model = model_name or model_desc or model_number
    if model:
        set_nested(target, "identity.model", model)

    # MAC / identifier
    mac_value = mac or serial
    if mac_value:
        set_nested(target, "identity.mac", mac_value)

    # Additional Sonos-specific metadata
    sw_version = _et_get_first_text(root, "softwareVersion")
    api_version = _et_get_first_text(root, "apiVersion")
    hw_version = _et_get_first_text(root, "hardwareVersion")
    display_name = _et_get_first_text(root, "displayName")
    series_id = _et_get_first_text(root, "seriesid")

    if sw_version:
        set_nested(target, "vendor.sonos.software_version", sw_version)
    if api_version:
        set_nested(target, "vendor.sonos.api_version", api_version)
    if hw_version:
        set_nested(target, "vendor.sonos.hardware_version", hw_version)
    if display_name:
        set_nested(target, "vendor.sonos.display_name", display_name)
    if series_id:
        set_nested(target, "vendor.sonos.series_id", series_id)

    return True