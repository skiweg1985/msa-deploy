import os
import json
import uvicorn
import asyncio
import logging

from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Header,
    Response,
    Request,
    Form,
    WebSocket,
    WebSocketDisconnect,
    Body,
    Query,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.encoders import jsonable_encoder
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from models import (
    SatRegisterRequest,
    SatRegisterResponse,
    SatConfig,
    SatInterface,
    ServiceIngestRequest,
    ServiceInstance,
    SpoofConfig,
    SpoofTarget,
    SpoofAssignment,
    ServiceWithMeta,
    SatMeta,
    ServiceRegistryEntry,
    HubUiSettings,
    HubServiceFilterSettings,
    ServiceTypeOption,
    ServiceFilterConfigResponse,
    ServiceFilterConfigUpdate,
)

from mdns_profiles import (
    normalize_txt,
    enrich_spotify_zeroconf,
    has_spotify_zeroconf_cpath,
    has_sonos_device_description,
    enrich_sonos_device_description,
)

from logging_config import LOGGING_CONFIG, get_logger
logging.config.dictConfig(LOGGING_CONFIG)

from auth import AuthManager, AuthSettings, SessionRecord
from hub_config import (
    get_security_bool,
    get_security_int,
    get_security_list,
    get_security_value,
    get_ui_value,
)


logger = get_logger(f"mdns_hub.main")


# ─────────────────────────────────────────────
# Startup / Shutdown - Lifespan
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    asyncio.create_task(enrichment_worker())
    asyncio.create_task(service_registry_ttl_worker())
    logger.info("Background tasks started")
    yield
    # Shutdown (optional)


# ─────────────────────────────────────────────
# FastAPI / App base
# ─────────────────────────────────────────────

app = FastAPI(
    title="mDNS Hub",
    description="Zentrale Verwaltung für mDNS-/AirGroup-ähnliche Sats",
    version="0.1.0",
    lifespan=lifespan,
)

templates = Jinja2Templates(directory="templates")

UI_AUTH_ENABLED = get_security_bool("ui_auth_enabled", True)
ALLOWED_ORIGINS = get_security_list("allowed_origins", [])
ALLOW_ALL_ORIGINS_FOR_DEV = get_security_bool("allow_all_origins_for_dev", False)

AUTH_MANAGER = AuthManager(
    AuthSettings(
        enabled=UI_AUTH_ENABLED,
        admin_username=str(get_security_value("admin_username", "") or ""),
        admin_password=(str(get_security_value("admin_password", "") or "") or None),
        admin_password_hash=(str(get_security_value("admin_password_hash", "") or "") or None),
        session_secret=(str(get_security_value("session_secret", "") or "") or os.urandom(32).hex()),
        session_ttl_seconds=get_security_int("session_ttl_seconds", 28800),
        cookie_secure=get_security_bool("session_cookie_secure", False),
        allowed_origins=ALLOWED_ORIGINS,
        allow_all_origins_for_dev=ALLOW_ALL_ORIGINS_FOR_DEV,
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if UI_AUTH_ENABLED else ["*"],
    allow_origin_regex=".*" if (UI_AUTH_ENABLED and ALLOW_ALL_ORIGINS_FOR_DEV) else None,
    allow_credentials=UI_AUTH_ENABLED,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent


app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)

FRONTEND_DIR = BASE_DIR / "frontend"

EXAMPLE_FILES = {
    "example_services.json",
    "example_sat.json",
    "example_groups.json",
}


app.mount(
    "/assets",
    StaticFiles(directory=FRONTEND_DIR / "assets"),
    name="assets",
)


INDEX_FILE = FRONTEND_DIR / "index.html"

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

SATELLITES_FILE = DATA_DIR / "satellites.json"
SAT_CONFIGS_FILE = DATA_DIR / "sat_configs.json"
SAT_GROUPS_FILE = DATA_DIR / "sat_groups.json"
SERVICE_REGISTRY_FILE = DATA_DIR / "service_registry.json"
HUB_UI_SETTINGS_FILE = DATA_DIR / "hub_ui_settings.json"

# ─────────────────────────────────────────────
# In-memory "database"
# ─────────────────────────────────────────────

SATELLITES: Dict[str, SatMeta] = {}
SATELLITE_CONFIGS: Dict[str, SatConfig] = {}

INGESTED_SERVICES_BY_SAT: Dict[str, Dict[str, ServiceInstance]] = {}

# Historical / future meta map, currently not heavily used
SERVICE_ENRICHED_DATA: Dict[str, Dict[str, Any]] = {}

SPOTIFY_ENRICH_STATE: Dict[str, Dict[str, Any]] = {}
SONOS_ENRICH_STATE: Dict[str, Dict[str, Any]] = {}

SPOTIFY_ENRICH_BASE_INTERVAL = timedelta(minutes=10)
SPOTIFY_ENRICH_BACKOFF_BASE = timedelta(seconds=30)
SPOTIFY_ENRICH_BACKOFF_MAX = timedelta(minutes=30)

SONOS_ENRICH_BASE_INTERVAL = timedelta(minutes=30)
SONOS_ENRICH_BACKOFF_BASE = timedelta(seconds=60)
SONOS_ENRICH_BACKOFF_MAX = timedelta(minutes=60)

SAT_GROUPS: Dict[str, Dict] = {}



SHARED_SECRET = get_security_value("shared_secret", "changeme")

if UI_AUTH_ENABLED and not ALLOWED_ORIGINS and not ALLOW_ALL_ORIGINS_FOR_DEV:
    logger.warning(
        "UI auth is enabled without configured security.allowed_origins; only same-origin browser access will work"
    )

if UI_AUTH_ENABLED and ALLOW_ALL_ORIGINS_FOR_DEV:
    logger.warning(
        "security.allow_all_origins_for_dev=true enables permissive cross-origin auth for testing only"
    )

# Active WS connections: sat_id -> WebSocket
ACTIVE_SAT_WEBSOCKETS: Dict[str, WebSocket] = {}
ACTIVE_WS_LOCK = asyncio.Lock()

# Active UI WebSocket connections (hub frontend)
ACTIVE_UI_WEBSOCKETS: List[WebSocket] = []
UI_WS_LOCK = asyncio.Lock()

# Optional in-memory state for WS-based info per Sat
SAT_WS_STATE: Dict[str, Dict] = {}

# Main service registry
SERVICE_REGISTRY: Dict[str, ServiceRegistryEntry] = {}
HUB_UI_SETTINGS = HubUiSettings()


def client_ip_from_request(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return "unknown"


def build_auth_session_payload(session: Optional[SessionRecord]) -> Dict[str, Any]:
    return {
        "authRequired": UI_AUTH_ENABLED,
        "authenticated": bool(session),
        "username": session.username if session else None,
        "csrfToken": session.csrf_token if session else None,
        "expiresAt": session.expires_at.isoformat() if session else None,
    }


def get_optional_ui_session(request: Request) -> Optional[SessionRecord]:
    if not UI_AUTH_ENABLED:
        return None
    return AUTH_MANAGER.get_session_from_request(request)


def require_ui_session(request: Request) -> SessionRecord:
    return AUTH_MANAGER.require_session(request)


async def require_ui_mutation_session(request: Request) -> SessionRecord:
    session = AUTH_MANAGER.require_session(request)
    await AUTH_MANAGER.require_csrf(request, session)
    return session


def require_satellite_or_ui_access(
    request: Request,
    x_satellite_token: Optional[str] = Header(default=None, alias="X-Satellite-Token"),
) -> bool:
    if x_satellite_token == SHARED_SECRET:
        return True
    if UI_AUTH_ENABLED and AUTH_MANAGER.get_session_from_request(request):
        return True
    raise HTTPException(status_code=401, detail="Unauthorized")


def _has_valid_satellite_token(request: Request) -> bool:
    return (request.headers.get("X-Satellite-Token") or "") == SHARED_SECRET


# Deny-by-default policy for backend API access:
# - /api/v1/auth/* stays publicly reachable so login bootstrap works.
# - Satellite clients may access /api/v1/* with X-Satellite-Token.
# - All other /api/v1/* calls require a valid UI session cookie.
@app.middleware("http")
async def api_access_guard(request: Request, call_next):
    path = request.url.path
    method = request.method.upper()

    if method == "OPTIONS":
        return await call_next(request)

    if path.startswith("/api/v1"):
        if path.startswith("/api/v1/auth/"):
            return await call_next(request)

        if _has_valid_satellite_token(request):
            return await call_next(request)

        if not UI_AUTH_ENABLED:
            return JSONResponse(status_code=503, content={"detail": "UI authentication must be enabled"})

        session = AUTH_MANAGER.get_session_from_request(request)
        if not session:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    return await call_next(request)

# ─────────────────────────────────────────────
# Helper functions (state & IDs)
# ─────────────────────────────────────────────

def log_field_changes(prefix: str, old_obj, new_obj, fields: list[str]):
    """
    Logs field-level changes between two Pydantic models.
    Only fields where the value has changed are logged.
    """
    for f in fields:
        old = getattr(old_obj, f, None)
        new = getattr(new_obj, f, None)
        if old != new:
            logger.info("%s: field '%s' changed from %r to %r", prefix, f, old, new)
            

def get_or_create_registry_entry(s_key: str) -> ServiceRegistryEntry:
    entry = SERVICE_REGISTRY.get(s_key)
    if entry is None:
        entry = ServiceRegistryEntry(service_key=s_key)
        SERVICE_REGISTRY[s_key] = entry
    return entry


def update_sat_meta(sat_id: str, **fields: Any) -> SatMeta:
    meta = SATELLITES.get(sat_id) or SatMeta()
    meta = meta.model_copy(update=fields)
    SATELLITES[sat_id] = meta
    save_satellites()
    return meta


def build_sat_runtime_status(sat_id: str) -> Dict[str, Any]:
    meta = SATELLITES.get(sat_id)
    ws_state = SAT_WS_STATE.get(sat_id, {}) or {}

    # Meta can be SatMeta or legacy dict
    if isinstance(meta, SatMeta):
        hostname = meta.hostname
        mgmt_interface = meta.mgmt_interface
        mgmt_ip_address = meta.mgmt_ip_address
        client_ip = meta.client_ip
        last_register = (
            meta.last_register.isoformat()
            if isinstance(meta.last_register, datetime)
            else meta.last_register
        )
    elif isinstance(meta, dict):
        hostname = meta.get("hostname")
        mgmt_interface = meta.get("mgmt_interface")
        mgmt_ip_address = meta.get("mgmt_ip_address")
        client_ip = meta.get("client_ip")
        last_register = meta.get("last_register")
    else:
        hostname = None
        mgmt_interface = None
        mgmt_ip_address = None
        client_ip = None
        last_register = None

    last_ws_hello = ws_state.get("last_hello")
    last_telemetry = ws_state.get("last_telemetry")
    last_activity = ws_state.get("last_activity")

    return {
        "sat_id": sat_id,
        "ws_connected": sat_id in ACTIVE_SAT_WEBSOCKETS,
        "hostname": hostname,
        "mgmt_interface": mgmt_interface,
        "mgmt_ip_address": mgmt_ip_address,
        "client_ip": client_ip,
        "last_register": last_register,
        "last_ws_hello": last_ws_hello,
        "last_telemetry": last_telemetry,
        "ws_state": ws_state,
        "last_ws_activity": last_activity,
    }


def find_latest_service_instance(service_key: str) -> Optional[ServiceInstance]:
    """
    Find the most recent ServiceInstance across all satellites for the given service_key.
    """
    best_instance: Optional[ServiceInstance] = None
    best_ts: Optional[datetime] = None

    for sat_id, sat_map in INGESTED_SERVICES_BY_SAT.items():
        inst = sat_map.get(service_key)
        if not inst:
            continue

        ts = inst.last_seen
        if ts is None:
            continue

        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        if best_ts is None or ts > best_ts:
            best_ts = ts
            best_instance = inst

    return best_instance


def generate_group_id_from_name(name: str) -> str:
    base = (name or "").strip().lower()
    if not base:
        base = "group"

    base = base.replace(" ", "-")
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    base = "".join(ch for ch in base if ch in allowed)

    if not base:
        base = "group"

    new_id = base
    i = 1
    while new_id in SAT_GROUPS:
        new_id = f"{base}-{i}"
        i += 1

    return new_id


def get_static_default_service_types() -> List[str]:
    """
    Read statically configured default include types from hub_config.yaml.
    """
    ui_service_filters = get_ui_value("service_filters", {})
    if not isinstance(ui_service_filters, dict):
        return []

    raw_default_types = ui_service_filters.get("default_include_service_types", [])
    if raw_default_types is None:
        return []

    if isinstance(raw_default_types, str):
        raw_default_types = [raw_default_types]

    if not isinstance(raw_default_types, list):
        logger.warning(
            "ui.service_filters.default_include_service_types must be a list or string, got %s",
            type(raw_default_types),
        )
        return []

    return HubServiceFilterSettings(include_service_types=raw_default_types).include_service_types


def build_default_hub_ui_settings() -> HubUiSettings:
    return HubUiSettings(
        service_filters=HubServiceFilterSettings(
            include_service_types=get_static_default_service_types(),
        )
    )


def extract_observed_service_types() -> List[str]:
    observed = set()

    for entry in SERVICE_REGISTRY.values():
        if entry.last_instance and entry.last_instance.service_name:
            observed.add(entry.last_instance.service_name)
            continue

        if "|" in entry.service_key:
            raw_service_name, _ = entry.service_key.split("|", 1)
            if raw_service_name:
                observed.add(raw_service_name)

    return sorted(observed)


def build_available_service_type_options(
    static_default_service_types: List[str],
    observed_service_types: List[str],
    include_service_types: List[str],
) -> List[ServiceTypeOption]:
    merged_sources: Dict[str, set[str]] = {}

    for name in static_default_service_types:
        merged_sources.setdefault(name, set()).add("static")
    for name in observed_service_types:
        merged_sources.setdefault(name, set()).add("observed")
    for name in include_service_types:
        merged_sources.setdefault(name, set()).add("saved")

    source_order = ["static", "observed", "saved"]
    options: List[ServiceTypeOption] = []

    for name in sorted(merged_sources):
        sources = merged_sources[name]
        source = "+".join(label for label in source_order if label in sources)
        options.append(ServiceTypeOption(name=name, source=source))

    return options


def build_service_filter_config_response() -> ServiceFilterConfigResponse:
    static_default_service_types = get_static_default_service_types()
    observed_service_types = extract_observed_service_types()
    include_service_types = HUB_UI_SETTINGS.service_filters.include_service_types

    return ServiceFilterConfigResponse(
        include_service_types=include_service_types,
        static_default_service_types=static_default_service_types,
        observed_service_types=observed_service_types,
        available_service_types=build_available_service_type_options(
            static_default_service_types=static_default_service_types,
            observed_service_types=observed_service_types,
            include_service_types=include_service_types,
        ),
    )


def load_sat_configs() -> None:
    """
    Load sat_configs.json (if present) into SATELLITE_CONFIGS.
    """
    if not SAT_CONFIGS_FILE.exists():
        return

    try:
        with SAT_CONFIGS_FILE.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        logger.warning("Could not load %s: %s", SAT_CONFIGS_FILE, e)
        return

    if not isinstance(raw, dict):
        logger.warning("%s does not contain a dict. Ignoring content.", SAT_CONFIGS_FILE)
        return

    for sat_id, cfg_dict in raw.items():
        try:
            SATELLITE_CONFIGS[sat_id] = SatConfig(**cfg_dict)
        except Exception as e:
            logger.warning(
                "Invalid SatConfig for satellite %s in %s: %s",
                sat_id,
                SAT_CONFIGS_FILE,
                e,
            )


def save_sat_configs() -> None:
    """
    Persist SATELLITE_CONFIGS to sat_configs.json.
    """
    serializable = {sid: cfg.model_dump() for sid, cfg in SATELLITE_CONFIGS.items()}
    try:
        with SAT_CONFIGS_FILE.open("w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        logger.warning("Could not write %s: %s", SAT_CONFIGS_FILE, e)


def apply_sat_config(cfg: SatConfig) -> SatConfig:
    """
    Central helper to set a config for a satellite and persist it.
    """
    SATELLITE_CONFIGS[cfg.satellite_id] = cfg
    save_sat_configs()
    return cfg


def service_key(svc: ServiceInstance) -> str:
    """
    Build unique identity for a service:
      service_name | "instance-without .<service_name> suffix"
    """
    short_instance = normalize_instance_name(svc.instance_name, svc.service_name)
    return f"{svc.service_name}|{short_instance}"


def normalize_instance_name(instance_name: str | None, service_name: str | None) -> str:
    """
    Remove the service suffix from the instance name, if present.
    """
    if not instance_name:
        return ""

    if not service_name:
        return instance_name

    suffix = f".{service_name}"
    if instance_name.endswith(suffix):
        return instance_name[:-len(suffix)]
    return instance_name


def build_device_id_from_service(svc: ServiceInstance) -> str:
    """
    Heuristic for a stable device ID.
    """
    if svc.hostname:
        return svc.hostname.strip().lower()

    if svc.addresses:
        return svc.addresses[0]

    short_inst = normalize_instance_name(svc.instance_name, svc.service_name)
    return short_inst or "unknown-device"


def derive_device_meta_from_service(inst: ServiceInstance) -> Dict[str, Optional[str]]:
    """
    Determine vendor / friendly_name of a device from SERVICE_ENRICHED_DATA.
    """

    def pick_nice_str(values: list[Any]) -> Optional[str]:
        for v in values:
            if isinstance(v, str):
                s = v.strip()
                if s:
                    return s
            elif isinstance(v, dict) and v:
                key = next(iter(v.keys()))
                if isinstance(key, str):
                    s = key.strip()
                    if s:
                        return s
        return None

    s_key = service_key(inst)
    meta = SERVICE_ENRICHED_DATA.get(s_key, {})

    normalized = meta.get("normalized") or {}
    spotify = meta.get("spotify") or {}

    vendor_candidates = [
        normalized.get("manufacturer"),
        normalized.get("vendor"),
        normalized.get("brand"),
        spotify.get("brand"),
        spotify.get("manufacturer"),
    ]

    friendly_candidates = [
        normalized.get("friendly_name"),
        normalized.get("name"),
        normalized.get("cn"),
        spotify.get("device_name"),
        spotify.get("name"),
    ]

    vendor = pick_nice_str(vendor_candidates)
    friendly_name = pick_nice_str(friendly_candidates)

    return {
        "vendor": vendor,
        "friendly_name": friendly_name,
    }


def mark_spotify_enrich_dirty(service_key: str) -> None:
    """
    Mark a service as 'dirty' for Spotify Zeroconf enrichment.
    """
    st = SPOTIFY_ENRICH_STATE.setdefault(service_key, {})
    st["dirty"] = True
    st.setdefault("error_count", 0)
    st.setdefault("next_allowed", datetime.now(timezone.utc))


def mark_sonos_enrich_dirty(service_key: str) -> None:
    """
    Mark a service as 'dirty' for Sonos device description enrichment.
    """
    st = SONOS_ENRICH_STATE.setdefault(service_key, {})
    st["dirty"] = True
    st.setdefault("error_count", 0)
    st.setdefault("next_allowed", datetime.now(timezone.utc))


def get_service_by_key(s_key: str) -> Optional[ServiceInstance]:
    """
    Search all satellites for a service with this key.
    """
    for sat_id, sat_map in INGESTED_SERVICES_BY_SAT.items():
        svc = sat_map.get(s_key)
        if svc is not None:
            return svc
    return None


def load_satellites() -> None:
    """
    Load SatMeta objects from satellites.json into SATELLITES.
    """
    global SATELLITES
    if not SATELLITES_FILE.exists():
        SATELLITES = {}
        return

    try:
        with SATELLITES_FILE.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        logger.warning("Could not load %s: %s", SATELLITES_FILE, e)
        SATELLITES = {}
        return

    if not isinstance(raw, dict):
        logger.warning("%s does not contain a dict. Ignoring content.", SATELLITES_FILE)
        SATELLITES = {}
        return

    tmp: Dict[str, SatMeta] = {}
    for sid, meta_dict in raw.items():
        try:
            tmp[sid] = SatMeta(**meta_dict)
        except Exception as e:
            logger.warning("Invalid SatMeta for %s: %s", sid, e)
    SATELLITES = tmp


def save_satellites() -> None:
    """
    Persist SATELLITES to satellites.json.
    """
    try:
        serializable = {
            sid: meta.model_dump(mode="json")
            for sid, meta in SATELLITES.items()
        }
        with SATELLITES_FILE.open("w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        logger.warning("Could not save %s: %s", SATELLITES_FILE, e)


def load_groups() -> None:
    """
    Load SAT_GROUPS from sat_groups.json.
    """
    global SAT_GROUPS
    if not SAT_GROUPS_FILE.exists():
        SAT_GROUPS = {}
        return
    try:
        with SAT_GROUPS_FILE.open("r", encoding="utf-8") as f:
            SAT_GROUPS = json.load(f)
    except Exception as e:
        logger.warning("Could not load %s: %s", SAT_GROUPS_FILE, e)
        SAT_GROUPS = {}


def save_groups() -> None:
    """
    Persist SAT_GROUPS to sat_groups.json.
    """
    try:
        with SAT_GROUPS_FILE.open("w", encoding="utf-8") as f:
            json.dump(SAT_GROUPS, f, indent=2)
    except Exception as e:
        logger.warning("Could not save %s: %s", SAT_GROUPS_FILE, e)


def load_service_registry() -> None:
    """
    Load SERVICE_REGISTRY from service_registry.json.
    """
    global SERVICE_REGISTRY
    if not SERVICE_REGISTRY_FILE.exists():
        SERVICE_REGISTRY = {}
        return

    try:
        with SERVICE_REGISTRY_FILE.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        logger.warning("Could not load %s: %s", SERVICE_REGISTRY_FILE, e)
        SERVICE_REGISTRY = {}
        return

    if not isinstance(raw, dict):
        logger.warning(
            "%s does not contain a dict. Ignoring content.",
            SERVICE_REGISTRY_FILE,
        )
        SERVICE_REGISTRY = {}
        return

    tmp: Dict[str, ServiceRegistryEntry] = {}
    for s_key, entry_dict in raw.items():
        try:
            tmp[s_key] = ServiceRegistryEntry(**entry_dict)
        except Exception as e:
            logger.warning("Invalid ServiceRegistryEntry for %s: %s", s_key, e)
    SERVICE_REGISTRY = tmp


def save_service_registry() -> None:
    """
    Persist SERVICE_REGISTRY to service_registry.json.
    """
    try:
        serializable = {
            s_key: entry.model_dump(mode="json")
            for s_key, entry in SERVICE_REGISTRY.items()
        }
        with SERVICE_REGISTRY_FILE.open("w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        logger.warning("Could not save %s: %s", SERVICE_REGISTRY_FILE, e)


def load_hub_ui_settings() -> None:
    """
    Load persisted UI settings from hub_ui_settings.json.

    If no file exists yet, static config defaults become the effective
    include defaults until the first PUT persists an explicit selection.
    """
    global HUB_UI_SETTINGS

    if not HUB_UI_SETTINGS_FILE.exists():
        HUB_UI_SETTINGS = build_default_hub_ui_settings()
        return

    try:
        with HUB_UI_SETTINGS_FILE.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        logger.warning("Could not load %s: %s", HUB_UI_SETTINGS_FILE, e)
        HUB_UI_SETTINGS = build_default_hub_ui_settings()
        return

    try:
        HUB_UI_SETTINGS = HubUiSettings(**raw)
    except Exception as e:
        logger.warning("Invalid HubUiSettings in %s: %s", HUB_UI_SETTINGS_FILE, e)
        HUB_UI_SETTINGS = build_default_hub_ui_settings()


def save_hub_ui_settings() -> None:
    """
    Persist HUB_UI_SETTINGS to hub_ui_settings.json.
    """
    try:
        with HUB_UI_SETTINGS_FILE.open("w", encoding="utf-8") as f:
            json.dump(HUB_UI_SETTINGS.model_dump(mode="json"), f, indent=2)
    except Exception as e:
        logger.warning("Could not save %s: %s", HUB_UI_SETTINGS_FILE, e)


# Load persisted state at startup
load_sat_configs()
load_satellites()
load_groups()
load_service_registry()
load_hub_ui_settings()

# ─────────────────────────────────────────────
# Auth for Sats
# ─────────────────────────────────────────────

def verify_satellite_token(x_satellite_token: str = Header(None)):
    if x_satellite_token != SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid satellite token")
    return True

# ─────────────────────────────────────────────
# Default config per Sat
# ─────────────────────────────────────────────

def get_default_config_for_sat(sat_id: str) -> SatConfig:
    """
    Fetch the config for a satellite.
    If none exists yet, create a default config, persist it and return it.
    """
    if sat_id in SATELLITE_CONFIGS:
        return SATELLITE_CONFIGS[sat_id]

    meta: Any = SATELLITES.get(sat_id)

    mgmt_if = "eth0"
    mgmt_ip = None
    ip_mode = "none"

    if isinstance(meta, SatMeta):
        if meta.mgmt_interface:
            mgmt_if = meta.mgmt_interface

        if meta.mgmt_ip_address:
            mgmt_ip = meta.mgmt_ip_address
        elif meta.client_ip:
            mgmt_ip = meta.client_ip

        if meta.mgmt_ip_mode:
            ip_mode = meta.mgmt_ip_mode

    elif isinstance(meta, dict):
        mgmt_if = meta.get("mgmt_interface") or mgmt_if
        mgmt_ip = (
            meta.get("mgmt_ip_address")
            or meta.get("client_ip")
            or mgmt_ip
        )
        ip_mode = meta.get("mgmt_ip_mode") or ip_mode

    cfg = SatConfig(
        satellite_id=sat_id,
        interfaces=[
            SatInterface(
                name=mgmt_if,
                description=f"Auto-default ({mgmt_if})",
                ip_mode=ip_mode,
                ip_address=mgmt_ip,
                mode="scan",
            )
        ],
    )

    apply_sat_config(cfg)
    return cfg

# ─────────────────────────────────────────────
# API: Health
# ─────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/api/v1/auth/login")
async def auth_login(
    request: Request,
    response: Response,
    payload: dict = Body(...),
):
    if not UI_AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="UI authentication is disabled")

    remote_addr = client_ip_from_request(request)
    limit_status = AUTH_MANAGER.check_login_allowed(remote_addr)
    if not limit_status.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
            headers={"Retry-After": str(limit_status.retry_after_seconds)},
        )

    username = str(payload.get("username", "") or "")
    password = str(payload.get("password", "") or "")

    if not AUTH_MANAGER.verify_password(username, password):
        AUTH_MANAGER.register_login_failure(remote_addr)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    AUTH_MANAGER.register_login_success(remote_addr)
    session = AUTH_MANAGER.create_session(username=username)
    AUTH_MANAGER.set_session_cookie(response, session)
    logger.info("UI login successful from %s", remote_addr)
    return build_auth_session_payload(session)


@app.post("/api/v1/auth/logout")
async def auth_logout(
    request: Request,
    response: Response,
):
    session = get_optional_ui_session(request)
    if session:
        await AUTH_MANAGER.require_csrf(request, session)
    AUTH_MANAGER.destroy_session(request)
    AUTH_MANAGER.clear_session_cookie(response)
    return build_auth_session_payload(None)


@app.get("/api/v1/auth/session")
def auth_session(request: Request):
    session = get_optional_ui_session(request)
    return build_auth_session_payload(session)

# ─────────────────────────────────────────────
# API: Sat register + get/set config
# ─────────────────────────────────────────────

@app.post("/api/v1/satellites/register", response_model=SatRegisterResponse)
def register_sat(
    req: SatRegisterRequest,
    request: Request,
    _auth_ok: bool = Depends(verify_satellite_token),
):
    sat_id = req.satellite_id
    client_ip = request.client.host
    now = datetime.now(timezone.utc)

    meta = update_sat_meta(
        sat_id,
        hostname=req.hostname,
        software_version=req.software_version,
        mgmt_interface=req.mgmt_interface or "eth0",
        mgmt_ip_address=req.mgmt_ip_address,
        mgmt_ip_mode=req.mgmt_ip_mode,
        last_register=now,
        client_ip=client_ip,
    )

    cfg = get_default_config_for_sat(sat_id)

    iface = cfg.interfaces[0] if cfg.interfaces else None
    changed = False
    if iface:
        if iface.name != meta.mgmt_interface:
            iface.name = meta.mgmt_interface
            changed = True

        if meta.mgmt_ip_address and iface.ip_address != meta.mgmt_ip_address:
            iface.ip_address = meta.mgmt_ip_address
            changed = True

        if meta.mgmt_ip_mode and iface.ip_mode != meta.mgmt_ip_mode:
            iface.ip_mode = meta.mgmt_ip_mode
            changed = True

    if changed:
        apply_sat_config(cfg)

    logger.info("Satellite %s registered from %s", sat_id, client_ip)

    return SatRegisterResponse(
        satellite_id=sat_id,
        assigned_config=cfg,
    )


@app.get("/api/v1/satellites/{sat_id}/config", response_model=SatConfig)
def get_sat_config(
    sat_id: str,
    _auth_ok: bool = Depends(require_satellite_or_ui_access),
):
    cfg = get_default_config_for_sat(sat_id)
    return cfg


@app.put("/api/v1/satellites/{sat_id}/config", response_model=SatConfig)
async def set_sat_config(
    request: Request,
    sat_id: str,
    new_cfg: SatConfig,
    _session: SessionRecord = Depends(require_ui_mutation_session),
):
    if new_cfg.satellite_id != sat_id:
        raise HTTPException(
            status_code=400,
            detail="satellite_id in body does not match path parameter",
        )
    logger.info("Satellite %s config updated via API", sat_id)
    return apply_sat_config(new_cfg)

# ─────────────────────────────────────────────
# API: Sat overview + interfaces (for UI)
# ─────────────────────────────────────────────

@app.get("/api/v1/satellites")
def api_sat_interfaces():
    result = []

    all_sat_ids = sorted(set(SATELLITE_CONFIGS.keys()) | set(SATELLITES.keys()))

    for sat_id in all_sat_ids:
        meta = SATELLITES.get(sat_id)
        cfg = SATELLITE_CONFIGS.get(sat_id) or get_default_config_for_sat(sat_id)

        if isinstance(meta, SatMeta):
            hostname = meta.hostname
            mgmt_if = meta.mgmt_interface
        elif isinstance(meta, dict):
            hostname = meta.get("hostname")
            mgmt_if = meta.get("mgmt_interface")
        else:
            hostname = None
            mgmt_if = None

        ifaces = []
        for iface in cfg.interfaces:
            ifaces.append({
                "name": iface.name,
                "parent_interface": iface.parent_interface,
                "mode": iface.mode,
                "vlan_id": iface.vlan_id,
                "ip_mode": iface.ip_mode,
                "ip_address": iface.ip_address,
                "description": iface.description,
            })

        ws_connected = sat_id in ACTIVE_SAT_WEBSOCKETS
        ws_state = SAT_WS_STATE.get(sat_id, {}) or {}
        last_ws_hello = ws_state.get("last_hello")
        last_telemetry = ws_state.get("last_telemetry")

        result.append({
            "sat_id": sat_id,
            "hostname": hostname,
            "mgmt_interface": mgmt_if,
            "interfaces": ifaces,
            "ws_connected": ws_connected,
            "last_ws_hello": last_ws_hello,
            "last_telemetry": last_telemetry,
        })

    return result

# ─────────────────────────────────────────────
# API: Service ingest
# ─────────────────────────────────────────────

@app.post("/api/v1/satellites/{sat_id}/services")
def ingest_services(
    sat_id: str,
    req: ServiceIngestRequest,
    request: Request,
    _auth_ok: bool = Depends(verify_satellite_token),
):
    if sat_id != req.satellite_id:
        raise HTTPException(status_code=400, detail="satellite_id mismatch")

    client_ip = request.client.host
    if sat_id in SATELLITES:
        update_sat_meta(sat_id, client_ip=client_ip)

    now = datetime.now(timezone.utc)
    sat_map = INGESTED_SERVICES_BY_SAT.setdefault(sat_id, {})

    for svc in req.services:
        if svc.last_seen is None:
            svc.last_seen = now
        else:
            if svc.last_seen.tzinfo is None:
                svc.last_seen = svc.last_seen.replace(tzinfo=timezone.utc)

        s_key = service_key(svc)

        existing_inst = sat_map.get(s_key)

                
        if existing_inst:
            # Snapshot before merge
            before = existing_inst.model_copy(deep=True)

            # --- Merge logic (existing code remains unchanged) ---
            existing_inst.hostname = svc.hostname or existing_inst.hostname

            if svc.addresses:
                existing_inst.addresses = svc.addresses

            if svc.port is not None:
                existing_inst.port = svc.port

            if svc.txt:
                existing_inst.txt = svc.txt

            if svc.src_ips:
                existing_inst.src_ips = svc.src_ips

            if svc.src_ifaces:
                merged_ifaces = set(existing_inst.src_ifaces or []) | set(svc.src_ifaces or [])
                existing_inst.src_ifaces = sorted(merged_ifaces)

            if svc.source_iface:
                existing_inst.source_iface = svc.source_iface

            if svc.mac:
                existing_inst.mac = svc.mac
            if svc.src_macs:
                existing_inst.src_macs = svc.src_macs

            existing_inst.vlan_id = svc.vlan_id or existing_inst.vlan_id
            existing_inst.location = svc.location or existing_inst.location
            existing_inst.last_seen = svc.last_seen

            # Snapshot after merge
            after = existing_inst

            # Fields to monitor for changes
            watched_fields = [
                "hostname",
                "addresses",
                "port",
                "txt",
                "src_ips",
                "src_ifaces",
                "source_iface",
                "mac",
                "src_macs",
                "vlan_id",
                "location",
            ]

            # Log changes
            log_field_changes(f"{s_key}", before, after, watched_fields)
            
        else:
            sat_map[s_key] = svc
            existing_inst = svc



        # Update registry entry
        reg_entry = get_or_create_registry_entry(s_key)

        new_ts = existing_inst.last_seen
        if new_ts is not None:
            if new_ts.tzinfo is None:
                new_ts = new_ts.replace(tzinfo=timezone.utc)

            cur_ts = reg_entry.last_seen
            if cur_ts is None:
                is_newer = True
            else:
                if cur_ts.tzinfo is None:
                    cur_ts = cur_ts.replace(tzinfo=timezone.utc)
                is_newer = new_ts > cur_ts

            if is_newer:
                reg_entry.last_instance = existing_inst
                reg_entry.last_seen = new_ts
                reg_entry.last_sat_id = sat_id

        reg_entry.online = True

        # TXT normalization + enrichment triggers
        txt_list = existing_inst.txt or []
        service_name = existing_inst.service_name

        try:
            normalized_new = normalize_txt(service_name, txt_list)

            reg_entry = get_or_create_registry_entry(s_key)
            meta = reg_entry.meta or {}

            existing_norm = meta.get("normalized") or {}
            merged = {**existing_norm, **normalized_new}

            meta["normalized"] = merged
            reg_entry.meta = meta
        except Exception as e:
            logger.warning("normalize_txt failed for %s: %s", s_key, e)

        try:
            if has_spotify_zeroconf_cpath(txt_list):
                mark_spotify_enrich_dirty(s_key)
        except Exception as e:
            logger.warning("has_spotify_zeroconf_cpath failed for %s: %s", s_key, e)

        try:
            if has_sonos_device_description(txt_list):
                mark_sonos_enrich_dirty(s_key)
        except Exception as e:
            logger.warning("has_sonos_device_description failed for %s: %s", s_key, e)

    # Per-sat TTL cleanup (does not delete from registry, only from sat map)
    max_age = timedelta(minutes=15)
    for s_key, inst in list(sat_map.items()):
        ls = inst.last_seen or now
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)

        if now - ls > max_age:
            del sat_map[s_key]

            reg_entry = SERVICE_REGISTRY.get(s_key)
            if reg_entry is not None:
                reg_entry.online = False

    # Persist registry after ingest + TTL updates
    save_service_registry()

    logger.info(
        "Ingested %d services for satellite %s from %s (known_for_sat=%d)",
        len(req.services),
        sat_id,
        client_ip,
        len(sat_map),
    )

    return {
        "status": "ok",
        "ingested": len(req.services),
        "known_for_sat": len(sat_map),
        "time": now.isoformat(),
    }

# ─────────────────────────────────────────────
# API: List services
# ─────────────────────────────────────────────

@app.get("/api/v1/services", response_model=List[ServiceWithMeta])
def list_services(limit: Optional[int] = None) -> List[ServiceWithMeta]:
    entries = list(SERVICE_REGISTRY.values())

    def _sort_key(entry: ServiceRegistryEntry):
        ts = entry.last_seen
        if ts is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts

    entries.sort(key=_sort_key, reverse=True)

    if limit is not None and limit > 0:
        entries = entries[:limit]

    result: List[ServiceWithMeta] = []

    for entry in entries:
        s_key = entry.service_key
        inst = entry.last_instance

        if inst is None:
            raw_service_name: Optional[str] = None
            short_inst: Optional[str] = None

            if "|" in s_key:
                raw_service_name, short_inst = s_key.split("|", 1)

            service_name_for_model = raw_service_name or "_unknown._tcp.local"
            if raw_service_name and short_inst:
                instance_name_for_model = f"{short_inst}.{raw_service_name}"
            else:
                instance_name_for_model = service_name_for_model

            inst = ServiceInstance(
                service_name=service_name_for_model,
                instance_name=instance_name_for_model,
                hostname=None,
                addresses=[],
                port=None,
                txt=[],
                last_seen=entry.last_seen,
                src_ifaces=[],
                src_ips=[],
                source_iface=None,
                vlan_id=None,
                location=None,
                mac=None,
                src_macs=[],
            )

        base_meta = entry.meta or {}
        meta = {
            **base_meta,
            "online": bool(entry.online),
            "spoof_enabled": bool(entry.spoof_enabled),
            "spoof_note": entry.spoof_note,
            "spoof_targets": [t.model_dump() for t in entry.spoof_targets],
        }

        result.append(
            ServiceWithMeta(
                service=inst,
                service_key=s_key,
                meta=meta,
                source_sat=entry.last_sat_id,
            )
        )

    return result


@app.get(
    "/api/v1/ui/service-filters",
    response_model=ServiceFilterConfigResponse,
)
def get_ui_service_filters() -> ServiceFilterConfigResponse:
    return build_service_filter_config_response()


@app.put(
    "/api/v1/ui/service-filters",
    response_model=ServiceFilterConfigResponse,
)
def update_ui_service_filters(
    payload: ServiceFilterConfigUpdate,
    _session: SessionRecord = Depends(require_ui_mutation_session),
) -> ServiceFilterConfigResponse:
    global HUB_UI_SETTINGS

    HUB_UI_SETTINGS = HubUiSettings(
        service_filters=HubServiceFilterSettings(
            include_service_types=payload.include_service_types,
        )
    )
    save_hub_ui_settings()
    return build_service_filter_config_response()

# ─────────────────────────────────────────────
# API: Spoof update per service
# ─────────────────────────────────────────────

@app.post("/api/v1/services/spoof", response_model=SpoofConfig)
async def update_spoof(
    request: Request,
    service_key: str = Query(..., description="Service key"),
    payload: dict = Body(...),
    _session: SessionRecord = Depends(require_ui_mutation_session),
):
    spoof_enabled = bool(payload.get("spoof_enabled", False))
    spoof_note = payload.get("spoof_note", "")
    spoof_targets_raw = payload.get("spoof_targets", [])

    targets: List[SpoofTarget] = []
    for t in spoof_targets_raw:
        try:
            targets.append(SpoofTarget(**t))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid SpoofTarget: {e}")

    entry = get_or_create_registry_entry(service_key)
    entry.spoof_enabled = spoof_enabled
    entry.spoof_note = spoof_note
    entry.spoof_targets = targets

    cfg = SpoofConfig(
        service_key=service_key,
        enabled=entry.spoof_enabled,
        note=entry.spoof_note,
        targets=entry.spoof_targets,
    )

    save_service_registry()
    logger.info(
        "Updated spoof config for service %s (enabled=%s, targets=%d)",
        service_key,
        spoof_enabled,
        len(targets),
    )

    await broadcast_assignments_to_all_sats()
    return cfg

# ─────────────────────────────────────────────
# API: Delete services
# ─────────────────────────────────────────────

@app.delete("/api/v1/services/delete")
async def delete_services(
    request: Request,
    service_keys: List[str] = Body(..., description="List of service keys to delete"),
    _session: SessionRecord = Depends(require_ui_mutation_session),
):
    """
    Delete one or more services from the registry.
    Also removes them from satellite-specific maps and persists the registry.
    """
    deleted_count = 0
    not_found = []
    
    for s_key in service_keys:
        if s_key in SERVICE_REGISTRY:
            # Remove from main registry
            del SERVICE_REGISTRY[s_key]
            
            # Remove from satellite-specific maps
            for sat_id, sat_map in INGESTED_SERVICES_BY_SAT.items():
                if s_key in sat_map:
                    del sat_map[s_key]
            
            deleted_count += 1
        else:
            not_found.append(s_key)
    
    # Persist registry after deletions
    if deleted_count > 0:
        save_service_registry()
        logger.info(
            "Deleted %d service(s) from registry. Not found: %d",
            deleted_count,
            len(not_found),
        )
    
    return {
        "status": "ok",
        "deleted": deleted_count,
        "not_found": not_found,
    }

# ─────────────────────────────────────────────
# Web UI: Sats
# ─────────────────────────────────────────────

@app.get("/ui", response_class=RedirectResponse)
def root_redirect(_session: SessionRecord = Depends(require_ui_session)):
    return RedirectResponse(url="/ui/sats")

@app.get("/", include_in_schema=False)
async def serve_frontend_root():
    return FileResponse(INDEX_FILE)


@app.get("/example_services.json", include_in_schema=False)
async def example_services():
    return FileResponse(FRONTEND_DIR / "example_services.json", media_type="application/json")


@app.get("/example_sat.json", include_in_schema=False)
async def example_sat():
    return FileResponse(FRONTEND_DIR / "example_sat.json", media_type="application/json")


@app.get("/example_groups.json", include_in_schema=False)
async def example_groups():
    return FileResponse(FRONTEND_DIR / "example_groups.json", media_type="application/json")




@app.get("/ui/sats", response_class=HTMLResponse)
def ui_sats(request: Request, session: SessionRecord = Depends(require_ui_session)):
    sat_items = []
    all_sat_ids = set(SATELLITE_CONFIGS.keys()) | set(SATELLITES.keys())

    for sat_id in sorted(all_sat_ids):
        meta = SATELLITES.get(sat_id, {})
        cfg = SATELLITE_CONFIGS.get(sat_id) or get_default_config_for_sat(sat_id)
        sat_items.append(
            {
                "sat_id": sat_id,
                "meta": meta,
                "config": cfg,
                "config_json": json.dumps(cfg.model_dump(), indent=2),
            }
        )

    return templates.TemplateResponse(
        "sats.html",
        {
            "request": request,
            "sats": sat_items,
            "csrf_token": session.csrf_token,
        },
    )


@app.get("/ui/sats/{sat_id}/edit", response_class=HTMLResponse)
def ui_edit_sat(
    request: Request,
    sat_id: str,
    session: SessionRecord = Depends(require_ui_session),
):
    cfg = SATELLITE_CONFIGS.get(sat_id) or get_default_config_for_sat(sat_id)

    interfaces_json = json.dumps(
        [iface.model_dump() for iface in cfg.interfaces],
        indent=2
    )

    return templates.TemplateResponse(
        "sat_config_edit.html",
        {
            "request": request,
            "sat_id": sat_id,
            "cfg": cfg,
            "interfaces_json": interfaces_json,
            "csrf_token": session.csrf_token,
        },
    )


@app.post("/ui/sats/{sat_id}/edit", response_class=HTMLResponse)
async def ui_save_sat(
    request: Request,
    sat_id: str,
    interfaces_json: str = Form("[]"),
    csrf_token: str = Form(""),
    _session: SessionRecord = Depends(require_ui_mutation_session),
):
    interfaces: List[SatInterface] = []
    raw_str = interfaces_json.strip()

    if raw_str:
        try:
            raw = json.loads(raw_str)
            if not isinstance(raw, list):
                raise ValueError("Root must be an array.")
            for item in raw:
                interfaces.append(SatInterface(**item))
        except Exception as e:
            return templates.TemplateResponse(
                "sat_config_edit.html",
                {
                    "request": request,
                    "sat_id": sat_id,
                    "cfg": SatConfig(satellite_id=sat_id, interfaces=[]),
                    "interfaces_json": interfaces_json,
                    "error": f"Error in interfaces JSON: {e}",
                    "csrf_token": csrf_token,
                },
                status_code=400,
            )

    new_cfg = SatConfig(
        satellite_id=sat_id,
        interfaces=interfaces,
    )
    apply_sat_config(new_cfg)
    logger.info("Satellite %s config updated via UI", sat_id)

    return RedirectResponse(url="/ui/sats", status_code=303)

# ─────────────────────────────────────────────
# Web UI: Services
# ─────────────────────────────────────────────

@app.get("/ui/services", response_class=HTMLResponse)
def ui_services(request: Request, session: SessionRecord = Depends(require_ui_session)):
    """
    API-first: UI only loads the template, data comes from /api/v1/services.
    Filtering by satellite is done in the frontend.
    """
    return templates.TemplateResponse(
        "services.html",
        {
            "request": request,
            "csrf_token": session.csrf_token,
        },
    )

# ─────────────────────────────────────────────
# Web UI: Groups
# ─────────────────────────────────────────────

@app.get("/ui/groups", response_class=HTMLResponse)
def ui_groups(request: Request, session: SessionRecord = Depends(require_ui_session)):
    all_sat_ids = sorted(set(SATELLITES.keys()) | set(SATELLITE_CONFIGS.keys()))

    group_items = []
    for group_id, data in sorted(SAT_GROUPS.items()):
        group_items.append(
            {
                "group_id": group_id,
                "name": data.get("name", group_id),
                "description": data.get("description", ""),
                "members": data.get("members", []),
            }
        )

    return templates.TemplateResponse(
        "groups.html",
        {
            "request": request,
            "groups": group_items,
            "all_sat_ids": all_sat_ids,
            "csrf_token": session.csrf_token,
        },
    )


@app.get("/ui/groups/{group_id}/edit", response_class=HTMLResponse)
def ui_edit_group(
    request: Request,
    group_id: str,
    session: SessionRecord = Depends(require_ui_session),
):
    is_new = (group_id == "__new__")

    if is_new:
        data = {
            "name": "",
            "description": "",
            "members": [],
        }
        display_group_id = ""
    else:
        data = SAT_GROUPS.get(
            group_id,
            {
                "name": group_id,
                "description": "",
                "members": [],
            },
        )
        display_group_id = group_id

    all_sat_ids = sorted(set(SATELLITES.keys()) | set(SATELLITE_CONFIGS.keys()))

    return templates.TemplateResponse(
        "group_edit.html",
        {
            "request": request,
            "group_id": display_group_id,
            "url_group_id": group_id,
            "group": data,
            "all_sat_ids": all_sat_ids,
            "is_new": is_new,
            "csrf_token": session.csrf_token,
        },
    )


@app.post("/ui/groups/{group_id}/edit", response_class=HTMLResponse)
async def ui_save_group(
    request: Request,
    group_id: str,
    name: str = Form(""),
    description: str = Form(""),
    members: List[str] = Form(default_factory=list),
    csrf_token: str = Form(""),
    _session: SessionRecord = Depends(require_ui_mutation_session),
):
    if group_id == "__new__":
        new_group_id = generate_group_id_from_name(name or "group")
    else:
        new_group_id = group_id

    SAT_GROUPS[new_group_id] = {
        "name": name or new_group_id,
        "description": description or "",
        "members": sorted(set(members)),
    }
    save_groups()
    logger.info(
        "Group %s saved (members=%d)",
        new_group_id,
        len(SAT_GROUPS[new_group_id]["members"]),
    )

    return RedirectResponse(url="/ui/groups", status_code=303)

@app.post("/ui/groups/{group_id}/delete", response_class=RedirectResponse)
async def ui_delete_group(
    request: Request,
    group_id: str,
    _session: SessionRecord = Depends(require_ui_mutation_session),
):
    SAT_GROUPS.pop(group_id, None)
    save_groups()
    return RedirectResponse(url="/ui/groups", status_code=303)

# ─────────────────────────────────────────────
# Web UI: Spoofing
# ─────────────────────────────────────────────

@app.get("/ui/spoofing", response_class=HTMLResponse)
def ui_spoofing(request: Request, session: SessionRecord = Depends(require_ui_session)):
    return templates.TemplateResponse(
        "spoofing.html",
        {
            "request": request,
            "csrf_token": session.csrf_token,
        },
    )

# ─────────────────────────────────────────────
# API: Spoofing assignments per Sat
# ─────────────────────────────────────────────

@app.get("/api/v1/satellites/{sat_id}/spoofing", response_model=List[SpoofTarget])
def api_get_spoofing_for_sat(
    sat_id: str,
    _auth_ok: bool = Depends(verify_satellite_token),
):
    result: List[SpoofTarget] = []

    for entry in SERVICE_REGISTRY.values():
        if not entry.spoof_enabled:
            continue

        for tgt in entry.spoof_targets:
            if tgt.sat_id == sat_id:
                result.append(tgt)

    return result


@app.get(
    "/api/v1/satellites/{sat_id}/spoof-assignments",
    response_model=List[SpoofAssignment],
)
def get_spoof_assignments_for_sat(
    sat_id: str,
    _auth_ok: bool = Depends(verify_satellite_token),
):
    return build_spoof_assignments_for_sat(sat_id)


def build_spoof_assignments_for_sat(sat_id: str) -> List[SpoofAssignment]:
    assignments: List[SpoofAssignment] = []

    for entry in SERVICE_REGISTRY.values():
        if not entry.spoof_enabled:
            continue

        if not entry.online:
            continue

        targets_for_sat = [t for t in entry.spoof_targets if t.sat_id == sat_id]
        if not targets_for_sat:
            continue

        inst = entry.last_instance

        # Optional fallback: try to find latest instance across Sats
        if inst is None:
            inst = find_latest_service_instance(entry.service_key)

        if not inst:
            continue

        iface_list: List[str] = []
        any_use_mgmt = False
        vlan_set: set[int] = set()

        for t in targets_for_sat:
            if t.iface:
                iface_list.extend(t.iface)
            if t.use_mgmt:
                any_use_mgmt = True
            for v in t.vlans:
                vlan_set.add(v)

        combined_ifaces = sorted(set(iface_list)) if iface_list else None

        combined_target = SpoofTarget(
            sat_id=sat_id,
            use_mgmt=any_use_mgmt,
            vlans=sorted(vlan_set),
            iface=combined_ifaces,
        )

        assignments.append(
            SpoofAssignment(
                service_key=entry.service_key,
                service=inst,
                spoof_target=combined_target,
            )
        )

    return assignments

# ─────────────────────────────────────────────
# WebSocket HUB <-> SAT
# ─────────────────────────────────────────────

async def handle_sat_ws_message(sat_id: str, msg: dict):
    msg_type = msg.get("type") or ""
    payload = msg.get("payload") or {}

    now = datetime.now(timezone.utc)

    # Update generic last activity timestamp
    state = SAT_WS_STATE.setdefault(sat_id, {})
    state["last_activity"] = now.isoformat()

    if msg_type == "sat.hello":
        update_sat_meta(
            sat_id,
            hostname=payload.get("hostname"),
            software_version=payload.get("software_version"),
            ws_capabilities=payload.get("capabilities"),
        )

        state["last_hello"] = now.isoformat()
        state["hello_payload"] = payload

        logger.info("WS: sat.hello from %s: %s", sat_id, payload)
        await broadcast_sat_status(sat_id)
        return

    if msg_type == "sat.telemetry":
        state["last_telemetry"] = now.isoformat()
        state["telemetry"] = payload

        logger.debug("WS: sat.telemetry from %s: %s", sat_id, payload)
        await broadcast_sat_status(sat_id)
        return

    if msg_type == "sat.services.snapshot":
        services = payload.get("services", []) or []
        count = len(services)

        logger.info(
            "WS: sat.services.snapshot from %s: %d services received (only read, not stored)",
            sat_id,
            count,
        )

        state["last_services_snapshot"] = now.isoformat()
        state["services_snapshot_count"] = count
        return

    logger.warning("WS: Unknown / unhandled message type from %s: %s", sat_id, msg_type)


async def send_assignments_to_sat(sat_id: str):
    async with ACTIVE_WS_LOCK:
        ws = ACTIVE_SAT_WEBSOCKETS.get(sat_id)

    if not ws:
        return

    assignments = build_spoof_assignments_for_sat(sat_id)

    message = {
        "type": "hub.assignments.update",
        "payload": {
            "sat_id": sat_id,
            "assignments": jsonable_encoder(assignments),
        },
    }

    try:
        await ws.send_json(message)
        logger.info(
            "WS: Sent %d spoof assignments to satellite %s",
            len(assignments),
            sat_id,
        )
    except Exception as e:
        logger.error("WS: Error sending assignments to satellite %s: %s", sat_id, e)
        async with ACTIVE_WS_LOCK:
            if ACTIVE_SAT_WEBSOCKETS.get(sat_id) is ws:
                ACTIVE_SAT_WEBSOCKETS.pop(sat_id, None)


async def broadcast_assignments_to_all_sats():
    async with ACTIVE_WS_LOCK:
        sat_ids = list(ACTIVE_SAT_WEBSOCKETS.keys())

    for sid in sat_ids:
        await send_assignments_to_sat(sid)


@app.websocket("/ws/sat")
async def websocket_sat_assignments(websocket: WebSocket):
    token = websocket.query_params.get("token")
    sat_id = websocket.query_params.get("sat_id")

    if token != SHARED_SECRET:
        await websocket.close(code=1008)
        return

    if not sat_id:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    async with ACTIVE_WS_LOCK:
        ACTIVE_SAT_WEBSOCKETS[sat_id] = websocket

    logger.info("WS: Satellite %s connected", sat_id)

    await broadcast_sat_status(sat_id)

    try:
        await send_assignments_to_sat(sat_id)

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception as e:
                logger.warning(
                    "WS: Invalid JSON from satellite %s: %s | raw=%r",
                    sat_id,
                    e,
                    raw,
                )
                continue

            body_sat_id = msg.get("sat_id")
            if body_sat_id and body_sat_id != sat_id:
                logger.warning(
                    "WS: sat_id in message body (%s) does not match URL (%s)",
                    body_sat_id,
                    sat_id,
                )

            await handle_sat_ws_message(sat_id, msg)

    except WebSocketDisconnect:
        logger.info("WS: Satellite %s disconnected", sat_id)
    except Exception as e:
        logger.error("WS: Error on WebSocket for satellite %s: %s", sat_id, e)
    finally:
        async with ACTIVE_WS_LOCK:
            if ACTIVE_SAT_WEBSOCKETS.get(sat_id) is websocket:
                ACTIVE_SAT_WEBSOCKETS.pop(sat_id, None)
        await broadcast_sat_status(sat_id)

# ─────────────────────────────────────────────
# WebSocket UI
# ─────────────────────────────────────────────

async def broadcast_sat_status(sat_id: str):
    payload = {
        "type": "sat.status",
        "payload": build_sat_runtime_status(sat_id),
    }

    async with UI_WS_LOCK:
        clients = list(ACTIVE_UI_WEBSOCKETS)

    for ws in clients:
        try:
            await ws.send_json(payload)
        except Exception as e:
            logger.warning("WS: Error sending status to UI client: %s", e)
            async with UI_WS_LOCK:
                if ws in ACTIVE_UI_WEBSOCKETS:
                    ACTIVE_UI_WEBSOCKETS.remove(ws)


@app.websocket("/ws/hub-status")
async def websocket_hub_status(websocket: WebSocket):
    if UI_AUTH_ENABLED:
        request = Request(websocket.scope)
        session = AUTH_MANAGER.get_session_from_request(request)
        if not session:
            await websocket.close(code=1008)
            return

        origin = websocket.headers.get("origin")
        host = websocket.headers.get("host")
        is_secure = websocket.url.scheme == "wss"
        if not AUTH_MANAGER.is_origin_allowed(origin, host, is_secure):
            await websocket.close(code=1008)
            return

    await websocket.accept()

    async with UI_WS_LOCK:
        ACTIVE_UI_WEBSOCKETS.append(websocket)

    logger.info("WS: UI client connected for hub status")

    try:
        all_sat_ids = sorted(set(SATELLITE_CONFIGS.keys()) | set(SATELLITES.keys()))
        snapshot = {
            "type": "sat.snapshot",
            "payload": [build_sat_runtime_status(sid) for sid in all_sat_ids],
        }
        await websocket.send_json(snapshot)

        while True:
            _ = await websocket.receive_text()
            # Currently no commands from UI, just keep connection alive
    except WebSocketDisconnect:
        logger.info("WS: UI client disconnected from hub status")
    except Exception as e:
        logger.error("WS: Error on UI WebSocket: %s", e)
    finally:
        async with UI_WS_LOCK:
            if websocket in ACTIVE_UI_WEBSOCKETS:
                ACTIVE_UI_WEBSOCKETS.remove(websocket)

# ─────────────────────────────────────────────
# Enrichment worker
# ─────────────────────────────────────────────

async def enrichment_worker():
    """
    Background task:

    - Handles Spotify and Sonos enrichment.
    - Uses 'dirty' + 'next_allowed' with backoff.
    - Runs enrichers in threads to avoid blocking the event loop.
    - Writes results into ServiceRegistryEntry.meta["normalized"].
    """
    ENRICH_SOURCES = {
        "spotify": {
            "state": SPOTIFY_ENRICH_STATE,
            "base_interval": SPOTIFY_ENRICH_BASE_INTERVAL,
            "backoff_base": SPOTIFY_ENRICH_BACKOFF_BASE,
            "backoff_max": SPOTIFY_ENRICH_BACKOFF_MAX,
            "enricher": enrich_spotify_zeroconf,
            "flag": "spotify_enriched",
        },
        "sonos": {
            "state": SONOS_ENRICH_STATE,
            "base_interval": SONOS_ENRICH_BASE_INTERVAL,
            "backoff_base": SONOS_ENRICH_BACKOFF_BASE,
            "backoff_max": SONOS_ENRICH_BACKOFF_MAX,
            "enricher": enrich_sonos_device_description,
            "flag": "sonos_enriched",
        },
    }

    logger.info("Enrichment worker started")

    while True:
        await asyncio.sleep(5)
        now = datetime.now(timezone.utc)

        for source_name, cfg in ENRICH_SOURCES.items():
            state_dict: Dict[str, Dict[str, Any]] = cfg["state"]
            base_interval: timedelta = cfg["base_interval"]
            backoff_base: timedelta = cfg["backoff_base"]
            backoff_max: timedelta = cfg["backoff_max"]
            enricher = cfg["enricher"]
            flag_name: str = cfg["flag"]

            for s_key, state in list(state_dict.items()):
                if not state.get("dirty"):
                    continue

                next_allowed: datetime = state.get("next_allowed", now)
                if next_allowed > now:
                    continue

                reg_entry = SERVICE_REGISTRY.get(s_key)
                inst = find_latest_service_instance(s_key) or (
                    reg_entry.last_instance if reg_entry else None
                )
                if not inst:
                    state["dirty"] = False
                    continue

                svc_dict: Dict[str, Any] = {
                    "service_name": inst.service_name,
                    "addresses": inst.addresses or [],
                    "port": inst.port,
                    "txt": inst.txt or [],
                }

                reg_entry = get_or_create_registry_entry(s_key)
                meta = reg_entry.meta or {}
                normalized = meta.setdefault("normalized", {})

                success = await asyncio.to_thread(
                    enricher,
                    svc_dict,
                    normalized,
                    2.0,
                )

                state["last_attempt"] = now

                if success:
                    state["last_success"] = now
                    state["error_count"] = 0
                    state["dirty"] = False
                    state["next_allowed"] = now + base_interval

                    meta[flag_name] = True
                    reg_entry.meta = meta
                    logger.info(
                        "Enrichment %s for %s succeeded; next_allowed=%s",
                        source_name,
                        s_key,
                        state["next_allowed"].isoformat(),
                    )
                    save_service_registry()
                else:
                    err_count = int(state.get("error_count", 0)) + 1
                    state["error_count"] = err_count

                    backoff_seconds = backoff_base.total_seconds() * (2 ** (err_count - 1))
                    max_seconds = backoff_max.total_seconds()
                    if backoff_seconds > max_seconds:
                        backoff_seconds = max_seconds

                    state["next_allowed"] = now + timedelta(seconds=backoff_seconds)
                    logger.warning(
                        "Enrichment %s for %s failed (errors=%d); next_allowed=%s",
                        source_name,
                        s_key,
                        err_count,
                        state["next_allowed"].isoformat(),
                    )

# ─────────────────────────────────────────────
# Service registry TTL worker
# ─────────────────────────────────────────────

async def service_registry_ttl_worker():
    MAX_AGE = timedelta(minutes=15)
    SLEEP_INTERVAL = 30

    logger.info("Service registry TTL worker started")

    while True:
        await asyncio.sleep(SLEEP_INTERVAL)
        now = datetime.now(timezone.utc)

        changed = False

        for s_key, entry in list(SERVICE_REGISTRY.items()):
            ts = entry.last_seen
            if not ts:
                continue
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    if entry.online:
                        entry.online = False
                        changed = True
                    continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            if now - ts > MAX_AGE:
                if entry.online:
                    entry.online = False
                    changed = True

        if changed:
            save_service_registry()
            logger.debug("Service registry TTL worker marked some entries offline")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    """
    SPA fallback for Lovable frontend:
    - All non-API/non-UI/non-static routes return index.html
    - React router takes over from there
    """
    # Do NOT steal backend/API/doc/ws/static routes
    if full_path.startswith(
        (
            "api/",
            "ui/",
            "ws/",
            "docs",
            "redoc",
            "openapi.json",
            "static/",
            "assets/",
            "example_services.json",
            "example_sat.json",
            "example_groups.json"                      
        )
    ):
        raise HTTPException(status_code=404, detail="Not Found")

    return FileResponse(INDEX_FILE)



if __name__ == "__main__":
   # uvicorn.run(app, host="0.0.0.0", port=8080)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_config=LOGGING_CONFIG,
)
