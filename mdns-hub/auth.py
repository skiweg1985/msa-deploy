from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import HTTPException, Request, Response

from logging_config import get_logger

logger = get_logger("mdns_hub.auth")

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError
except ImportError:  # pragma: no cover - optional dependency
    PasswordHasher = None
    InvalidHashError = Exception
    VerifyMismatchError = Exception


SESSION_COOKIE_NAME = "msa_hub_session"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "csrf_token"
RATE_LIMIT_WINDOW = timedelta(minutes=15)
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_BLOCK = timedelta(minutes=15)


@dataclass(slots=True)
class AuthSettings:
    enabled: bool
    admin_username: str
    admin_password: Optional[str]
    admin_password_hash: Optional[str]
    session_secret: str
    session_ttl_seconds: int
    cookie_secure: bool
    allowed_origins: list[str]


@dataclass(slots=True)
class SessionRecord:
    session_id: str
    username: str
    csrf_token: str
    created_at: datetime
    expires_at: datetime


@dataclass(slots=True)
class LoginRateLimitStatus:
    allowed: bool
    retry_after_seconds: int = 0


class LoginRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, object]] = {}

    def _prune_locked(self, now: datetime) -> None:
        for key in list(self._entries.keys()):
            entry = self._entries[key]
            blocked_until = entry.get("blocked_until")
            attempts = [
                ts
                for ts in entry.get("attempts", [])
                if isinstance(ts, datetime) and now - ts <= RATE_LIMIT_WINDOW
            ]
            if blocked_until and isinstance(blocked_until, datetime) and blocked_until > now:
                entry["attempts"] = attempts
                continue
            if attempts:
                entry["attempts"] = attempts
                entry["blocked_until"] = None
                continue
            self._entries.pop(key, None)

    def check(self, key: str) -> LoginRateLimitStatus:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune_locked(now)
            entry = self._entries.get(key)
            if not entry:
                return LoginRateLimitStatus(allowed=True)

            blocked_until = entry.get("blocked_until")
            if isinstance(blocked_until, datetime) and blocked_until > now:
                retry_after = max(1, int((blocked_until - now).total_seconds()))
                return LoginRateLimitStatus(False, retry_after)

            attempts = entry.get("attempts", [])
            if isinstance(attempts, list) and len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
                blocked_until = now + RATE_LIMIT_BLOCK
                entry["blocked_until"] = blocked_until
                retry_after = int(RATE_LIMIT_BLOCK.total_seconds())
                return LoginRateLimitStatus(False, retry_after)

        return LoginRateLimitStatus(allowed=True)

    def register_failure(self, key: str) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune_locked(now)
            entry = self._entries.setdefault(key, {"attempts": [], "blocked_until": None})
            attempts = entry.setdefault("attempts", [])
            if isinstance(attempts, list):
                attempts.append(now)
                if len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
                    entry["blocked_until"] = now + RATE_LIMIT_BLOCK

    def register_success(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)


class InMemorySessionStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = max(ttl_seconds, 60)
        self._lock = threading.Lock()
        self._sessions: Dict[str, SessionRecord] = {}

    def _purge_expired_locked(self, now: datetime) -> None:
        for session_id, record in list(self._sessions.items()):
            if record.expires_at <= now:
                self._sessions.pop(session_id, None)

    def create(self, username: str) -> SessionRecord:
        now = datetime.now(timezone.utc)
        record = SessionRecord(
            session_id=secrets.token_urlsafe(32),
            username=username,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        with self._lock:
            self._purge_expired_locked(now)
            self._sessions[record.session_id] = record
        return record

    def get(self, session_id: str) -> Optional[SessionRecord]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_expired_locked(now)
            record = self._sessions.get(session_id)
            if not record:
                return None
            if record.expires_at <= now:
                self._sessions.pop(session_id, None)
                return None

            refreshed = SessionRecord(
                session_id=record.session_id,
                username=record.username,
                csrf_token=record.csrf_token,
                created_at=record.created_at,
                expires_at=now + timedelta(seconds=self._ttl_seconds),
            )
            self._sessions[session_id] = refreshed
            return refreshed

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


class AuthManager:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self._ph = PasswordHasher() if PasswordHasher else None
        self._sessions = InMemorySessionStore(settings.session_ttl_seconds)
        self._rate_limiter = LoginRateLimiter()

    def _sign_session_id(self, session_id: str) -> str:
        digest = hmac.new(
            self.settings.session_secret.encode("utf-8"),
            session_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        signature = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return f"{session_id}.{signature}"

    def _unsign_session_cookie(self, cookie_value: str | None) -> Optional[str]:
        if not cookie_value or "." not in cookie_value:
            return None
        session_id, signature = cookie_value.rsplit(".", 1)
        expected = self._sign_session_id(session_id).rsplit(".", 1)[1]
        if not hmac.compare_digest(signature, expected):
            return None
        return session_id

    def get_session_from_request(self, request: Request) -> Optional[SessionRecord]:
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        session_id = self._unsign_session_cookie(session_cookie)
        if not session_id:
            return None
        return self._sessions.get(session_id)

    def create_session(self, username: str) -> SessionRecord:
        return self._sessions.create(username=username)

    def destroy_session(self, request: Request) -> None:
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        session_id = self._unsign_session_cookie(session_cookie)
        if session_id:
            self._sessions.delete(session_id)

    def set_session_cookie(self, response: Response, session: SessionRecord) -> None:
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=self._sign_session_id(session.session_id),
            max_age=self.settings.session_ttl_seconds,
            httponly=True,
            secure=self.settings.cookie_secure,
            samesite="lax",
            path="/",
        )

    def clear_session_cookie(self, response: Response) -> None:
        response.delete_cookie(
            key=SESSION_COOKIE_NAME,
            httponly=True,
            secure=self.settings.cookie_secure,
            samesite="lax",
            path="/",
        )

    def verify_password(self, username: str, password: str) -> bool:
        if not self.settings.admin_username:
            return False
        if not hmac.compare_digest(username, self.settings.admin_username):
            return False

        password_hash = (self.settings.admin_password_hash or "").strip()
        if password_hash:
            if password_hash.startswith("$argon2"):
                if not self._ph:
                    logger.warning("Argon2 password hash configured, but argon2-cffi is unavailable")
                    return False
                try:
                    return bool(self._ph.verify(password_hash, password))
                except (VerifyMismatchError, InvalidHashError):
                    return False

            if password_hash.startswith("pbkdf2_sha256$"):
                return verify_pbkdf2_sha256(password, password_hash)

            logger.warning("Unsupported admin_password_hash format configured")
            return False

        configured_password = self.settings.admin_password or ""
        return hmac.compare_digest(password, configured_password)

    def check_login_allowed(self, remote_addr: str) -> LoginRateLimitStatus:
        return self._rate_limiter.check(remote_addr or "unknown")

    def register_login_failure(self, remote_addr: str) -> None:
        self._rate_limiter.register_failure(remote_addr or "unknown")

    def register_login_success(self, remote_addr: str) -> None:
        self._rate_limiter.register_success(remote_addr or "unknown")

    def is_origin_allowed(self, origin: str | None, host: str | None, secure: bool) -> bool:
        if not origin:
            return True

        allowed = set(self.settings.allowed_origins)
        if host:
            scheme = "https" if secure else "http"
            allowed.add(f"{scheme}://{host}")
        return origin in allowed

    def require_session(self, request: Request) -> SessionRecord:
        if not self.settings.enabled:
            now = datetime.now(timezone.utc)
            return SessionRecord(
                session_id="auth-disabled",
                username=self.settings.admin_username or "admin",
                csrf_token="",
                created_at=now,
                expires_at=now + timedelta(days=365),
            )

        session = self.get_session_from_request(request)
        if not session:
            raise HTTPException(status_code=401, detail="Authentication required")
        return session

    async def require_csrf(self, request: Request, session: SessionRecord) -> None:
        if not self.settings.enabled or request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
            return

        provided_token = request.headers.get(CSRF_HEADER_NAME)
        content_type = request.headers.get("content-type", "")
        if not provided_token and content_type.startswith("application/x-www-form-urlencoded"):
            form = await request.form()
            provided_token = str(form.get(CSRF_FORM_FIELD, "")).strip()
        if not provided_token and content_type.startswith("multipart/form-data"):
            form = await request.form()
            provided_token = str(form.get(CSRF_FORM_FIELD, "")).strip()
        if not provided_token or not hmac.compare_digest(provided_token, session.csrf_token):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")


def verify_pbkdf2_sha256(password: str, encoded_hash: str) -> bool:
    try:
        _, iterations_raw, salt, hash_value = encoded_hash.split("$", 3)
        iterations = int(iterations_raw)
    except (TypeError, ValueError):
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    candidate_b64 = base64.b64encode(candidate).decode("ascii")
    return hmac.compare_digest(candidate_b64, hash_value)
