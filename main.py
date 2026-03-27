"""
Sentinel — Password & Security Audit API  v4.0.0
Production-ready FastAPI backend.

Run:
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import hashlib
import logging
import math
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware


# ─────────────────────────────────────────────
#  CONFIG  (reads from .env automatically)
# ─────────────────────────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False

    # CORS — restrict to your domain(s) in production
    # e.g.  ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
    allowed_origins: list[str] = ["*"]

    hibp_timeout: float = 6.0
    hibp_retries: int = 2

    rate_limit_global: str = "60/minute"
    rate_limit_audit: str = "20/minute"

    common_passwords_path: str = "common_passwords.txt"

    log_level: str = "INFO"


settings = Settings()

# ─────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("sentinel")


# ─────────────────────────────────────────────
#  INLINE FALLBACK COMMON PASSWORDS
# ─────────────────────────────────────────────
_INLINE_COMMON = {
    "123456", "password", "123456789", "qwerty", "abc123",
    "111111", "password1", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "master", "sunshine", "princess",
    "football", "shadow", "superman", "michael", "letmein",
    "trustno1", "starwars", "login", "pass", "passw0rd",
    "baseball", "solo", "access", "mustang", "service",
}

COMMON_PASSWORDS: set[str] = set()


def load_common_passwords() -> set[str]:
    path = Path(settings.common_passwords_path)
    if path.exists():
        words = {line.strip().lower() for line in path.open(encoding="utf-8") if line.strip()}
        logger.info("Loaded %d common passwords from %s", len(words), path)
        return words
    logger.warning("common_passwords.txt not found — using inline fallback (%d entries)", len(_INLINE_COMMON))
    return set(_INLINE_COMMON)


# ─────────────────────────────────────────────
#  HTTP CLIENT  (shared, connection-pooled)
# ─────────────────────────────────────────────
_http_client: httpx.AsyncClient | None = None


# ─────────────────────────────────────────────
#  LIFESPAN
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client, COMMON_PASSWORDS
    COMMON_PASSWORDS = load_common_passwords()
    _http_client = httpx.AsyncClient(
        timeout=settings.hibp_timeout,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        follow_redirects=False,
    )
    logger.info("Sentinel API started — debug=%s", settings.debug)
    yield
    await _http_client.aclose()
    logger.info("Sentinel API shutdown")


# ─────────────────────────────────────────────
#  RATE LIMITER
# ─────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit_global],
)


# ─────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────
app = FastAPI(
    title="Sentinel — Password Audit API",
    version="4.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)

app.state.limiter = limiter


# ─────────────────────────────────────────────
#  SECURITY HEADERS MIDDLEWARE
# ─────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


# ─────────────────────────────────────────────
#  REQUEST-ID / TIMING MIDDLEWARE
# ─────────────────────────────────────────────
class RequestTracingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = str(uuid.uuid4())[:8]
        request.state.request_id = req_id
        t0 = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        response.headers["X-Request-ID"] = req_id
        response.headers["X-Response-Time"] = f"{elapsed_ms:.1f}ms"
        logger.debug("[%s] %s %s → %d  (%.1f ms)", req_id, request.method, request.url.path, response.status_code, elapsed_ms)
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTracingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
    max_age=600,
)


# ─────────────────────────────────────────────
#  MODELS
# ─────────────────────────────────────────────
class PasswordIn(BaseModel):
    password: str = Field(..., min_length=1, max_length=512)

    @field_validator("password")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("Password contains invalid control characters")
        return v


class AuditOut(BaseModel):
    score: int
    status: str
    is_common: bool
    is_pwned: bool
    pwn_count: int
    estimated_entropy_bits: float
    crack_time_online: str
    crack_time_offline: str
    char_classes: dict[str, bool]
    issues: list[str]
    recommendations: list[str]


# ─────────────────────────────────────────────
#  CORE LOGIC
# ─────────────────────────────────────────────

def detect_patterns(password: str) -> list[str]:
    issues: list[str] = []
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated characters detected (e.g. aaa, 111)")
    for seq in ["12345", "23456", "34567", "abcde", "bcdef", "qwerty", "asdfg", "zxcvb"]:
        if seq in password.lower():
            issues.append("Sequential or keyboard-walk pattern detected")
            break
    if re.fullmatch(r"[a-zA-Z]+\d{1,4}", password):
        issues.append("Word + number suffix pattern is easily guessable")
    if re.fullmatch(r"\d+", password):
        issues.append("All-numeric password is very weak")
    return issues


def compute_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d", password):    charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 33
    if charset == 0:
        return 0.0
    return round(len(password) * math.log2(charset), 2)


_SPEED_ONLINE  = 100        # guesses/sec (throttled service)
_SPEED_OFFLINE = 1_000_000_000  # 1B/sec (GPU offline attack on bcrypt-equivalent)

def crack_time_label(bits: float, guesses_per_sec: float) -> str:
    if bits <= 0:
        return "INSTANT"
    seconds = (2 ** bits) / guesses_per_sec
    if not math.isfinite(seconds) or seconds > 3.154e13:  # > 1M years
        return "CENTURIES"
    if seconds < 1:
        return "INSTANT"
    if seconds < 60:
        return f"{int(seconds)} SECS"
    if seconds < 3_600:
        return f"{math.ceil(seconds / 60)} MINS"
    if seconds < 86_400:
        return f"{math.ceil(seconds / 3600)} HOURS"
    if seconds < 31_536_000:
        return f"{math.ceil(seconds / 86400)} DAYS"
    years = seconds / 31_536_000
    if years < 1_000:
        return f"{int(years)} YEARS"
    return "CENTURIES"


def get_char_classes(password: str) -> dict[str, bool]:
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits":    bool(re.search(r"\d", password)),
        "symbols":   bool(re.search(r"[^a-zA-Z0-9]", password)),
    }


def check_strength(password: str) -> tuple[int, str, list[str], list[str]]:
    score = 0
    issues: list[str] = []
    recommendations: list[str] = []

    # Length scoring
    length = len(password)
    if length >= 16:
        score += 2
    elif length >= 12:
        score += 1
    else:
        issues.append(f"Too short ({length} chars)")
        recommendations.append("Use at least 12 characters (16+ is ideal)")

    cc = get_char_classes(password)
    if cc["uppercase"]:  score += 1
    else: recommendations.append("Add uppercase letters (A-Z)")

    if cc["lowercase"]:  score += 1
    else: recommendations.append("Add lowercase letters (a-z)")

    if cc["digits"]:     score += 1
    else: recommendations.append("Add digits (0-9)")

    if cc["symbols"]:    score += 1
    else: recommendations.append("Add special characters (!@#$%…)")

    pattern_issues = detect_patterns(password)
    issues.extend(pattern_issues)
    if pattern_issues:
        score = max(score - 1, 0)

    score = min(score, 6)

    if score >= 5:
        status = "Strong"
    elif score >= 3:
        status = "Moderate"
    else:
        status = "Weak"

    return score, status, issues, recommendations


async def check_pwned(password: str) -> tuple[bool, int]:
    """k-Anonymity check against HIBP — the full password is NEVER sent."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    for attempt in range(settings.hibp_retries + 1):
        try:
            resp = await _http_client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true", "User-Agent": "Sentinel/4.0"},
            )
            resp.raise_for_status()
            for line in resp.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    return True, int(parts[1])
            return False, 0
        except httpx.TimeoutException:
            if attempt < settings.hibp_retries:
                await asyncio.sleep(0.3 * (attempt + 1))
                continue
            logger.warning("HIBP timeout after %d attempts", settings.hibp_retries + 1)
        except httpx.HTTPStatusError as exc:
            logger.warning("HIBP HTTP error: %s", exc.response.status_code)
            break
        except Exception as exc:
            logger.warning("HIBP unexpected error: %s", exc)
            break

    # On failure — degrade gracefully, don't crash the request
    return False, 0


# ─────────────────────────────────────────────
#  ERROR HANDLERS
# ─────────────────────────────────────────────
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "rate_limit_exceeded", "detail": "Too many requests. Please slow down."},
        headers={"Retry-After": "60"},
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "?")
    logger.error("[%s] Unhandled exception: %s", req_id, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": "An unexpected error occurred."},
    )


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("index.html")


@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "version": app.version}


@app.get("/metrics", tags=["ops"])
async def metrics():
    """Stub — wire to Prometheus/OpenTelemetry in production."""
    return {"common_passwords_loaded": len(COMMON_PASSWORDS)}


@app.post("/audit", response_model=AuditOut, tags=["audit"])
@limiter.limit(settings.rate_limit_audit)
async def audit(request: Request, body: PasswordIn):
    pw = body.password

    (score, status, issues, recommendations), (is_pwned, pwn_count) = await asyncio.gather(
        asyncio.to_thread(check_strength, pw),
        check_pwned(pw),
    )

    is_common = pw.lower() in COMMON_PASSWORDS
    if is_common:
        issues.insert(0, "This is a known common password")
        recommendations.insert(0, "Replace with a randomly generated passphrase")
        score = 0
        status = "Weak"

    if is_pwned and not any("breached" in i.lower() or "pwned" in i.lower() for i in issues):
        issues.insert(0, f"Found in {pwn_count:,} known data breach(es)")
        if score > 1:
            score = max(score - 2, 0)

    entropy = compute_entropy(pw)

    return AuditOut(
        score=score,
        status=status,
        is_common=is_common,
        is_pwned=is_pwned,
        pwn_count=pwn_count,
        estimated_entropy_bits=entropy,
        crack_time_online=crack_time_label(entropy, _SPEED_ONLINE),
        crack_time_offline=crack_time_label(entropy, _SPEED_OFFLINE),
        char_classes=get_char_classes(pw),
        issues=issues,
        recommendations=recommendations,
    )


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        access_log=settings.debug,
    )
