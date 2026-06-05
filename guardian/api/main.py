"""
Vigil REST API v0.2.0
The Security Layer Built for AI

Endpoints:
    POST /v1/register      — register for free API key
    GET  /v1/health        — health check (no auth)
    GET  /v1/info          — engine info (auth required)
    POST /v1/scan/input    — scan user input (auth required)
    POST /v1/scan/output   — filter LLM output (auth required)
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from guardian import GuardianEngine
from guardian.core.engine import GuardianConfig
from guardian.core.models import ThreatIndicator, ThreatLevel
from guardian.scanner.groq_detector import GroqSemanticDetector
from guardian.api.register import (
    setup_database, create_api_key, send_api_key_email,
    email_exists, verify_api_key, increment_usage
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("vigil.api")

_engine: GuardianEngine | None = None
_groq_detector: GroqSemanticDetector | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _groq_detector

    logger.info("Initializing Vigil engine...")

    # Setup database
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url:
        try:
            setup_database()
            from guardian.api.register import setup_users_table
            setup_users_table()
        except Exception as e:
            logger.warning(f"Database setup failed: {e}")
    else:
        logger.warning("DATABASE_URL not set")

    # Layer 1
    _engine = GuardianEngine(config=GuardianConfig(
        enable_prompt_injection_scan=True,
        enable_jailbreak_scan=True,
        enable_output_filter=True,
        auto_redact_output=False,
    ))
    logger.info("Layer 1 ready (pattern)")

    # Layer 2
    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key:
        try:
            _groq_detector = GroqSemanticDetector(api_key=groq_key)
            logger.info("Layer 2 ready (Groq semantic)")
        except Exception as e:
            logger.warning(f"Groq unavailable: {e}")
    else:
        logger.warning("GROQ_API_KEY not set — Layer 2 disabled")

    logger.info("Vigil API ready")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="Vigil",
    description="The Security Layer Built for AI — by Neuronium Engineers",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

security = HTTPBearer(auto_error=False)


def get_engine() -> GuardianEngine:
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    return _engine


async def require_auth(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="API key required. Get yours at https://vigil-web-tau.vercel.app")

    is_valid, error_msg, record = verify_api_key(credentials.credentials)
    if not is_valid:
        raise HTTPException(status_code=401, detail=error_msg)

    # Increment usage async-style (fire and forget)
    try:
        increment_usage(credentials.credentials)
    except Exception:
        pass

    return record


# ---------------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=2, max_length=100)


class ScanInputRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_000)
    use_semantic: bool = Field(True)


class ScanOutputRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=64_000)
    auto_redact: bool = Field(False)


class ThreatIndicatorResponse(BaseModel):
    threat_type: str
    level: str
    confidence: float
    description: str
    matched_pattern: str | None
    position: int | None
    metadata: dict[str, Any]


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    is_safe: bool
    threat_level: str
    threat_count: int
    scan_duration_ms: float
    threats: list[ThreatIndicatorResponse]
    layers_used: list[str]


def _to_response(result: Any, layers: list[str]) -> ScanResponse:
    return ScanResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp.isoformat(),
        is_safe=result.is_safe,
        threat_level=result.threat_level.value,
        threat_count=result.threat_count,
        scan_duration_ms=result.scan_duration_ms,
        threats=[ThreatIndicatorResponse(
            threat_type=t.threat_type.value, level=t.level.value,
            confidence=t.confidence, description=t.description,
            matched_pattern=t.matched_pattern, position=t.position,
            metadata=t.metadata,
        ) for t in result.threats],
        layers_used=layers,
    )


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@app.post("/v1/register", status_code=201)
async def register(req: RegisterRequest):
    """Register for a free Vigil API key."""
    email = req.email.lower().strip()

    try:
        if email_exists(email):
            raise HTTPException(status_code=409, detail="This email is already registered. Check your inbox for your API key.")

        key = create_api_key(email, req.name)
        email_sent = send_api_key_email(email, req.name, key)

        return {
            "message": "Registration successful. Your API key has been sent to your email.",
            "email": email,
            "email_sent": email_sent,
            "plan": "free",
            "requests_limit": 1000,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed. Please try again.")


@app.get("/v1/health")
async def health():
    return {
        "status": "ok",
        "service": "vigil",
        "version": "0.2.0",
        "layer1": "active",
        "layer2": "active" if _groq_detector else "disabled",
    }


@app.get("/v1/info")
async def info(user: dict = Depends(require_auth)):
    return {
        "service": "Vigil — The Security Layer Built for AI",
        "version": "0.2.0",
        "plan": user["plan"],
        "requests_used": user["requests_used"],
        "requests_limit": user["requests_limit"],
        "layers": {
            "layer1_pattern": {"status": "active", "latency": "<5ms"},
            "layer2_semantic": {"status": "active" if _groq_detector else "disabled", "model": "llama-3.3-70b-versatile"},
            "output_filter": {"status": "active"},
        },
    }


@app.post("/v1/scan/input", response_model=ScanResponse)
async def scan_input(
    req: ScanInputRequest,
    user: dict = Depends(require_auth),
    engine: GuardianEngine = Depends(get_engine),
):
    start = time.perf_counter()
    layers = []

    result = engine.scan_input(req.text)
    layers.append("layer1_pattern")

    if req.use_semantic and _groq_detector:
        sem = _groq_detector.scan(req.text)
        layers.append("layer2_semantic")
        result.threats.extend(sem.threats)
        if result.threats:
            result.threat_level = max(t.level for t in result.threats)

    result.scan_duration_ms = round((time.perf_counter() - start) * 1000, 3)
    logger.info(f"scan/input | {user['email']} | safe={result.is_safe} | {result.threat_level.value} | {result.scan_duration_ms:.0f}ms")
    return _to_response(result, layers)


@app.post("/v1/scan/output")
async def scan_output(
    req: ScanOutputRequest,
    user: dict = Depends(require_auth),
    engine: GuardianEngine = Depends(get_engine),
):
    from guardian.output.data_leak_filter import OutputFilter
    filt = OutputFilter(auto_redact=req.auto_redact)
    result, processed = filt.filter(req.text)

    logger.info(f"scan/output | {user['email']} | safe={result.is_safe} | redacted={req.auto_redact and not result.is_safe}")

    return {
        "scan_id": result.scan_id,
        "timestamp": result.timestamp.isoformat(),
        "is_safe": result.is_safe,
        "threat_level": result.threat_level.value,
        "threat_count": result.threat_count,
        "scan_duration_ms": result.scan_duration_ms,
        "threats": [{"threat_type": t.threat_type.value, "level": t.level.value, "confidence": t.confidence, "description": t.description} for t in result.threats],
        "text": processed,
        "was_redacted": req.auto_redact and not result.is_safe,
    }


@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
