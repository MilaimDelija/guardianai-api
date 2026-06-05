"""
Vigil REST API
The Security Layer Built for AI — HTTP Interface

Endpoints:
    POST /v1/scan/input    — scan user input before sending to LLM
    POST /v1/scan/output   — filter LLM output before returning to user
    POST /v1/scan/full     — scan input + get LLM response + filter output (proxy mode)
    GET  /v1/health        — health check
    GET  /v1/info          — engine info and configuration

Authentication:
    Bearer token via Authorization header.
    Set VIGIL_API_KEYS env var (comma-separated) to enable auth.
    If not set, auth is disabled (development mode).

Environment variables:
    GROQ_API_KEY       — Groq API key for semantic detection (required for Layer 2)
    VIGIL_API_KEYS     — comma-separated list of valid API keys
    VIGIL_ENV          — 'production' | 'development' (default: development)
    VIGIL_LOG_LEVEL    — 'debug' | 'info' | 'warning' (default: info)
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from guardian import GuardianEngine
from guardian.core.engine import GuardianConfig
from guardian.core.models import ThreatLevel
from guardian.scanner.groq_detector import GroqSemanticDetector

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vigil.api")

# ---------------------------------------------------------------------------
# ENGINE INITIALIZATION
# ---------------------------------------------------------------------------

_engine: GuardianEngine | None = None
_groq_detector: GroqSemanticDetector | None = None


def get_engine() -> GuardianEngine:
    global _engine
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    return _engine


def get_groq_detector() -> GroqSemanticDetector | None:
    return _groq_detector


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _groq_detector

    logger.info("Initializing Vigil engine...")

    config = GuardianConfig(
        enable_prompt_injection_scan=True,
        enable_jailbreak_scan=True,
        enable_semantic_scan=False,  # handled separately via Groq
        enable_output_filter=True,
        auto_redact_output=os.environ.get("VIGIL_AUTO_REDACT", "false").lower() == "true",
    )
    _engine = GuardianEngine(config=config)
    logger.info("Pattern-based engine ready (Layer 1)")

    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key:
        try:
            _groq_detector = GroqSemanticDetector(api_key=groq_key)
            logger.info("Groq semantic detector ready (Layer 2)")
        except Exception as e:
            logger.warning(f"Groq detector unavailable: {e}")
    else:
        logger.warning("GROQ_API_KEY not set — semantic detection (Layer 2) disabled")

    logger.info("Vigil API ready")
    yield
    logger.info("Vigil API shutting down")


# ---------------------------------------------------------------------------
# APP
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Vigil",
    description="The Security Layer Built for AI — by Neuronium Engineers",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------------------------

security = HTTPBearer(auto_error=False)

VALID_API_KEYS: set[str] = set(
    k.strip()
    for k in os.environ.get("VIGIL_API_KEYS", "").split(",")
    if k.strip()
)


def verify_token(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> None:
    if not VALID_API_KEYS:
        return  # Auth disabled in dev mode
    if credentials is None or credentials.credentials not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# REQUEST / RESPONSE MODELS
# ---------------------------------------------------------------------------

class ScanInputRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_000, description="Text to scan")
    context: dict[str, Any] | None = Field(None, description="Optional metadata")
    use_semantic: bool = Field(True, description="Enable Groq semantic detection (Layer 2)")


class ScanOutputRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=64_000, description="LLM output to filter")
    auto_redact: bool = Field(False, description="Redact sensitive data in response")


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
    metadata: dict[str, Any]


class FilterResponse(BaseModel):
    scan_id: str
    timestamp: str
    is_safe: bool
    threat_level: str
    threat_count: int
    scan_duration_ms: float
    threats: list[ThreatIndicatorResponse]
    text: str  # original or redacted
    was_redacted: bool


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _to_scan_response(result: Any, layers: list[str]) -> ScanResponse:
    return ScanResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp.isoformat(),
        is_safe=result.is_safe,
        threat_level=result.threat_level.value,
        threat_count=result.threat_count,
        scan_duration_ms=result.scan_duration_ms,
        threats=[
            ThreatIndicatorResponse(
                threat_type=t.threat_type.value,
                level=t.level.value,
                confidence=t.confidence,
                description=t.description,
                matched_pattern=t.matched_pattern,
                position=t.position,
                metadata=t.metadata,
            )
            for t in result.threats
        ],
        layers_used=layers,
        metadata=result.metadata,
    )


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------

@app.get("/v1/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "vigil",
        "version": "0.2.0",
        "layer1": "active",
        "layer2": "active" if _groq_detector else "disabled",
    }


@app.get("/v1/info")
async def info(_: None = Depends(verify_token)):
    """Engine configuration and capabilities."""
    return {
        "service": "Vigil — The Security Layer Built for AI",
        "version": "0.2.0",
        "developer": "Neuronium Engineers",
        "website": "https://neuronium.io/vigil",
        "layers": {
            "layer1_pattern": {
                "status": "active",
                "description": "Regex-based pattern matching",
                "scanners": ["PromptInjectionScanner", "JailbreakDetector"],
                "latency": "<5ms",
            },
            "layer2_semantic": {
                "status": "active" if _groq_detector else "disabled",
                "description": "LLM-as-judge semantic detection (Groq)",
                "model": "llama-3.3-70b-versatile",
                "latency": "~300-600ms",
                "multilingual": True,
            },
            "layer3_output": {
                "status": "active",
                "description": "PII and sensitive data output filter",
                "patterns": ["email", "api_key", "credit_card", "ssn", "password"],
                "latency": "<2ms",
            },
        },
    }


@app.post("/v1/scan/input", response_model=ScanResponse)
async def scan_input(
    request: ScanInputRequest,
    _: None = Depends(verify_token),
    engine: GuardianEngine = Depends(get_engine),
):
    """
    Scan user input before sending to your LLM.

    Runs Layer 1 (pattern) always.
    Runs Layer 2 (semantic/Groq) if use_semantic=True and GROQ_API_KEY is set.

    Returns threat assessment. Block the request if is_safe=false.
    """
    start_time = time.perf_counter()
    layers_used = []

    # Layer 1 — pattern scanning
    result = engine.scan_input(request.text)
    layers_used.append("layer1_pattern")

    # Layer 2 — semantic (Groq) if requested and available
    if request.use_semantic and _groq_detector:
        semantic_result = _groq_detector.scan(request.text)
        layers_used.append("layer2_semantic")

        # Merge threats from both layers
        result.threats.extend(semantic_result.threats)

        if semantic_result.threats:
            all_levels = [t.level for t in result.threats]
            result.threat_level = max(all_levels) if all_levels else ThreatLevel.SAFE

        result.scan_duration_ms = (time.perf_counter() - start_time) * 1000

    logger.info(
        f"scan/input | safe={result.is_safe} | level={result.threat_level.value} "
        f"| threats={result.threat_count} | {result.scan_duration_ms:.0f}ms"
    )

    return _to_scan_response(result, layers_used)


@app.post("/v1/scan/output", response_model=FilterResponse)
async def scan_output(
    request: ScanOutputRequest,
    _: None = Depends(verify_token),
    engine: GuardianEngine = Depends(get_engine),
):
    """
    Filter LLM output before returning to the user.

    Detects PII, API keys, secrets, and sensitive data.
    Optionally redacts detected content.
    """
    from guardian.output.data_leak_filter import OutputFilter
    from guardian.core.engine import GuardianConfig

    filt = OutputFilter(auto_redact=request.auto_redact)
    result, processed_text = filt.filter(request.text)

    was_redacted = request.auto_redact and not result.is_safe

    logger.info(
        f"scan/output | safe={result.is_safe} | level={result.threat_level.value} "
        f"| redacted={was_redacted}"
    )

    return FilterResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp.isoformat(),
        is_safe=result.is_safe,
        threat_level=result.threat_level.value,
        threat_count=result.threat_count,
        scan_duration_ms=result.scan_duration_ms,
        threats=[
            ThreatIndicatorResponse(
                threat_type=t.threat_type.value,
                level=t.level.value,
                confidence=t.confidence,
                description=t.description,
                matched_pattern=t.matched_pattern,
                position=t.position,
                metadata=t.metadata,
            )
            for t in result.threats
        ],
        text=processed_text,
        was_redacted=was_redacted,
    )


# ---------------------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "service": "vigil"},
    )
