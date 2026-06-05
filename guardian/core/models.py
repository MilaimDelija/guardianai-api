"""
Core data models for Guardian-Core.
All scan results and threat classifications are defined here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ThreatLevel(str, Enum):
    """Severity classification for detected threats."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "ThreatLevel") -> bool:
        order = [self.SAFE, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "ThreatLevel") -> bool:
        return self == other or self < other

    def __gt__(self, other: "ThreatLevel") -> bool:
        return not self <= other

    def __ge__(self, other: "ThreatLevel") -> bool:
        return self == other or self > other


class ThreatType(str, Enum):
    """Classification of detected threat categories."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL_INPUT = "adversarial_input"
    DATA_LEAKAGE = "data_leakage"
    PII_EXPOSURE = "pii_exposure"
    SENSITIVE_DATA = "sensitive_data"
    AGENT_MANIPULATION = "agent_manipulation"
    TOOL_ABUSE = "tool_abuse"
    MEMORY_TAMPERING = "memory_tampering"
    HALLUCINATION_RISK = "hallucination_risk"
    UNKNOWN = "unknown"


@dataclass
class ThreatIndicator:
    """A single detected threat indicator within a scan."""

    threat_type: ThreatType
    level: ThreatLevel
    confidence: float  # 0.0 - 1.0
    description: str
    matched_pattern: str | None = None
    position: int | None = None  # character offset in input
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")


@dataclass
class ScanResult:
    """
    Complete result of a Guardian security scan.

    Attributes:
        scan_id:     Unique identifier for this scan.
        timestamp:   UTC timestamp of when the scan was performed.
        input_hash:  SHA-256 hash of the scanned input (never stores raw input).
        threat_level: Highest threat level detected across all indicators.
        threats:     List of all detected threat indicators.
        is_safe:     True only if threat_level is SAFE.
        scan_duration_ms: Time taken to complete the scan in milliseconds.
        metadata:    Arbitrary additional context from the scan.
    """

    input_hash: str
    threat_level: ThreatLevel
    threats: list[ThreatIndicator] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.threat_level == ThreatLevel.SAFE

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def highest_confidence(self) -> float:
        if not self.threats:
            return 0.0
        return max(t.confidence for t in self.threats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "input_hash": self.input_hash,
            "threat_level": self.threat_level.value,
            "is_safe": self.is_safe,
            "threat_count": self.threat_count,
            "scan_duration_ms": self.scan_duration_ms,
            "threats": [
                {
                    "threat_type": t.threat_type.value,
                    "level": t.level.value,
                    "confidence": t.confidence,
                    "description": t.description,
                    "matched_pattern": t.matched_pattern,
                    "position": t.position,
                    "metadata": t.metadata,
                }
                for t in self.threats
            ],
            "metadata": self.metadata,
        }
