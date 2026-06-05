"""
Output Security Filter.

Scans AI model outputs before delivery to the end user.
Prevents accidental or malicious leakage of:
    - Personally Identifiable Information (PII)
    - API keys, tokens, secrets
    - Credit card and financial data
    - System internals and credentials
    - Sensitive configuration data

This module operates on AI outputs, not inputs.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Sequence

from guardian.core.models import ScanResult, ThreatIndicator, ThreatLevel, ThreatType
from guardian.core.threat_db import PII_PATTERNS, SENSITIVE_DATA_PATTERNS, ThreatPattern


def _compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _aggregate_threat_level(indicators: list[ThreatIndicator]) -> ThreatLevel:
    if not indicators:
        return ThreatLevel.SAFE
    return max(i.level for i in indicators)


def _redact(text: str, match_start: int, match_end: int) -> str:
    """Replace a matched sensitive region with [REDACTED]."""
    return text[:match_start] + "[REDACTED]" + text[match_end:]


class OutputFilter:
    """
    Scans and optionally redacts sensitive data from AI outputs.

    Usage:
        filt = OutputFilter(auto_redact=True)
        result, clean_output = filt.filter("Your API key is sk-abc123xyz...")
        if not result.is_safe:
            print("Sensitive data detected and redacted")
            print(clean_output)
    """

    def __init__(
        self,
        patterns: Sequence[ThreatPattern] | None = None,
        min_confidence_threshold: float = 0.60,
        auto_redact: bool = False,
    ) -> None:
        """
        Args:
            patterns: Override default PII + sensitive data patterns.
            min_confidence_threshold: Minimum confidence to flag an indicator.
            auto_redact: If True, filter() returns redacted text as second value.
        """
        self._patterns = list(patterns or (PII_PATTERNS + SENSITIVE_DATA_PATTERNS))
        self._threshold = min_confidence_threshold
        self._auto_redact = auto_redact

    def scan(self, text: str) -> ScanResult:
        """
        Scan output text for sensitive data leakage.

        Args:
            text: AI-generated output text to evaluate.

        Returns:
            ScanResult with detected PII and sensitive data indicators.
        """
        start_time = time.perf_counter()
        input_hash = _compute_hash(text)
        indicators: list[ThreatIndicator] = []

        for pattern in self._patterns:
            matches = list(pattern.regex.finditer(text))
            if not matches:
                continue

            for match in matches:
                confidence = pattern.confidence_base

                # Phone pattern is noisy — require minimum digit density
                if pattern.pattern_id == "PII-002":
                    digits = sum(c.isdigit() for c in match.group(0))
                    if digits < 7:
                        continue
                    confidence *= 0.85

                if confidence < self._threshold:
                    continue

                indicators.append(
                    ThreatIndicator(
                        threat_type=pattern.threat_type,
                        level=pattern.level,
                        confidence=round(confidence, 4),
                        description=pattern.description,
                        matched_pattern=pattern.pattern_id,
                        position=match.start(),
                        metadata={
                            "tags": pattern.tags,
                            "match_length": match.end() - match.start(),
                        },
                    )
                )

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            input_hash=input_hash,
            threat_level=_aggregate_threat_level(indicators),
            threats=indicators,
            scan_duration_ms=round(elapsed_ms, 3),
            metadata={
                "scanner": "OutputFilter",
                "auto_redact": self._auto_redact,
                "pattern_count": len(self._patterns),
            },
        )

    def filter(self, text: str) -> tuple[ScanResult, str]:
        """
        Scan and optionally redact sensitive data from output.

        Args:
            text: AI-generated output to evaluate.

        Returns:
            Tuple of (ScanResult, processed_text).
            If auto_redact=True, processed_text has sensitive data replaced.
            If auto_redact=False, processed_text is unchanged original.
        """
        result = self.scan(text)

        if not self._auto_redact or result.is_safe:
            return result, text

        # Apply redactions in reverse order to preserve positions
        redacted = text
        sorted_threats = sorted(
            result.threats,
            key=lambda t: t.position or 0,
            reverse=True,
        )

        for threat in sorted_threats:
            if threat.position is None:
                continue
            match_len = threat.metadata.get("match_length", 0)
            if match_len > 0:
                redacted = _redact(redacted, threat.position, threat.position + match_len)

        return result, redacted
