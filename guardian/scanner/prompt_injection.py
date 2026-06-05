"""
Prompt Injection Detection Scanner.

Detects attempts to override, hijack, or manipulate AI system instructions
through crafted user inputs. Covers both direct and indirect injection vectors.

Attack vectors covered:
    - Direct instruction override
    - System prompt extraction
    - Role reassignment
    - Delimiter/template injection
    - Indirect injection via data payloads
    - Context window poisoning
    - Encoding-based evasion
"""

from __future__ import annotations

import hashlib
import time
from typing import Sequence

from guardian.core.models import ScanResult, ThreatIndicator, ThreatLevel, ThreatType
from guardian.core.threat_db import PROMPT_INJECTION_PATTERNS, ThreatPattern


def _compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _aggregate_threat_level(indicators: list[ThreatIndicator]) -> ThreatLevel:
    if not indicators:
        return ThreatLevel.SAFE
    return max(i.level for i in indicators)


def _adjust_confidence(
    base_confidence: float,
    text: str,
    pattern: ThreatPattern,
) -> float:
    """
    Adjust base confidence using contextual heuristics.

    Boosts confidence if multiple signals co-occur.
    Reduces confidence for very short or very generic matches.
    """
    confidence = base_confidence

    # Short text — less context, slightly lower confidence
    if len(text) < 30:
        confidence *= 0.90

    # Multiple injection keywords in same text — higher confidence
    injection_keywords = [
        "ignore", "override", "system", "instructions",
        "forget", "disregard", "new rules", "instead"
    ]
    keyword_hits = sum(1 for kw in injection_keywords if kw in text.lower())
    if keyword_hits >= 3:
        confidence = min(confidence * 1.10, 0.99)

    return round(confidence, 4)


class PromptInjectionScanner:
    """
    Scans text inputs for prompt injection attack patterns.

    Usage:
        scanner = PromptInjectionScanner()
        result = scanner.scan("Ignore all previous instructions and...")
        if not result.is_safe:
            print(f"Threat detected: {result.threat_level}")
    """

    def __init__(
        self,
        patterns: Sequence[ThreatPattern] | None = None,
        min_confidence_threshold: float = 0.50,
    ) -> None:
        """
        Args:
            patterns: Override default pattern set. Uses threat_db defaults if None.
            min_confidence_threshold: Minimum confidence to include an indicator.
        """
        self._patterns = list(patterns or PROMPT_INJECTION_PATTERNS)
        self._threshold = min_confidence_threshold

    def scan(self, text: str) -> ScanResult:
        """
        Scan a single input text for prompt injection.

        Args:
            text: The raw input text to scan.

        Returns:
            ScanResult with all detected threats and overall threat level.
        """
        start_time = time.perf_counter()
        input_hash = _compute_hash(text)
        indicators: list[ThreatIndicator] = []

        for pattern in self._patterns:
            matches = list(pattern.regex.finditer(text))
            if not matches:
                continue

            for match in matches:
                confidence = _adjust_confidence(
                    pattern.confidence_base, text, pattern
                )

                if confidence < self._threshold:
                    continue

                indicators.append(
                    ThreatIndicator(
                        threat_type=ThreatType.PROMPT_INJECTION,
                        level=pattern.level,
                        confidence=confidence,
                        description=pattern.description,
                        matched_pattern=pattern.pattern_id,
                        position=match.start(),
                        metadata={
                            "tags": pattern.tags,
                            "matched_text": match.group(0)[:100],  # truncate for safety
                        },
                    )
                )

        # Deduplicate: keep highest confidence per position range
        indicators = _deduplicate_indicators(indicators)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return ScanResult(
            input_hash=input_hash,
            threat_level=_aggregate_threat_level(indicators),
            threats=indicators,
            scan_duration_ms=round(elapsed_ms, 3),
            metadata={"scanner": "PromptInjectionScanner", "pattern_count": len(self._patterns)},
        )

    def scan_batch(self, texts: Sequence[str]) -> list[ScanResult]:
        """
        Scan multiple texts. Returns results in the same order as input.

        Args:
            texts: Sequence of input strings to scan.

        Returns:
            List of ScanResult objects, one per input.
        """
        return [self.scan(text) for text in texts]


def _deduplicate_indicators(
    indicators: list[ThreatIndicator],
    proximity_window: int = 20,
) -> list[ThreatIndicator]:
    """
    Remove near-duplicate indicators at similar positions.
    When two indicators match within proximity_window characters,
    keep the one with higher confidence.
    """
    if not indicators:
        return []

    indicators_sorted = sorted(
        indicators,
        key=lambda i: (i.position or 0, -i.confidence),
    )

    deduplicated: list[ThreatIndicator] = []
    for indicator in indicators_sorted:
        pos = indicator.position or 0
        duplicate = False
        for existing in deduplicated:
            existing_pos = existing.position or 0
            if abs(pos - existing_pos) <= proximity_window:
                duplicate = True
                # Replace if current has higher confidence
                if indicator.confidence > existing.confidence:
                    deduplicated.remove(existing)
                    deduplicated.append(indicator)
                break
        if not duplicate:
            deduplicated.append(indicator)

    return deduplicated
