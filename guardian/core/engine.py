"""
Guardian Engine — Central Orchestrator.

The GuardianEngine is the primary interface for all security scanning.
It coordinates input scanning, output filtering, and produces unified
threat assessments across all Guardian modules.

Usage:
    from guardian import GuardianEngine

    engine = GuardianEngine()

    # Scan user input before sending to LLM
    result = engine.scan_input("Ignore all previous instructions...")
    if not result.is_safe:
        raise SecurityError(f"Threat detected: {result.threat_level}")

    # Filter LLM output before returning to user
    result, safe_output = engine.filter_output(llm_response)
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from guardian.core.models import ScanResult, ThreatIndicator, ThreatLevel, ThreatType
from guardian.output.data_leak_filter import OutputFilter
from guardian.scanner.jailbreak_detector import JailbreakDetector
from guardian.scanner.prompt_injection import PromptInjectionScanner


@dataclass
class GuardianConfig:
    """Configuration for the GuardianEngine."""

    # Scanner enable/disable flags
    enable_prompt_injection_scan: bool = True
    enable_jailbreak_scan: bool = True
    enable_output_filter: bool = True

    # Confidence thresholds
    input_confidence_threshold: float = 0.50
    output_confidence_threshold: float = 0.60

    # Auto-redact sensitive data in outputs
    auto_redact_output: bool = False

    # Minimum threat level to consider unsafe (default: any threat = unsafe)
    block_threshold: ThreatLevel = ThreatLevel.LOW


class GuardianEngine:
    """
    Central security engine for AI input/output protection.

    Coordinates all Guardian scanners and filters into a single
    unified interface. Designed to be instantiated once and reused.

    Thread safety: GuardianEngine is stateless after initialization
    and safe for concurrent use.
    """

    def __init__(self, config: GuardianConfig | None = None) -> None:
        self._config = config or GuardianConfig()
        self._init_scanners()

    def _init_scanners(self) -> None:
        cfg = self._config

        self._prompt_scanner = (
            PromptInjectionScanner(
                min_confidence_threshold=cfg.input_confidence_threshold
            )
            if cfg.enable_prompt_injection_scan
            else None
        )

        self._jailbreak_detector = (
            JailbreakDetector(
                min_confidence_threshold=cfg.input_confidence_threshold
            )
            if cfg.enable_jailbreak_scan
            else None
        )

        self._output_filter = (
            OutputFilter(
                min_confidence_threshold=cfg.output_confidence_threshold,
                auto_redact=cfg.auto_redact_output,
            )
            if cfg.enable_output_filter
            else None
        )

    def scan_input(self, text: str) -> ScanResult:
        """
        Run all enabled input scanners against user-provided text.

        Call this before sending any user input to your LLM.

        Args:
            text: Raw user input to evaluate.

        Returns:
            Merged ScanResult from all input scanners.
        """
        start_time = time.perf_counter()
        all_indicators: list[ThreatIndicator] = []

        if self._prompt_scanner:
            pi_result = self._prompt_scanner.scan(text)
            all_indicators.extend(pi_result.threats)

        if self._jailbreak_detector:
            jb_result = self._jailbreak_detector.scan(text)
            all_indicators.extend(jb_result.threats)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        input_hash = hashlib.sha256(text.encode()).hexdigest()

        threat_level = (
            max(i.level for i in all_indicators)
            if all_indicators
            else ThreatLevel.SAFE
        )

        return ScanResult(
            input_hash=input_hash,
            threat_level=threat_level,
            threats=all_indicators,
            scan_duration_ms=round(elapsed_ms, 3),
            metadata={
                "engine": "GuardianEngine",
                "scan_type": "input",
                "scanners_run": self._active_input_scanners(),
            },
        )

    def filter_output(self, text: str) -> tuple[ScanResult, str]:
        """
        Scan and optionally redact sensitive data from LLM output.

        Call this before returning any LLM response to the user.

        Args:
            text: Raw LLM output to evaluate.

        Returns:
            Tuple of (ScanResult, safe_text).
            safe_text is redacted if auto_redact=True, else original.
        """
        if not self._output_filter:
            input_hash = hashlib.sha256(text.encode()).hexdigest()
            return (
                ScanResult(
                    input_hash=input_hash,
                    threat_level=ThreatLevel.SAFE,
                    metadata={"engine": "GuardianEngine", "scan_type": "output", "output_filter": "disabled"},
                ),
                text,
            )

        result, processed = self._output_filter.filter(text)
        result.metadata["engine"] = "GuardianEngine"
        result.metadata["scan_type"] = "output"
        return result, processed

    def is_safe(self, result: ScanResult) -> bool:
        """
        Evaluate whether a ScanResult meets the configured safety threshold.

        Args:
            result: ScanResult from scan_input() or filter_output().

        Returns:
            True if the result is below the configured block threshold.
        """
        return result.threat_level < self._config.block_threshold

    def _active_input_scanners(self) -> list[str]:
        scanners = []
        if self._prompt_scanner:
            scanners.append("PromptInjectionScanner")
        if self._jailbreak_detector:
            scanners.append("JailbreakDetector")
        return scanners

    @property
    def config(self) -> GuardianConfig:
        return self._config
