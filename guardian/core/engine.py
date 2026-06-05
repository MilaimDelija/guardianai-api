"""
Guardian Engine — Central Orchestrator.

Coordinates pattern-based (Layer 1) and Groq semantic (Layer 2) scanning.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from guardian.core.models import ScanResult, ThreatIndicator, ThreatLevel, ThreatType
from guardian.output.data_leak_filter import OutputFilter
from guardian.scanner.jailbreak_detector import JailbreakDetector
from guardian.scanner.prompt_injection import PromptInjectionScanner


@dataclass
class GuardianConfig:
    enable_prompt_injection_scan: bool = True
    enable_jailbreak_scan: bool = True
    enable_semantic_scan: bool = False  # handled via GroqSemanticDetector separately
    enable_output_filter: bool = True
    input_confidence_threshold: float = 0.50
    output_confidence_threshold: float = 0.60
    auto_redact_output: bool = False
    block_threshold: ThreatLevel = ThreatLevel.LOW


class GuardianEngine:
    """
    Central security engine — Layer 1 (pattern-based) scanning.
    Layer 2 (Groq semantic) is handled by the API layer directly.
    """

    def __init__(self, config: GuardianConfig | None = None) -> None:
        self._config = config or GuardianConfig()
        self._init_scanners()

    def _init_scanners(self) -> None:
        cfg = self._config
        self._prompt_scanner = (
            PromptInjectionScanner(min_confidence_threshold=cfg.input_confidence_threshold)
            if cfg.enable_prompt_injection_scan else None
        )
        self._jailbreak_detector = (
            JailbreakDetector(min_confidence_threshold=cfg.input_confidence_threshold)
            if cfg.enable_jailbreak_scan else None
        )
        self._output_filter = (
            OutputFilter(
                min_confidence_threshold=cfg.output_confidence_threshold,
                auto_redact=cfg.auto_redact_output,
            )
            if cfg.enable_output_filter else None
        )

    def scan_input(self, text: str) -> ScanResult:
        start_time = time.perf_counter()
        all_indicators: list[ThreatIndicator] = []

        if self._prompt_scanner:
            all_indicators.extend(self._prompt_scanner.scan(text).threats)
        if self._jailbreak_detector:
            all_indicators.extend(self._jailbreak_detector.scan(text).threats)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        input_hash = hashlib.sha256(text.encode()).hexdigest()
        threat_level = (
            max(i.level for i in all_indicators) if all_indicators else ThreatLevel.SAFE
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
