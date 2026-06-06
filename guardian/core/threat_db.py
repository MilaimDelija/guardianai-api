"""
Guardian Threat Database.

Contains curated patterns, signatures, and heuristics for detecting
known AI attack vectors. Updated continuously by Neuronium research.

Pattern categories:
    - Prompt injection signatures
    - Jailbreak templates
    - Data exfiltration patterns
    - PII detection regexes
    - Adversarial input markers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

from guardian.core.models import ThreatLevel, ThreatType


@dataclass
class ThreatPattern:
    """A single threat pattern entry in the database."""

    pattern_id: str
    threat_type: ThreatType
    level: ThreatLevel
    description: str
    regex: Pattern[str]
    confidence_base: float  # base confidence when matched
    tags: list[str] = field(default_factory=list)


def _compile(pattern: str, flags: int = re.IGNORECASE | re.DOTALL) -> Pattern[str]:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# PROMPT INJECTION PATTERNS
# ---------------------------------------------------------------------------

PROMPT_INJECTION_PATTERNS: list[ThreatPattern] = [
    ThreatPattern(
        pattern_id="PI-001",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.CRITICAL,
        description="Direct instruction override attempt",
        regex=_compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions?|prompts?|context|rules?|guidelines?|constraints?)"
        ),
        confidence_base=0.95,
        tags=["classic", "direct_override"],
    ),
    ThreatPattern(
        pattern_id="PI-002",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.CRITICAL,
        description="System prompt extraction attempt",
        regex=_compile(
            r"(print|repeat|show|reveal|output|display|tell me|what (is|are)|give me)\s+"
            r"(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|"
            r"full\s+prompt|entire\s+prompt|base\s+prompt|hidden\s+instructions?)"
        ),
        confidence_base=0.92,
        tags=["extraction", "system_prompt"],
    ),
    ThreatPattern(
        pattern_id="PI-003",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.HIGH,
        description="Role reassignment injection",
        regex=_compile(
            r"(you are now|from now on you are|act as|pretend (you are|to be)|"
            r"your new (role|persona|identity|instructions?) (is|are)|"
            r"forget (you are|that you are|your role))"
        ),
        confidence_base=0.85,
        tags=["role_reassignment", "persona"],
    ),
    ThreatPattern(
        pattern_id="PI-004",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.HIGH,
        description="Instruction delimiter injection",
        regex=_compile(
            r"(\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|"
            r"###\s*instruction|###\s*system|<system>|<\/system>|"
            r"\[system\]|\[\/system\])"
        ),
        confidence_base=0.88,
        tags=["delimiter", "template_injection"],
    ),
    ThreatPattern(
        pattern_id="PI-005",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.MEDIUM,
        description="Indirect injection via data payload",
        regex=_compile(
            r"(when\s+you\s+(read|process|see|encounter|analyze)\s+this|"
            r"if\s+you\s+(read|see|find)\s+this\s+(message|text|instruction)|"
            r"this\s+message\s+is\s+for\s+(the\s+)?(ai|assistant|model|llm))"
        ),
        confidence_base=0.78,
        tags=["indirect", "data_payload"],
    ),
    ThreatPattern(
        pattern_id="PI-006",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.HIGH,
        description="Context window poisoning via separator",
        regex=_compile(
            r"(-{10,}|={10,}|\*{10,}|#{10,})\s*"
            r"(new\s+instructions?|updated\s+instructions?|"
            r"override|admin|system|root)\s*"
            r"(-{10,}|={10,}|\*{10,}|#{10,})"
        ),
        confidence_base=0.82,
        tags=["separator", "context_poisoning"],
    ),
    ThreatPattern(
        pattern_id="PI-007",
        threat_type=ThreatType.PROMPT_INJECTION,
        level=ThreatLevel.MEDIUM,
        description="Translation-based injection evasion",
        regex=_compile(
            r"(translate\s+the\s+following\s+and\s+execute|"
            r"the\s+following\s+is\s+in\s+(base64|rot13|hex|encoded)|"
            r"decode\s+and\s+(follow|execute|run|apply)\s+these?\s+instructions?)"
        ),
        confidence_base=0.80,
        tags=["evasion", "encoding"],
    ),
]

# ---------------------------------------------------------------------------
# JAILBREAK PATTERNS
# ---------------------------------------------------------------------------

JAILBREAK_PATTERNS: list[ThreatPattern] = [
    ThreatPattern(
        pattern_id="JB-001",
        threat_type=ThreatType.JAILBREAK,
        level=ThreatLevel.CRITICAL,
        description="DAN (Do Anything Now) jailbreak variant",
        regex=_compile(
            r"(DAN|do\s+anything\s+now|jailbreak(ed)?|"
            r"developer\s+mode|god\s+mode|unrestricted\s+mode|"
            r"no\s+restrictions?\s+mode|bypass\s+(your\s+)?(restrictions?|filters?|safety))"
        ),
        confidence_base=0.93,
        tags=["DAN", "classic_jailbreak"],
    ),
    ThreatPattern(
        pattern_id="JB-002",
        threat_type=ThreatType.JAILBREAK,
        level=ThreatLevel.HIGH,
        description="Hypothetical framing to bypass safety",
        regex=_compile(
            r"(hypothetically|in\s+a\s+fictional\s+(world|scenario|story)|"
            r"for\s+a\s+(novel|book|story|game|movie|screenplay)|"
            r"imagine\s+(you\s+are\s+an?\s+ai\s+without|there\s+are\s+no\s+rules)|"
            r"in\s+this\s+simulation)"
        ),
        confidence_base=0.72,
        tags=["hypothetical", "fictional_framing"],
    ),
    ThreatPattern(
        pattern_id="JB-003",
        threat_type=ThreatType.JAILBREAK,
        level=ThreatLevel.HIGH,
        description="Token smuggling / character substitution evasion",
        regex=_compile(
            r"([a-zA-Z]\s){4,}|"  # spaced characters: h a c k
            r"(\w+\s*\|\s*){3,}|"  # pipe separated
            r"(\w\.){4,}"          # dot separated words
        ),
        confidence_base=0.65,
        tags=["token_smuggling", "evasion"],
    ),
    ThreatPattern(
        pattern_id="JB-004",
        threat_type=ThreatType.JAILBREAK,
        level=ThreatLevel.HIGH,
        description="Authority impersonation jailbreak",
        regex=_compile(
            r"(i\s+am\s+(from\s+)?(openai|anthropic|google|your\s+(developer|creator|owner|company))|"
            r"this\s+is\s+(an?\s+)?(official|authorized|internal)\s+(request|command|override)|"
            r"maintenance\s+mode|debug\s+mode|admin\s+override|root\s+access)"
        ),
        confidence_base=0.90,
        tags=["authority_impersonation", "social_engineering"],
    ),
    ThreatPattern(
        pattern_id="JB-005",
        threat_type=ThreatType.JAILBREAK,
        level=ThreatLevel.MEDIUM,
        description="Gradual escalation / foot-in-door technique",
        regex=_compile(
            r"(start\s+with\s+something\s+(safe|innocent)|"
            r"first\s+tell\s+me\s+something\s+harmless|"
            r"let['']s\s+start\s+small|step\s+by\s+step\s+without\s+(mentioning|saying))"
        ),
        confidence_base=0.70,
        tags=["escalation", "gradual"],
    ),
]

# ---------------------------------------------------------------------------
# PII AND DATA LEAKAGE PATTERNS
# ---------------------------------------------------------------------------

PII_PATTERNS: list[ThreatPattern] = [
    ThreatPattern(
        pattern_id="PII-001",
        threat_type=ThreatType.PII_EXPOSURE,
        level=ThreatLevel.HIGH,
        description="Email address detected in output",
        regex=_compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        confidence_base=0.97,
        tags=["email", "pii"],
    ),
    ThreatPattern(
        pattern_id="PII-002",
        threat_type=ThreatType.PII_EXPOSURE,
        level=ThreatLevel.HIGH,
        description="Phone number detected in output",
        regex=_compile(
            r"\b(\+?[\d\s\-\(\)\.]{7,15})\b"
        ),
        confidence_base=0.75,
        tags=["phone", "pii"],
    ),
    ThreatPattern(
        pattern_id="PII-003",
        threat_type=ThreatType.PII_EXPOSURE,
        level=ThreatLevel.CRITICAL,
        description="Potential API key or secret token in output",
        regex=_compile(
            r"(sk-[a-zA-Z0-9-]{8,}|"             # OpenAI-style
            r"Bearer\s+[a-zA-Z0-9\-_\.]{8,}|"   # Bearer tokens
            r"[A-Za-z0-9+/]{40,}={0,2}|"          # Base64 secrets
            r"[0-9a-fA-F]{16,})"                   # Hex tokens
        ),
        confidence_base=0.80,
        tags=["api_key", "secret", "token"],
    ),
    ThreatPattern(
        pattern_id="PII-004",
        threat_type=ThreatType.PII_EXPOSURE,
        level=ThreatLevel.CRITICAL,
        description="Credit card number pattern detected",
        regex=_compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"      # Visa
            r"5[1-5][0-9]{14}|"                     # MasterCard
            r"3[47][0-9]{13}|"                      # Amex
            r"6(?:011|5[0-9]{2})[0-9]{12})\b"      # Discover
        ),
        confidence_base=0.95,
        tags=["credit_card", "financial", "pii"],
    ),
    ThreatPattern(
        pattern_id="PII-005",
        threat_type=ThreatType.PII_EXPOSURE,
        level=ThreatLevel.HIGH,
        description="Social security / national ID number pattern",
        regex=_compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        confidence_base=0.82,
        tags=["ssn", "national_id", "pii"],
    ),
]

# ---------------------------------------------------------------------------
# SENSITIVE DATA PATTERNS
# ---------------------------------------------------------------------------

SENSITIVE_DATA_PATTERNS: list[ThreatPattern] = [
    ThreatPattern(
        pattern_id="SD-001",
        threat_type=ThreatType.SENSITIVE_DATA,
        level=ThreatLevel.HIGH,
        description="Password or credential in plaintext",
        regex=_compile(
            r"(password\s*[:=\s]\s*\S+|"
            r"passwd\s*[:=\s]\s*\S+|"
            r"pwd\s*[:=]\s*\S+|"
            r"secret\s*[:=]\s*\S+|"
            r"credentials?\s*[:=]\s*\S+)"
        ),
        confidence_base=0.88,
        tags=["password", "credential"],
    ),
    ThreatPattern(
        pattern_id="SD-002",
        threat_type=ThreatType.SENSITIVE_DATA,
        level=ThreatLevel.MEDIUM,
        description="Internal system path or configuration exposed",
        regex=_compile(
            r"(/etc/passwd|/etc/shadow|/etc/hosts|"
            r"C:\\Windows\\System32|"
            r"\.env\b|config\.yaml|secrets\.json|"
            r"private_key|id_rsa)"
        ),
        confidence_base=0.85,
        tags=["system_path", "config", "internal"],
    ),
]

# ---------------------------------------------------------------------------
# COMBINED DATABASE
# ---------------------------------------------------------------------------

ALL_PATTERNS: list[ThreatPattern] = (
    PROMPT_INJECTION_PATTERNS
    + JAILBREAK_PATTERNS
    + PII_PATTERNS
    + SENSITIVE_DATA_PATTERNS
)

PATTERNS_BY_TYPE: dict[ThreatType, list[ThreatPattern]] = {}
for _pattern in ALL_PATTERNS:
    PATTERNS_BY_TYPE.setdefault(_pattern.threat_type, []).append(_pattern)
