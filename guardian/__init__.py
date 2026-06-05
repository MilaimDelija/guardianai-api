"""
GuardianAI: AI Security Engine
An open-source security layer for AI agents, LLMs, and autonomous systems.

Developed by Neuronium Engineers
https://github.com/neuronium/vigil
"""

__version__ = "0.1.0"
__author__ = "Neuronium Engineers"
__license__ = "Apache-2.0"

from guardian.core.engine import GuardianEngine
from guardian.core.models import ScanResult, ThreatLevel, ThreatType

__all__ = [
    "GuardianEngine",
    "ScanResult",
    "ThreatLevel",
    "ThreatType",
]
