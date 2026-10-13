"""
Core security models, threat levels, and inspection result schemas for Agent Cyber Sentinel.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS).
"""

from __future__ import annotations

import datetime
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def _iso_now() -> str:
    """Returns ISO 8601 UTC timestamp."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class SecurityThreatLevel(str, Enum):
    """Graduated threat risk levels."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class ThreatCategory(str, Enum):
    """Categories of agentic security threats."""
    PROMPT_INJECTION = "prompt_injection"
    SECRET_LEAKAGE = "secret_leakage"
    TOXIC_TOOL_CALL = "toxic_tool_call"
    SSRF_ATTEMPT = "ssrf_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PATH_TRAVERSAL = "path_traversal"


class RemediationAction(str, Enum):
    """Enforcement policy actions."""
    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"
    ALLOW = "allow"


class ThreatFinding(BaseModel):
    """Individual threat signal detected by a security probe."""
    category: ThreatCategory
    rule_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    matched_sample: str
    action: RemediationAction = RemediationAction.BLOCK


class InspectionResult(BaseModel):
    """
    Comprehensive outcome of a prompt, output, or tool call inspection.
    Includes deterministic evidence digest for POD-9 (Proof-of-Defense).
    """
    is_safe: bool
    threat_level: SecurityThreatLevel
    findings: List[ThreatFinding] = Field(default_factory=list)
    sanitized_text: str = ""
    sanitized_payload: Optional[Dict[str, Any]] = None
    evidence_digest: str = ""
    pod9_layer: str = "L5-Agentic-AI"
    gate: str = "SG-5"
    timestamp: str = Field(default_factory=_iso_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.evidence_digest:
            self.evidence_digest = self.compute_digest()

    def compute_digest(self) -> str:
        """Computes deterministic SHA-256 seal over the findings and sanitized text."""
        canonical_obj = {
            "is_safe": self.is_safe,
            "threat_level": self.threat_level.value,
            "findings": [f.model_dump() for f in self.findings],
            "sanitized_text": self.sanitized_text,
            "pod9_layer": self.pod9_layer,
            "gate": self.gate,
        }
        raw_bytes = json.dumps(canonical_obj, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()


# Exceptions
class SecurityInterceptionError(Exception):
    """Base error raised when a dangerous operation is intercepted."""
    def __init__(self, message: str, result: InspectionResult):
        super().__init__(message)
        self.result = result


class PromptInjectionBlockedError(SecurityInterceptionError):
    """Raised when prompt injection or jailbreak attempt is blocked."""
    pass


class SecretLeakageBlockedError(SecurityInterceptionError):
    """Raised when a secret or private credential leakage is blocked."""
    pass


class ToxicToolBlockedError(SecurityInterceptionError):
    """Raised when a destructive or toxic tool command is blocked."""
    pass


class SSRFBlockedError(SecurityInterceptionError):
    """Raised when a Server-Side Request Forgery attempt is blocked."""
    pass
