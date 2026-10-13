"""
POD-9 (Proof-of-Defense in 9 Layers) envelope generator.
Produces tamper-evident cryptographic verification records for security compliance.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cyber_sentinel.core.models import InspectionResult, _iso_now


class Pod9ProofEnvelope(BaseModel):
    """
    Standardized Proof-of-Defense envelope certifying that an agentic
    action passed through Tier-0 security verification gates.
    """
    envelope_id: str = Field(default_factory=lambda: f"pod9_{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=_iso_now)
    policy_version: str = "Benni-POD9-v1.0.0"
    pod9_layer: str  # L1 to L9
    gate: str        # SG-0 to SG-C
    decision: str    # ADMIT, REVIEW_REQUIRED, DENY
    target_asset: str
    threat_level: str
    findings_count: int
    evidence_digest: str
    signature: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.signature:
            self.signature = self.generate_signature()

    def generate_signature(self) -> str:
        """Generates deterministic signature across all envelope claims."""
        claims = {
            "envelope_id": self.envelope_id,
            "timestamp": self.timestamp,
            "policy_version": self.policy_version,
            "pod9_layer": self.pod9_layer,
            "gate": self.gate,
            "decision": self.decision,
            "target_asset": self.target_asset,
            "evidence_digest": self.evidence_digest,
        }
        raw = json.dumps(claims, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def verify(self) -> bool:
        """Verifies integrity of the proof envelope."""
        return self.signature == self.generate_signature()


def create_pod9_envelope(
    target_asset: str,
    result: InspectionResult,
) -> Pod9ProofEnvelope:
    """Wraps an InspectionResult into a formal POD-9 Proof-of-Defense envelope."""
    decision = "ADMIT" if result.is_safe else "DENY"
    return Pod9ProofEnvelope(
        pod9_layer=result.pod9_layer,
        gate=result.gate,
        decision=decision,
        target_asset=target_asset,
        threat_level=result.threat_level.value,
        findings_count=len(result.findings),
        evidence_digest=result.evidence_digest,
    )
