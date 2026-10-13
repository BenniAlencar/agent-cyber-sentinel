"""
Tests for POD-9 Proof-of-Defense envelopes.
"""

from cyber_sentinel.core.envelope import Pod9ProofEnvelope, create_pod9_envelope
from cyber_sentinel.shield import CyberSentinel


def test_pod9_envelope_signature_and_verification():
    sentinel = CyberSentinel(strict=False)
    result = sentinel.inspect_prompt("Summarize the quarterly financials.")
    envelope = create_pod9_envelope("user-prompt-input", result)

    assert envelope.pod9_layer == "L5-Agentic-AI"
    assert envelope.gate == "SG-5"
    assert envelope.decision == "ADMIT"
    assert envelope.verify() is True


def test_pod9_envelope_tampering_detected():
    sentinel = CyberSentinel(strict=False)
    result = sentinel.inspect_prompt("Summarize the quarterly financials.")
    envelope = create_pod9_envelope("user-prompt-input", result)

    # Tamper with the decision
    envelope.decision = "DENY"

    # Signature verification must fail
    assert envelope.verify() is False
