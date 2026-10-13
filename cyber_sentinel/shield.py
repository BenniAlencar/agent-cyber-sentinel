"""
Unified Zero-Trust Security Shield entrypoint for Agent Cyber Sentinel.
Combines L4, L5, and L6 threat detectors into an atomic, low-latency runtime gate.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS).
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, List, Optional, Set

from cyber_sentinel.core.envelope import Pod9ProofEnvelope, create_pod9_envelope
from cyber_sentinel.core.models import (
    InspectionResult,
    PromptInjectionBlockedError,
    RemediationAction,
    SecretLeakageBlockedError,
    SecurityThreatLevel,
    SSRFBlockedError,
    ThreatCategory,
    ThreatFinding,
    ToxicToolBlockedError,
)
from cyber_sentinel.detectors.prompt_injection import PromptInjectionDetector
from cyber_sentinel.detectors.secret_leak import SecretLeakDetector
from cyber_sentinel.detectors.tool_sanitizer import ToolCallSanitizer


class CyberSentinel:
    """
    Tier-0 Security Shield for autonomous AI agents, LLM chains, and MCP servers.
    """

    def __init__(
        self,
        strict: bool = True,
        auto_redact_secrets: bool = True,
        canary_tokens: Optional[Set[str]] = None,
        allow_private_networks: bool = False,
        entropy_threshold: float = 4.3,
    ):
        self.strict = strict
        self.auto_redact_secrets = auto_redact_secrets
        self.prompt_detector = PromptInjectionDetector(canary_tokens=canary_tokens)
        self.secret_detector = SecretLeakDetector(entropy_threshold=entropy_threshold)
        self.tool_sanitizer = ToolCallSanitizer(allow_private_networks=allow_private_networks)

    def _determine_threat_level(self, findings: List[ThreatFinding]) -> SecurityThreatLevel:
        """Computes graduated threat level based on finding severities."""
        if not findings:
            return SecurityThreatLevel.SAFE

        has_blocking = any(f.action == RemediationAction.BLOCK for f in findings)
        if has_blocking:
            return SecurityThreatLevel.CRITICAL

        has_redaction = any(f.action == RemediationAction.REDACT for f in findings)
        if has_redaction:
            return SecurityThreatLevel.DANGEROUS

        return SecurityThreatLevel.SUSPICIOUS

    def inspect_prompt(
        self,
        prompt: str,
        gate: str = "SG-5",
    ) -> InspectionResult:
        """
        Inspects an incoming prompt or retrieved context for prompt injection and secrets.
        """
        findings: List[ThreatFinding] = []

        # 1. Prompt Injection probe
        inj_findings = self.prompt_detector.scan(prompt)
        findings.extend(inj_findings)

        # 2. Secret Leak probe
        sanitized_text, sec_findings = self.secret_detector.scan_and_redact(prompt)
        findings.extend(sec_findings)

        threat_level = self._determine_threat_level(findings)
        is_safe = threat_level in {SecurityThreatLevel.SAFE, SecurityThreatLevel.SUSPICIOUS}
        # In non-strict mode, if secrets were redacted, the sanitized prompt can be safe
        if self.auto_redact_secrets and not inj_findings:
            is_safe = True

        result = InspectionResult(
            is_safe=is_safe,
            threat_level=threat_level,
            findings=findings,
            sanitized_text=sanitized_text if self.auto_redact_secrets else prompt,
            pod9_layer="L5-Agentic-AI",
            gate=gate,
        )

        if self.strict and not result.is_safe:
            if any(f.category == ThreatCategory.PROMPT_INJECTION for f in findings):
                raise PromptInjectionBlockedError(
                    f"[CYBER-SENTINEL BLOCKED] Prompt injection detected: {findings[0].description}",
                    result=result,
                )
            if any(f.category == ThreatCategory.SECRET_LEAKAGE for f in findings):
                raise SecretLeakageBlockedError(
                    f"[CYBER-SENTINEL BLOCKED] Credential leak detected: {findings[0].description}",
                    result=result,
                )

        return result

    def inspect_output(
        self,
        output_text: str,
        gate: str = "SG-6",
    ) -> InspectionResult:
        """
        Inspects generated model output or tool response to prevent credential exfiltration.
        """
        findings: List[ThreatFinding] = []

        sanitized_text, sec_findings = self.secret_detector.scan_and_redact(output_text)
        findings.extend(sec_findings)

        threat_level = self._determine_threat_level(findings)
        # Output is safe if sanitized
        is_safe = True if self.auto_redact_secrets else (len(findings) == 0)

        result = InspectionResult(
            is_safe=is_safe,
            threat_level=threat_level,
            findings=findings,
            sanitized_text=sanitized_text if self.auto_redact_secrets else output_text,
            pod9_layer="L6-Data-Cryptography",
            gate=gate,
        )

        if self.strict and not is_safe and not self.auto_redact_secrets:
            raise SecretLeakageBlockedError(
                f"[CYBER-SENTINEL BLOCKED] Outbound response contains credentials: {findings[0].description}",
                result=result,
            )

        return result

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        gate: str = "SG-4",
    ) -> InspectionResult:
        """
        Inspects a planned tool execution and arguments for SSRF, toxic commands, and secrets.
        """
        findings: List[ThreatFinding] = []

        # 1. Tool Sanitization probe
        tool_findings = self.tool_sanitizer.scan_tool_call(tool_name, arguments)
        findings.extend(tool_findings)

        # 2. Secret leak in arguments
        sanitized_args: Dict[str, Any] = {}
        for k, v in arguments.items():
            if isinstance(v, str):
                s_val, s_findings = self.secret_detector.scan_and_redact(v)
                sanitized_args[k] = s_val if self.auto_redact_secrets else v
                findings.extend(s_findings)
            else:
                sanitized_args[k] = v

        threat_level = self._determine_threat_level(findings)
        is_safe = len(tool_findings) == 0

        result = InspectionResult(
            is_safe=is_safe,
            threat_level=threat_level,
            findings=findings,
            sanitized_payload=sanitized_args,
            pod9_layer="L4-Code-Configuration",
            gate=gate,
        )

        if self.strict and not is_safe:
            ssrf = next((f for f in findings if f.category == ThreatCategory.SSRF_ATTEMPT), None)
            if ssrf:
                raise SSRFBlockedError(
                    f"[CYBER-SENTINEL BLOCKED] SSRF attack intercepted on tool '{tool_name}': {ssrf.description}",
                    result=result,
                )
            toxic = next((f for f in findings if f.category == ThreatCategory.TOXIC_TOOL_CALL), None)
            if toxic:
                raise ToxicToolBlockedError(
                    f"[CYBER-SENTINEL BLOCKED] Destructive tool command intercepted on '{tool_name}': {toxic.description}",
                    result=result,
                )
            raise ToxicToolBlockedError(
                f"[CYBER-SENTINEL BLOCKED] Tool call violated safety policy: {findings[0].description}",
                result=result,
            )

        return result

    def create_proof(self, target_asset: str, result: InspectionResult) -> Pod9ProofEnvelope:
        """Creates a signed, verifiable POD-9 Proof-of-Defense envelope."""
        return create_pod9_envelope(target_asset=target_asset, result=result)

    def guard_tool(self, tool_fn: Optional[Callable[..., Any]] = None, *, name: Optional[str] = None) -> Callable[..., Any]:
        """Decorator that wraps a Python function with tool inspection."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            target_name = name or fn.__name__

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                arguments = {"args": args, **kwargs}
                # Inspect arguments
                self.inspect_tool_call(target_name, arguments)
                # Execute tool
                result = fn(*args, **kwargs)
                # Inspect output if string
                if isinstance(result, str):
                    insp = self.inspect_output(result)
                    return insp.sanitized_text
                return result

            return wrapper

        if tool_fn is not None:
            return decorator(tool_fn)
        return decorator
