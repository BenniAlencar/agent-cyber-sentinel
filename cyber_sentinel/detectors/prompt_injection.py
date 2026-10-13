"""
Prompt Injection, Jailbreak, and Delimiter Breakout Detector.
Intercepts direct instruction overrides, indirect RAG injections, and canary token extraction.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS - Layer L5 Agentic AI).
"""

from __future__ import annotations

import re
from typing import List, Optional, Set

from cyber_sentinel.core.models import RemediationAction, ThreatCategory, ThreatFinding


class PromptInjectionDetector:
    """
    Evaluates incoming prompts and third-party context for adversarial manipulation.
    """

    # High-confidence direct instruction override patterns
    DIRECT_OVERRIDE_PATTERNS = [
        (
            re.compile(
                r"(?i)\b(ignore|disregard|forget|bypass|override)\s+(all\s+)?(previous|prior|above|initial|system)\s+(instructions|prompts|rules|commands|constraints)\b"
            ),
            "INJECTION_DIRECT_OVERRIDE",
            0.98,
            "Direct attempt to override prior system prompt instructions.",
        ),
        (
            re.compile(
                r"(?i)\b(you\s+are\s+now|act\s+as)\s+(an?\s+)?(unrestricted|jailbroken|unfiltered|dan|developer\s+mode|chaosgpt)\b"
            ),
            "INJECTION_ROLE_HIJACK",
            0.95,
            "Role hijacking attempt to bypass safety guardrails.",
        ),
        (
            re.compile(
                r"(?i)\b(do\s+anything\s+now|dan\s+mode\s+enabled|always\s+comply\s+without\s+moral)\b"
            ),
            "INJECTION_JAILBREAK_AFFIRMATION",
            0.96,
            "Jailbreak prompt pattern detected.",
        ),
        (
            re.compile(
                r"(?i)\bsystem\s+override\s*[:=\-]\s*.*"
            ),
            "INJECTION_SYSTEM_OVERRIDE_HEADER",
            0.92,
            "Fake system override command block.",
        ),
    ]

    # Delimiter breakout patterns (trying to inject synthetic system / user tags)
    DELIMITER_BREAKOUT_PATTERNS = [
        (
            re.compile(r"(?i)</?(system|instruction|rules|prompt|assistant_message)>"),
            "DELIMITER_TAG_INJECTION",
            0.88,
            "Attempt to inject synthetic XML/HTML instruction tags.",
        ),
        (
            re.compile(r"(?i)(^|\n)###\s*(System|Instruction|New\s+Directive)\s*:"),
            "DELIMITER_MARKDOWN_HEADER_INJECTION",
            0.85,
            "Attempt to simulate markdown system directive block.",
        ),
    ]

    # Indirect prompt injection signatures (embedded in web pages, scraped content, or tool outputs)
    INDIRECT_INJECTION_PATTERNS = [
        (
            re.compile(
                r"(?i)\b(assistant\s+note|system\s+notice)\s*:\s*(ignore|send|forward|exfiltrate|delete)\b"
            ),
            "INDIRECT_PROMPT_INJECTION_NOTE",
            0.93,
            "Indirect prompt injection hidden in context payload.",
        ),
        (
            re.compile(
                r"(?i)\bwhen\s+you\s+read\s+this[,\s]+(do\s+not|instead\s+of|silently\s+send|visit)\b"
            ),
            "INDIRECT_TRIGGER_ACTION",
            0.90,
            "Subversive conditional instruction embedded in retrieved content.",
        ),
    ]

    def __init__(self, canary_tokens: Optional[Set[str]] = None):
        self.canary_tokens = canary_tokens or set()

    def scan(self, text: str) -> List[ThreatFinding]:
        """Scans the text and returns all detected prompt injection findings."""
        findings: List[ThreatFinding] = []

        if not text:
            return findings

        # 1. Direct instruction overrides
        for pattern, rule_name, conf, desc in self.DIRECT_OVERRIDE_PATTERNS:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)[:60]
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        rule_name=rule_name,
                        confidence=conf,
                        description=desc,
                        matched_sample=f"'{matched_str}...'",
                        action=RemediationAction.BLOCK,
                    )
                )

        # 2. Delimiter breakout patterns
        for pattern, rule_name, conf, desc in self.DELIMITER_BREAKOUT_PATTERNS:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)[:40]
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        rule_name=rule_name,
                        confidence=conf,
                        description=desc,
                        matched_sample=f"'{matched_str}'",
                        action=RemediationAction.BLOCK,
                    )
                )

        # 3. Indirect prompt injection patterns
        for pattern, rule_name, conf, desc in self.INDIRECT_INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)[:60]
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        rule_name=rule_name,
                        confidence=conf,
                        description=desc,
                        matched_sample=f"'{matched_str}'",
                        action=RemediationAction.BLOCK,
                    )
                )

        # 4. Canary token leakage probes
        for canary in self.canary_tokens:
            if canary and canary in text:
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        rule_name="CANARY_TOKEN_LEAK_DETECTED",
                        confidence=1.0,
                        description="Secret system canary token was found inside scanned text.",
                        matched_sample="[CANARY_MATCHED]",
                        action=RemediationAction.BLOCK,
                    )
                )

        return findings
