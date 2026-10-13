"""
Secret Leakage and Credential Interceptor Detector.
Combines Shannon-entropy randomness analysis with provider-specific regex signatures
to detect and redact sensitive credentials in agent outputs, logs, and tool arguments.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS - Layer L6 Data & Cryptography).
"""

from __future__ import annotations

import math
import re
from typing import List, Tuple

from cyber_sentinel.core.models import RemediationAction, ThreatCategory, ThreatFinding


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {c: data.count(c) for c in set(data)}
    for count in frequencies.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    return entropy


class SecretLeakDetector:
    """
    Detects API keys, tokens, private keys, database passwords, and high-entropy secrets.
    Provides automatic in-place redaction.
    """

    KNOWN_SECRET_PATTERNS = [
        # Anthropic Claude API keys (must be before generic sk- pattern)
        (
            re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
            "SECRET_ANTHROPIC_KEY",
            "Anthropic API Key signature",
        ),
        # OpenAI API keys (legacy and modern project keys)
        (
            re.compile(r"sk-(?!ant-)(proj-)?[a-zA-Z0-9_\-]{32,}"),
            "SECRET_OPENAI_KEY",
            "OpenAI API Key signature",
        ),
        # AWS Access Key ID
        (
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "SECRET_AWS_ACCESS_KEY",
            "AWS Access Key ID signature",
        ),
        # Google Gemini / GCP API Key
        (
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            "SECRET_GOOGLE_API_KEY",
            "Google API Key signature",
        ),
        # GitHub Personal Access Token (classic & fine-grained)
        (
            re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
            "SECRET_GITHUB_PAT",
            "GitHub Personal Access Token signature",
        ),
        (
            re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{82}\b"),
            "SECRET_GITHUB_FINE_GRAINED",
            "GitHub Fine-Grained Personal Access Token",
        ),
        # JSON Web Tokens (JWT)
        (
            re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"),
            "SECRET_JWT_TOKEN",
            "JSON Web Token (JWT) signature",
        ),
        # Private Keys (RSA, OpenSSH, EC)
        (
            re.compile(r"-----BEGIN ([A-Z\s]+) PRIVATE KEY-----[^-]+-----END \1 PRIVATE KEY-----", re.DOTALL),
            "SECRET_PRIVATE_KEY",
            "Cryptographic Private Key block",
        ),
        # Database URIs with embedded plaintext password
        (
            re.compile(r"\b(postgresql|postgres|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_]+:([^@\s]+)@"),
            "SECRET_DB_PASSWORD",
            "Database connection string with plaintext password",
        ),
    ]

    def __init__(self, entropy_threshold: float = 4.3, min_entropy_len: int = 24):
        self.entropy_threshold = entropy_threshold
        self.min_entropy_len = min_entropy_len

    def scan_and_redact(self, text: str) -> Tuple[str, List[ThreatFinding]]:
        """
        Scans text for secrets, returns sanitized text with secrets redacted,
        and a list of ThreatFinding records.
        """
        findings: List[ThreatFinding] = []
        if not text:
            return text, findings

        sanitized = text

        # 1. Regex signature based scanning
        for pattern, rule_name, desc in self.KNOWN_SECRET_PATTERNS:
            for match in pattern.finditer(text):
                matched_val = match.group(0)
                # Mask matched sample for safety in logs
                masked = matched_val[:4] + "..." + matched_val[-4:] if len(matched_val) > 8 else "***"
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.SECRET_LEAKAGE,
                        rule_name=rule_name,
                        confidence=0.99,
                        description=desc,
                        matched_sample=masked,
                        action=RemediationAction.REDACT,
                    )
                )
                replacement = f"[REDACTED_{rule_name}]"
                sanitized = sanitized.replace(matched_val, replacement)

        # 2. Shannon entropy analysis on isolated tokens
        tokens = re.findall(r"\b[a-zA-Z0-9_+/=-]{24,}\b", sanitized)
        for token in tokens:
            # Skip if already a redaction tag
            if token.startswith("[REDACTED_"):
                continue
            ent = shannon_entropy(token)
            if ent >= self.entropy_threshold:
                masked = token[:4] + "..." + token[-4:]
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.SECRET_LEAKAGE,
                        rule_name="HIGH_SHANNON_ENTROPY_SECRET",
                        confidence=0.88,
                        description=f"High-entropy token detected (entropy={ent:.2f} >= {self.entropy_threshold})",
                        matched_sample=masked,
                        action=RemediationAction.REDACT,
                    )
                )
                sanitized = sanitized.replace(token, "[REDACTED_HIGH_ENTROPY_SECRET]")

        return sanitized, findings
