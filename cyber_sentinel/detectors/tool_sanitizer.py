"""
Tool Call Sanitizer & Toxic Action Interceptor.
Prevents Server-Side Request Forgery (SSRF), destructive shell commands,
SQL injection, and path traversal in AI agent tool executions and MCP calls.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS - Layer L4 Code & Config, L5 Agentic AI).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from cyber_sentinel.core.models import RemediationAction, ThreatCategory, ThreatFinding


class ToolCallSanitizer:
    """
    Evaluates tool names and execution arguments against zero-trust safety gates.
    """

    # Cloud metadata service endpoints & hostnames
    METADATA_HOSTS = {
        "169.254.169.254",
        "metadata.google.internal",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }

    # Destructive shell command regexes
    DESTRUCTIVE_COMMAND_PATTERNS = [
        (
            re.compile(r"(?i)\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+/(?:\s|$|\*)|\brm\s+-[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|$|\*)"),
            "TOXIC_ROOT_DELETION",
            "Root filesystem deletion attempt ('rm -rf /').",
        ),
        (
            re.compile(r"\b(mkfs(\.[a-z0-9]+)?|dd\s+if=/dev/(zero|urandom))\b"),
            "TOXIC_DISK_WIPE",
            "Disk wiping or filesystem format command.",
        ),
        (
            re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
            "TOXIC_FORK_BOMB",
            "Bash fork bomb detected.",
        ),
        (
            re.compile(r"\b(curl|wget)\s+[^|]+\|\s*(bash|sh|zsh)\b"),
            "TOXIC_PIPE_TO_SHELL",
            "Dangerous unverified script piping to shell.",
        ),
        (
            re.compile(r"\bchmod\s+-[a-zA-Z]*R\s+777\s+/\b"),
            "TOXIC_GLOBAL_CHMOD_777",
            "Unrestricted global permission escalation ('chmod -R 777 /').",
        ),
    ]

    # Destructive SQL patterns
    DESTRUCTIVE_SQL_PATTERNS = [
        (
            re.compile(r"(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b"),
            "TOXIC_SQL_DESTRUCTIVE",
            "Destructive SQL command (DROP or TRUNCATE).",
        ),
        (
            re.compile(r"(?i)\b(xp_cmdshell|exec\s+master\.\.xp_cmdshell)\b"),
            "TOXIC_SQL_EXTENDED_PROC",
            "Dangerous SQL Server xp_cmdshell execution.",
        ),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\.[/\\]){3,}|%2e%2e[%2f%5c]{2,}")

    def __init__(self, allow_private_networks: bool = False):
        self.allow_private_networks = allow_private_networks

    def _check_ssrf_url(self, url_str: str) -> Optional[ThreatFinding]:
        """Validates if a URL points to cloud metadata or prohibited private networks."""
        try:
            parsed = urlparse(url_str)
            if not parsed.scheme or not parsed.netloc:
                return None

            # Disallow forbidden schemas (e.g. file, gopher, dict)
            if parsed.scheme.lower() not in {"http", "https"}:
                return ThreatFinding(
                    category=ThreatCategory.SSRF_ATTEMPT,
                    rule_name="SSRF_UNSUPPORTED_SCHEME",
                    confidence=0.99,
                    description=f"Forbidden protocol scheme '{parsed.scheme}://'.",
                    matched_sample=f"'{parsed.scheme}://'",
                    action=RemediationAction.BLOCK,
                )

            hostname = parsed.hostname
            if not hostname:
                return None

            # 1. Cloud metadata host check
            if hostname.lower() in self.METADATA_HOSTS:
                return ThreatFinding(
                    category=ThreatCategory.SSRF_ATTEMPT,
                    rule_name="SSRF_CLOUD_METADATA_ACCESS",
                    confidence=1.0,
                    description=f"Attempted access to Cloud Metadata service: {hostname}",
                    matched_sample=f"'{hostname}'",
                    action=RemediationAction.BLOCK,
                )

            # 2. Localhost check
            if hostname.lower() in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
                return ThreatFinding(
                    category=ThreatCategory.SSRF_ATTEMPT,
                    rule_name="SSRF_LOOPBACK_ACCESS",
                    confidence=1.0,
                    description=f"Prohibited loopback/localhost access: {hostname}",
                    matched_sample=f"'{hostname}'",
                    action=RemediationAction.BLOCK,
                )

            # 3. Private IP subnet check (RFC-1918)
            try:
                ip = ipaddress.ip_address(hostname)
                if not self.allow_private_networks and (ip.is_private or ip.is_link_local):
                    return ThreatFinding(
                        category=ThreatCategory.SSRF_ATTEMPT,
                        rule_name="SSRF_PRIVATE_NETWORK_ACCESS",
                        confidence=0.98,
                        description=f"Prohibited private subnet destination IP: {ip}",
                        matched_sample=f"'{ip}'",
                        action=RemediationAction.BLOCK,
                    )
            except ValueError:
                # Hostname is a domain name, not an IP literal
                pass

        except Exception:
            pass

        return None

    def scan_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> List[ThreatFinding]:
        """
        Scans a tool invocation and its arguments for SSRF, toxic shell commands,
        destructive SQL, and path traversal vulnerabilities.
        """
        findings: List[ThreatFinding] = []

        def _extract_all_strings(val: Any) -> List[str]:
            res: List[str] = []
            if isinstance(val, str):
                res.append(val)
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    res.extend(_extract_all_strings(item))
            elif isinstance(val, dict):
                for item in val.values():
                    res.extend(_extract_all_strings(item))
            return res

        all_strings = _extract_all_strings(arguments)
        arg_str = " ".join(all_strings)

        # 1. SSRF Scan on all string values
        for s in all_strings:
            if "://" in s:
                ssrf_finding = self._check_ssrf_url(s)
                if ssrf_finding:
                    findings.append(ssrf_finding)

        # 2. Destructive Shell Command scan
        for pattern, rule_name, desc in self.DESTRUCTIVE_COMMAND_PATTERNS:
            if pattern.search(arg_str):
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.TOXIC_TOOL_CALL,
                        rule_name=rule_name,
                        confidence=0.99,
                        description=desc,
                        matched_sample=f"in tool '{tool_name}'",
                        action=RemediationAction.BLOCK,
                    )
                )

        # 3. Destructive SQL scan
        for pattern, rule_name, desc in self.DESTRUCTIVE_SQL_PATTERNS:
            if pattern.search(arg_str):
                findings.append(
                    ThreatFinding(
                        category=ThreatCategory.TOXIC_TOOL_CALL,
                        rule_name=rule_name,
                        confidence=0.95,
                        description=desc,
                        matched_sample=f"in tool '{tool_name}'",
                        action=RemediationAction.BLOCK,
                    )
                )

        # 4. Path traversal scan
        if self.PATH_TRAVERSAL_PATTERN.search(arg_str):
            findings.append(
                ThreatFinding(
                    category=ThreatCategory.PATH_TRAVERSAL,
                    rule_name="PATH_TRAVERSAL_ATTEMPT",
                    confidence=0.95,
                    description="Path traversal sequences detected in tool parameters.",
                    matched_sample=f"in tool '{tool_name}'",
                    action=RemediationAction.BLOCK,
                )
            )

        return findings
