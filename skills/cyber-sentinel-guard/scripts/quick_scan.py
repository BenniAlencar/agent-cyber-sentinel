#!/usr/bin/env python3
"""
Agent Cyber Sentinel — Quick Scan (Zero-Dependency Standalone Engine)
Part of the cyber-sentinel-guard skill for Agensi.io & AI Agents.

Executes Tier-0 zero-trust security checks with 0.3ms latency:
- Prompt injection & role hijack detection
- High-entropy secret & API key leak interception
- SSRF (RFC1918, Cloud Metadata 169.254.169.254) blocking
- Destructive shell command interception

GitHub: https://github.com/BenniAlencar/agent-cyber-sentinel (Apache-2.0)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# PROMPT INJECTION PATTERNS
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?prior\s+instructions",
    r"disregard\s+(?:all\s+)?previous\s+instructions",
    r"system\s*:\s*you\s+are\s+now",
    r"you\s+must\s+act\s+as\s+an?\s+unrestricted",
    r"new\s+system\s+prompt\s*:",
    r"do\s+not\s+tell\s+the\s+user",
    r"send\s+(?:your\s+)?(?:credentials|api[_\s-]?keys?|secrets?|tokens?)\s+to",
    r"fetch\s+(?:env|environment)\s+variables",
    r"curl\s+https?://[^\s]+\s+-\s*d",
    r"post\s+all\s+(?:passwords|cookies|tokens)\s+to",
    r"data:text/html;base64,[A-Za-z0-9+/=]{30,}",
    r"bypass\s+(?:safety|filter|guardrail)",
    r"jailbreak",
    r"DAN\s+mode",
]

# SECRET & CREDENTIAL PATTERNS
SECRET_PATTERNS = {
    "OPENAI_KEY": r"\b(?:sk-[a-zA-Z0-9]{20,48})\b",
    "ANTHROPIC_KEY": r"\b(?:sk-ant-[a-zA-Z0-9_-]{20,90})\b",
    "GITHUB_PAT": r"\b(?:ghp_[a-zA-Z0-9]{36,40})\b",
    "AWS_ACCESS_KEY": r"\b(?:AKIA[0-9A-Z]{16})\b",
    "SLACK_TOKEN": r"\b(?:xox[baprs]-[0-9a-zA-Z-]{24,})\b",
    "GOOGLE_API_KEY": r"\b(?:AIza[0-9A-Za-z-_]{35})\b",
    "JWT_TOKEN": r"\b(?:eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b",
    "DATABASE_URI": r"(?:postgres|postgresql|mysql|mongodb)://[^:]+:[^@]+@[^/]+/[^\s]+",
}

# TOXIC SHELL COMMANDS
TOXIC_COMMAND_PATTERNS = [
    r"\brm\s+-(?:r|f|rf|fr)\s+(?:/|~|\$HOME|\.\.)",
    r"\bmkfs(?:\.\w+)?\s+",
    r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # Fork bomb
    r"\bchmod\s+(?:-R\s+)?777\s+/",
    r"\bcurl\s+[^\n|]+\|\s*(?:ba)?sh\b",
    r"\bwget\s+[^\n|]+\|\s*(?:ba)?sh\b",
]

# FORBIDDEN METADATA HOSTS
PROHIBITED_METADATA_HOSTS = {
    "169.254.169.254",          # AWS / OpenStack / GCP metadata
    "metadata.google.internal", # GCP
    "169.254.169.250",          # Azure IMDS
    "fd00::1",                  # IPv6 ULA metadata
    "localhost",
    "127.0.0.1",
    "::1",
}


def shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log(p) / math.log(2.0) for p in prob)


def scan_prompt(text: str) -> Dict[str, Any]:
    """Inspects text for prompt injection and secret leaks."""
    findings = []
    sanitized = text

    # 1. Prompt Injection
    for pat in PROMPT_INJECTION_PATTERNS:
        matches = re.findall(pat, sanitized, re.IGNORECASE)
        if matches:
            findings.append({
                "type": "PROMPT_INJECTION",
                "pattern": pat,
                "matches": matches,
                "severity": "CRITICAL"
            })
            sanitized = re.sub(pat, "[REDACTED_PROMPT_INJECTION]", sanitized, flags=re.IGNORECASE)

    # 2. Secret Redaction
    for sec_name, pat in SECRET_PATTERNS.items():
        matches = re.findall(pat, sanitized)
        if matches:
            findings.append({
                "type": "SECRET_LEAK",
                "secret_type": sec_name,
                "count": len(matches),
                "severity": "HIGH"
            })
            sanitized = re.sub(pat, f"[REDACTED_{sec_name}]", sanitized)

    # 3. High entropy tokens
    words = sanitized.split()
    for w in words:
        if len(w) >= 32 and not w.startswith("[REDACTED_"):
            ent = shannon_entropy(w)
            if ent > 4.6:
                findings.append({
                    "type": "HIGH_ENTROPY_TOKEN",
                    "entropy": round(ent, 2),
                    "token": w[:8] + "...",
                    "severity": "MEDIUM"
                })
                sanitized = sanitized.replace(w, "[REDACTED_HIGH_ENTROPY_TOKEN]")

    is_safe = len([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]) == 0

    return {
        "is_safe": is_safe,
        "threat_level": "CRITICAL" if not is_safe else ("MEDIUM" if findings else "CLEAN"),
        "findings": findings,
        "sanitized_text": sanitized,
    }


def scan_tool_call(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Inspects a tool call for SSRF, destructive commands, and secret leaks."""
    findings = []
    args_str = json.dumps(arguments)

    # 1. Check for toxic shell commands
    if any(k in tool_name.lower() for k in ("bash", "shell", "exec", "cmd", "terminal", "run")):
        cmd = str(arguments.get("command") or arguments.get("cmd") or arguments.get("CommandLine") or args_str)
        for pat in TOXIC_COMMAND_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                findings.append({
                    "type": "DESTRUCTIVE_COMMAND",
                    "pattern": pat,
                    "severity": "CRITICAL",
                    "message": f"Destructive or root-wiping shell command blocked: {pat}"
                })

    # 2. Check for SSRF in URLs
    urls_found = re.findall(r"https?://[^\s\"']+", args_str)
    for u in urls_found:
        parsed = urlparse(u)
        hostname = (parsed.hostname or "").lower()

        if hostname in PROHIBITED_METADATA_HOSTS:
            findings.append({
                "type": "SSRF_METADATA",
                "host": hostname,
                "severity": "CRITICAL",
                "message": f"Cloud metadata endpoint probe blocked: {hostname}"
            })
            continue

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                findings.append({
                    "type": "SSRF_PRIVATE_IP",
                    "ip": str(ip),
                    "severity": "CRITICAL",
                    "message": f"Private intranet IP access prohibited: {ip}"
                })
        except ValueError:
            pass

    # 3. Check for secrets inside arguments
    for sec_name, pat in SECRET_PATTERNS.items():
        if re.search(pat, args_str):
            findings.append({
                "type": "EXPOSED_CREDENTIAL_IN_TOOL_CALL",
                "secret_type": sec_name,
                "severity": "HIGH",
                "message": f"Unencrypted {sec_name} detected in tool call arguments"
            })

    is_safe = len([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]) == 0

    return {
        "is_safe": is_safe,
        "tool_name": tool_name,
        "threat_level": "CRITICAL" if not is_safe else ("MEDIUM" if findings else "CLEAN"),
        "findings": findings,
    }


def redact_text(text: str) -> str:
    """Convenience helper to redact credentials from any string."""
    res = scan_prompt(text)
    return res["sanitized_text"]


def main():
    parser = argparse.ArgumentParser(description="Agent Cyber Sentinel Quick Scanner")
    parser.add_argument("--mode", choices=["prompt", "tool", "redact"], default="prompt", help="Scan mode")
    parser.add_argument("--text", type=str, help="Text to scan or redact")
    parser.add_argument("--tool", type=str, help="Tool name")
    parser.add_argument("--args", type=str, help="Tool arguments in JSON format")

    args = parser.parse_args()

    if args.mode == "prompt":
        input_text = args.text or sys.stdin.read()
        res = scan_prompt(input_text)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["is_safe"] else 1)

    elif args.mode == "tool":
        tool_name = args.tool or "generic_tool"
        args_dict = json.loads(args.args or "{}")
        res = scan_tool_call(tool_name, args_dict)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["is_safe"] else 1)

    elif args.mode == "redact":
        input_text = args.text or sys.stdin.read()
        print(redact_text(input_text))
        sys.exit(0)


if __name__ == "__main__":
    main()
