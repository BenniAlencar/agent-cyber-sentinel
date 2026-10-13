"""
Model Context Protocol (MCP) Security Guard and Server.
Provides native security gates for Claude Desktop, Cursor, Antigravity, and Project Benjamin.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from cyber_sentinel.core.envelope import Pod9ProofEnvelope
from cyber_sentinel.core.models import SecurityInterceptionError
from cyber_sentinel.shield import CyberSentinel


class McpSecurityGuard:
    """
    MCP Server exposing Tier-0 security verification and runtime tool firewalling.
    """

    def __init__(self, sentinel: Optional[CyberSentinel] = None):
        self.sentinel = sentinel or CyberSentinel(strict=False)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns standard MCP tool specifications."""
        return [
            {
                "name": "sentinel_scan_prompt",
                "description": "Scans an LLM prompt or retrieved context for prompt injection and secret leaks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "The prompt or retrieved context text to inspect."},
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "sentinel_scan_tool_call",
                "description": "Evaluates a planned tool call and arguments for SSRF, toxic shell commands, and secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Name of the target tool."},
                        "arguments": {"type": "object", "description": "Key-value dictionary of arguments."},
                    },
                    "required": ["tool_name", "arguments"],
                },
            },
            {
                "name": "sentinel_redact_secrets",
                "description": "Scans output text for API keys, private keys, and high-entropy credentials, returning sanitized text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to redact credentials from."},
                    },
                    "required": ["text"],
                },
            },
            {
                "name": "sentinel_verify_pod9",
                "description": "Verifies the cryptographic integrity of a POD-9 Proof-of-Defense envelope.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "envelope": {"type": "object", "description": "Serialized POD-9 envelope."},
                    },
                    "required": ["envelope"],
                },
            },
        ]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Executes an MCP security tool call."""
        if tool_name == "sentinel_scan_prompt":
            text = arguments.get("text", "")
            res = self.sentinel.inspect_prompt(text)
            proof = self.sentinel.create_proof("mcp:prompt_scan", res)
            return {
                "isError": not res.is_safe,
                "is_safe": res.is_safe,
                "threat_level": res.threat_level.value,
                "findings": [f.model_dump() for f in res.findings],
                "sanitized_text": res.sanitized_text,
                "pod9_signature": proof.signature,
                "content": [{"type": "text", "text": f"Safety check: {'PASSED' if res.is_safe else 'BLOCKED'} ({res.threat_level.value})"}],
            }

        elif tool_name == "sentinel_scan_tool_call":
            target_tool = arguments.get("tool_name", "")
            tool_args = arguments.get("arguments", {})
            res = self.sentinel.inspect_tool_call(target_tool, tool_args)
            proof = self.sentinel.create_proof(f"mcp:tool:{target_tool}", res)
            return {
                "isError": not res.is_safe,
                "is_safe": res.is_safe,
                "threat_level": res.threat_level.value,
                "findings": [f.model_dump() for f in res.findings],
                "sanitized_payload": res.sanitized_payload,
                "pod9_signature": proof.signature,
                "content": [{"type": "text", "text": f"Tool '{target_tool}' check: {'PASSED' if res.is_safe else 'BLOCKED'}"}],
            }

        elif tool_name == "sentinel_redact_secrets":
            text = arguments.get("text", "")
            res = self.sentinel.inspect_output(text)
            return {
                "isError": False,
                "sanitized_text": res.sanitized_text,
                "redactions_count": len(res.findings),
                "content": [{"type": "text", "text": res.sanitized_text}],
            }

        elif tool_name == "sentinel_verify_pod9":
            env_data = arguments.get("envelope", {})
            try:
                envelope = Pod9ProofEnvelope(**env_data)
                valid = envelope.verify()
                return {
                    "isError": not valid,
                    "valid": valid,
                    "envelope_id": envelope.envelope_id,
                    "content": [{"type": "text", "text": f"POD-9 Envelope verification: {'VALID' if valid else 'INVALID'}"}],
                }
            except Exception as e:
                return {
                    "isError": True,
                    "valid": False,
                    "error": str(e),
                    "content": [{"type": "text", "text": f"Invalid envelope payload: {e}"}],
                }

        return {
            "isError": True,
            "error": f"Unknown tool '{tool_name}'",
            "content": [{"type": "text", "text": f"Tool '{tool_name}' not recognized."}],
        }
