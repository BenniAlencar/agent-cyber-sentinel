"""
OpenAI SDK Security Guard and Proxy Adapter for Agent Cyber Sentinel.
Intercepts Chat Completions, Assistant Messages, and Tool Calls to enforce
zero-trust security policies, prompt injection defense, and secret redaction.
Governed by Benni Master OS v9.4 (Skill 63 Cyber Sentinel OS).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from cyber_sentinel.core.models import (
    PromptInjectionBlockedError,
    SecretLeakageBlockedError,
    ToxicToolBlockedError,
    SSRFBlockedError,
)
from cyber_sentinel.shield import CyberSentinel


class OpenAISecurityGuard:
    """
    Zero-trust security proxy for the official OpenAI Python SDK.
    Screens prompts before transmission and sanitizes completions and tool arguments.
    """

    def __init__(self, sentinel: Optional[CyberSentinel] = None):
        self.sentinel = sentinel or CyberSentinel(strict=True, auto_redact_secrets=True)

    def guard_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Screens all conversation messages for prompt injection and credentials before sending to OpenAI.
        """
        sanitized_messages: List[Dict[str, Any]] = []

        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                result = self.sentinel.inspect_prompt(content)
                sanitized_msg = dict(msg)
                sanitized_msg["content"] = result.sanitized_text
                sanitized_messages.append(sanitized_msg)
            elif isinstance(content, list):
                # Multimodal / structured content blocks
                sanitized_blocks = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_val = block.get("text", "")
                        result = self.sentinel.inspect_prompt(text_val)
                        s_block = dict(block)
                        s_block["text"] = result.sanitized_text
                        sanitized_blocks.append(s_block)
                    else:
                        sanitized_blocks.append(block)
                sanitized_msg = dict(msg)
                sanitized_msg["content"] = sanitized_blocks
                sanitized_messages.append(sanitized_msg)
            else:
                sanitized_messages.append(msg)

        return sanitized_messages

    def guard_response(self, response: Any) -> Any:
        """
        Inspects model response, redacting any leaked credentials and screening tool calls.
        Works with both raw dicts and OpenAI ChatCompletion objects.
        """
        # If response has choices
        choices = getattr(response, "choices", None)
        if choices is None and isinstance(response, dict):
            choices = response.get("choices")

        if not choices:
            return response

        for choice in choices:
            message = getattr(choice, "message", None)
            if message is None and isinstance(choice, dict):
                message = choice.get("message")

            if not message:
                continue

            # 1. Screen response text for secrets
            content = getattr(message, "content", None)
            if content is None and isinstance(message, dict):
                content = message.get("content")

            if isinstance(content, str):
                out_res = self.sentinel.inspect_output(content)
                if hasattr(message, "content"):
                    message.content = out_res.sanitized_text
                elif isinstance(message, dict):
                    message["content"] = out_res.sanitized_text

            # 2. Screen tool calls in response
            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls is None and isinstance(message, dict):
                tool_calls = message.get("tool_calls")

            if tool_calls:
                for tc in tool_calls:
                    fn = getattr(tc, "function", None)
                    if fn is None and isinstance(tc, dict):
                        fn = tc.get("function")
                    if not fn:
                        continue

                    fn_name = getattr(fn, "name", "") if hasattr(fn, "name") else fn.get("name", "")
                    fn_args = getattr(fn, "arguments", "") if hasattr(fn, "arguments") else fn.get("arguments", "")

                    if isinstance(fn_args, str):
                        try:
                            parsed_args = json.loads(fn_args)
                        except Exception:
                            parsed_args = {"raw": fn_args}
                    else:
                        parsed_args = fn_args or {}

                    self.sentinel.inspect_tool_call(fn_name, parsed_args)

        return response

    def wrap_client(self, client: Any) -> Any:
        """
        Wraps an OpenAI client instance so all chat.completions.create calls
        are guarded with zero-trust pre-flight and post-flight security checks.
        """
        orig_create = client.chat.completions.create
        guard = self

        def guarded_create(*args: Any, **kwargs: Any) -> Any:
            # Pre-flight prompt screening
            if "messages" in kwargs:
                kwargs["messages"] = guard.guard_messages(kwargs["messages"])

            # Call upstream OpenAI API
            response = orig_create(*args, **kwargs)

            # Post-flight completion screening
            return guard.guard_response(response)

        client.chat.completions.create = guarded_create
        return client
