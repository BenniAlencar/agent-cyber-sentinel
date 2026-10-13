"""
LangChain & LangGraph Security Callback Handler for Agent Cyber Sentinel.
Intercepts LLM inputs, tool calls, and outputs at runtime.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from cyber_sentinel.shield import CyberSentinel


class CyberSentinelCallbackHandler:
    """
    LangChain callback handler that inspects and sanitizes prompts, tool calls, and outputs.
    """

    def __init__(self, sentinel: Optional[CyberSentinel] = None):
        self.sentinel = sentinel or CyberSentinel(strict=True)

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called before prompts are sent to the LLM."""
        for prompt in prompts:
            self.sentinel.inspect_prompt(prompt)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called before a tool is invoked."""
        tool_name = serialized.get("name", "unknown_tool")
        self.sentinel.inspect_tool_call(tool_name, {"input": input_str})

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool returns output."""
        self.sentinel.inspect_output(output)
