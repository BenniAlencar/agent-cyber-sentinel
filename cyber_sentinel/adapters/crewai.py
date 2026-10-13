"""
CrewAI Security Wrapper for Agent Cyber Sentinel.
Wraps CrewAI tools and custom agents with prompt/tool safety inspection.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from cyber_sentinel.shield import CyberSentinel


class CyberSentinelCrewWrapper:
    """
    Wraps CrewAI tools with Tier-0 runtime security screening.
    """

    def __init__(self, sentinel: Optional[CyberSentinel] = None):
        self.sentinel = sentinel or CyberSentinel(strict=True)

    def wrap_tool(self, tool_fn: Callable[..., Any], name: Optional[str] = None) -> Callable[..., Any]:
        """Decorates a CrewAI tool to intercept SSRF, toxic arguments, and secret leaks."""
        tool_name = name or getattr(tool_fn, "__name__", "crewai_tool")

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            inputs = {"args": args, "kwargs": kwargs}
            # 1. Screen tool execution
            self.sentinel.inspect_tool_call(tool_name, inputs)

            # 2. Run target tool
            result = tool_fn(*args, **kwargs)

            # 3. Screen output for credentials
            if isinstance(result, str):
                insp = self.sentinel.inspect_output(result)
                return insp.sanitized_text

            return result

        return wrapped
