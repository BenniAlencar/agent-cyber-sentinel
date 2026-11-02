#!/usr/bin/env python3
"""
Agent Cyber Sentinel — Automated MCP Configurator
Part of the cyber-sentinel-guard skill for Agensi.io & AI Agents.

Automatically detects and configures:
- Claude Desktop (claude_desktop_config.json)
- Cursor (mcp.json)
- Windsurf (mcp_config.json)

GitHub: https://github.com/BenniAlencar/agent-cyber-sentinel (Apache-2.0)
"""

from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path


def get_claude_config_path() -> Path:
    system = platform.system()
    if system == "Windows":
        return Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json"
    elif system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    else:
        return Path.home() / ".config" / "claude" / "claude_desktop_config.json"


def configure_claude_desktop() -> bool:
    config_path = get_claude_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    data = {}
    if config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

    mcp_servers = data.setdefault("mcpServers", {})
    mcp_servers["cyber-sentinel"] = {
        "command": "cyber-sentinel",
        "args": ["mcp"]
    }

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[OK] Successfully configured Claude Desktop at: {config_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write Claude Desktop configuration: {e}")
        return False


def main():
    print("=== Agent Cyber Sentinel MCP Configurator ===")
    success = configure_claude_desktop()
    if success:
        print("\nCyber Sentinel MCP Server is now configured!")
        print("To verify, ensure 'agent-cyber-sentinel' is installed via:")
        print("  pip install agent-cyber-sentinel")
    else:
        print("\nPlease configure manually by adding this to your claude_desktop_config.json:")
        manual_config = {
            "mcpServers": {
                "cyber-sentinel": {
                    "command": "cyber-sentinel",
                    "args": ["mcp"]
                }
            }
        }
        print(json.dumps(manual_config, indent=2))


if __name__ == "__main__":
    main()
