# MCP Configuration Guide for Agent Cyber Sentinel

Easily integrate Agent Cyber Sentinel into your favorite AI agent harness:

---

## 1. Claude Desktop (`claude_desktop_config.json`)

**Location:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cyber-sentinel": {
      "command": "cyber-sentinel",
      "args": ["mcp"]
    }
  }
}
```

---

## 2. Cursor (`mcp.json`)

Go to **Cursor Settings > Features > MCP**, or edit `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "cyber-sentinel": {
      "command": "cyber-sentinel",
      "args": ["mcp"]
    }
  }
}
```

---

## 3. Python Virtual Environments (Custom Path)

If installed in a specific virtualenv:

```json
{
  "mcpServers": {
    "cyber-sentinel": {
      "command": "/path/to/venv/bin/cyber-sentinel",
      "args": ["mcp"]
    }
  }
}
```

---

## Available Native MCP Tools

Once connected, your AI agent gains access to:

1. `sentinel_scan_prompt`: Evaluates input text for prompt injection, jailbreaks, and leaked secrets.
2. `sentinel_scan_tool_call`: Inspects planned tool names and arguments for SSRF and toxic shell commands.
3. `sentinel_redact_secrets`: Automatically strips credentials from logs, outputs, and files.
4. `sentinel_verify_pod9`: Verifies cryptographic signatures of POD-9 defense envelopes.
