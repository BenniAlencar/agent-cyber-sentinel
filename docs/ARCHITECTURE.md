# Agent Cyber Sentinel — Architecture Specification

**Doctrine:** Benni Master OS v9.4 — Skill 63 (Cyber Sentinel OS / POD-9 Proof-of-Defense)

---

## 1. System Overview

`agent-cyber-sentinel` is a sub-millisecond, zero-dependency Tier-0 runtime defense shield for autonomous AI agents and MCP servers. Every prompt, output, and tool invocation passes through POD-9 gates (`SG-4`, `SG-5`, `SG-6`) and yields a SHA-256 signed `Pod9ProofEnvelope`.

```text
  OpenAI SDK / LangChain / CrewAI / MCP Clients / Autonomous Agents
         │
         ├──► CyberSentinel.inspect_prompt / inspect_output / inspect_tool_call
         └──► McpSecurityGuard (JSON-RPC 2.0 Security Proxy)
                       │
                       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        agent-cyber-sentinel                         │
  │                                                                     │
  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │
  │  │ SG-5 Injection    │  │  SG-6 Secret      │  │ SG-4 Tool Call  │  │
  │  │ Firewall (L5)     │─►│  Interceptor (L6) │─►│ Sanitizer (L4)  │  │
  │  │ • Role Hijack     │  │  • API Key Regex  │  │ • SSRF Guard    │  │
  │  │ • Canary Tokens   │  │  • Shannon Entropy│  │ • Toxic Command │  │
  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │
  │                                                                     │
  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │
  │  │ POD-9 Proof       │  │  Framework        │  │ Tools & CLI     │  │
  │  │ Envelope          │  │  Adapters         │  │ • doctor        │  │
  │  │ • SHA-256 Claims  │  │  • OpenAI Guard   │  │ • bench_matrix  │  │
  │  │ • Tamper Verify   │  │  • LangChain/Crew │  │ • scan-text     │  │
  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Components

| Module | Responsibility |
|---|---|
| `cyber_sentinel/shield.py` | `CyberSentinel` unified runtime shield orchestrating SG-4, SG-5, and SG-6 |
| `cyber_sentinel/detectors/prompt_injection.py` | `PromptInjectionDetector` for direct/indirect injections & canary leaks |
| `cyber_sentinel/detectors/secret_leak.py` | `SecretLeakDetector` with regex + Shannon entropy credential redaction |
| `cyber_sentinel/detectors/tool_sanitizer.py` | `ToolCallSanitizer` blocking SSRF (`169.254.169.254`, RFC1918) & destructive commands |
| `cyber_sentinel/core/envelope.py` | `Pod9ProofEnvelope` SHA-256 signed compliance & tamper-detection record |
| `cyber_sentinel/core/models.py` | `InspectionResult`, `ThreatFinding`, `SecurityThreatLevel`, exception hierarchy |
| `cyber_sentinel/adapters/` | Drop-in guards for `openai_guard`, `langchain`, `crewai`, and `mcp_guard` |
| `cyber_sentinel/tools/` | `doctor.py` POD-9 gate probe and `bench_matrix.py` sub-ms latency matrix |
| `cyber_sentinel/cli/main.py` | Click + Rich CLI (`info`, `scan-text`, `inspect-tool`, `redact`, `verify-envelope`, `mcp`, `doctor`, `matrix`) |

---

## 3. Verification Gates

- `scripts/gate_pod9_defense_runner.py`: Fail-closed gate verifying SG-5 injection blocking, SG-6 secret redaction, SG-4 SSRF/toxic command blocking, and POD-9 envelope tamper rejection.
- `scripts/benchmark_sentinel_latency.py`: Multi-gate inspection latency and throughput benchmark.
