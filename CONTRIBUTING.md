# Contributing to Agent Cyber Sentinel

Thank you for your interest in contributing to **Agent Cyber Sentinel**!

This project is part of the **Benni OS** ecosystem, governed by the **Benni Master OS v9.4 Doctrine (Skill 63 Cyber Sentinel OS)**.

## Core Rules

1. **Reality Lock Principle**:
   - Defenses without verifiable proof are mere decoration.
   - Every threat detector rule or mitigation probe MUST include dated positive and negative unit tests.
   - Never claim an agent or prompt is "100% immune" without an explicit threat scope.

2. **Zero In-Memory Token Leaks**:
   - Redactions and masks must never accidentally log or persist plaintext secrets.
   - Threat findings must truncate or mask sensitive token payload substrings.

3. **Submitting Changes**:
   - Run `pytest tests -v` locally. All tests must pass before opening a Pull Request.
   - Keep code strictly typed with Python 3.10+ typing standards.
   - Follow standard commit naming conventions: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`.

## Development Setup

```bash
git clone https://github.com/BenniAlencar/agent-cyber-sentinel.git
cd agent-cyber-sentinel
pip install -e ".[dev]"
pytest tests -v
```
