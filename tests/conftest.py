"""
Test fixtures for Agent Cyber Sentinel.
"""

import pytest
from cyber_sentinel.shield import CyberSentinel


@pytest.fixture
def strict_sentinel() -> CyberSentinel:
    return CyberSentinel(strict=True, canary_tokens={"TEST_CANARY_TOKEN_99"})


@pytest.fixture
def permissive_sentinel() -> CyberSentinel:
    return CyberSentinel(strict=False, auto_redact_secrets=True)
