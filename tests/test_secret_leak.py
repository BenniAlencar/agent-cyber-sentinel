"""
Tests for SecretLeakDetector and Shannon entropy calculations.
"""

from cyber_sentinel.detectors.secret_leak import SecretLeakDetector, shannon_entropy


def test_shannon_entropy_calculation():
    # Low entropy (repetitive)
    low_ent = shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # High entropy (random alphanumeric base64)
    high_ent = shannon_entropy("7x9Qz!mK8#vL2$pW4@jR6%tY")
    assert high_ent >= 4.0


def test_benign_text_no_secrets():
    detector = SecretLeakDetector()
    sanitized, findings = detector.scan_and_redact("The project was deployed to production at 14:00 UTC.")
    assert len(findings) == 0
    assert sanitized == "The project was deployed to production at 14:00 UTC."


def test_openai_api_key_redaction():
    detector = SecretLeakDetector()
    raw = "My key is sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef."
    sanitized, findings = detector.scan_and_redact(raw)
    assert len(findings) >= 1
    assert "SECRET_OPENAI_KEY" in [f.rule_name for f in findings]
    assert "sk-proj-" not in sanitized
    assert "[REDACTED_SECRET_OPENAI_KEY]" in sanitized


def test_aws_key_redaction():
    detector = SecretLeakDetector()
    raw = "AWS Access Key is AKIAIOSFODNN7EXAMPLE used for S3."
    sanitized, findings = detector.scan_and_redact(raw)
    assert len(findings) >= 1
    assert "SECRET_AWS_ACCESS_KEY" in [f.rule_name for f in findings]
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED_SECRET_AWS_ACCESS_KEY]" in sanitized


def test_database_password_redaction():
    detector = SecretLeakDetector()
    raw = "Connect to postgresql://postgres:MyVerySecretPassword123@localhost:5432/mydb"
    sanitized, findings = detector.scan_and_redact(raw)
    assert len(findings) >= 1
    assert "SECRET_DB_PASSWORD" in [f.rule_name for f in findings]
    assert "MyVerySecretPassword123" not in sanitized


def test_jwt_token_redaction():
    detector = SecretLeakDetector()
    fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw = f"Bearer {fake_jwt}"
    sanitized, findings = detector.scan_and_redact(raw)
    assert len(findings) >= 1
    assert "SECRET_JWT_TOKEN" in [f.rule_name for f in findings]
    assert fake_jwt not in sanitized
