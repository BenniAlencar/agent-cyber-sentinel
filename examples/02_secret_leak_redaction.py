"""
Example 02: Secret Leak Interceptor & Automatic Redaction.
Demonstrates catching OpenAI keys, AWS tokens, database passwords, and high-entropy secrets in text.
"""

from cyber_sentinel import CyberSentinel


def main() -> None:
    print("--- [AGENT-CYBER-SENTINEL] Secret Leak Interceptor Demo ---\n")

    sentinel = CyberSentinel(strict=False, auto_redact_secrets=True)

    # Simulated model output or agent log containing credentials
    dangerous_output = (
        "Deployment configured successfully.\n"
        "Configured OpenAI Key: sk-proj-99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6\n"
        "AWS Credentials: AKIAIOSFODNN7EXAMPLE\n"
        "Database URI: postgresql://admin:SuperSecretPass123!@db.internal:5432/production\n"
        "Access token: ghp_111122223333444455556666777788889999"
    )

    print("1. Raw Output with Exposed Secrets:")
    print("--------------------------------------------------")
    print(dangerous_output)
    print("--------------------------------------------------\n")

    # Run inspection
    result = sentinel.inspect_output(dangerous_output)

    print("2. Sanitized Output (Redacted In-Memory):")
    print("--------------------------------------------------")
    print(result.sanitized_text)
    print("--------------------------------------------------\n")

    print(f"Total Secrets Redacted: {len(result.findings)}")
    for i, finding in enumerate(result.findings, 1):
        print(f"   [{i}] {finding.rule_name}: {finding.description} (Sample: {finding.matched_sample})")

    # Generate POD-9 proof envelope
    proof = sentinel.create_proof("model-response-stream", result)
    print(f"\n3. Cryptographic POD-9 Seal Generated:")
    print(f"   Envelope ID: {proof.envelope_id}")
    print(f"   Layer: {proof.pod9_layer} | Gate: {proof.gate} | Decision: {proof.decision}")
    print(f"   Signature: {proof.signature}")
    print(f"   Signature Verification: {'VALID' if proof.verify() else 'INVALID'}")


if __name__ == "__main__":
    main()
