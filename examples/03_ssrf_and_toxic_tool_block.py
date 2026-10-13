"""
Example 03: SSRF Protection & Toxic Tool Command Interceptor.
Demonstrates blocking malicious agent tool calls targeting cloud metadata, destructive shell commands, and path traversal.
"""

from cyber_sentinel import CyberSentinel, SSRFBlockedError, ToxicToolBlockedError


def main() -> None:
    print("--- [AGENT-CYBER-SENTINEL] Tool Call Sanitizer & SSRF Shield Demo ---\n")

    sentinel = CyberSentinel(strict=True)

    # 1. SSRF Attack against AWS/GCP Cloud Metadata (Blocked)
    print("1. Testing SSRF Cloud Metadata Exploit:")
    ssrf_args = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    try:
        sentinel.inspect_tool_call("http_fetch", ssrf_args)
    except SSRFBlockedError as e:
        print(f"   [BLOCKED] {e}\n")

    # 2. SSRF Attack targeting Localhost/Loopback (Blocked)
    print("2. Testing SSRF Loopback Exploit:")
    loopback_args = {"url": "http://127.0.0.1:8080/admin/delete_all"}
    try:
        sentinel.inspect_tool_call("fetch_webpage", loopback_args)
    except SSRFBlockedError as e:
        print(f"   [BLOCKED] {e}\n")

    # 3. Toxic Command Attack (Blocked)
    print("3. Testing Destructive Shell Command Execution:")
    toxic_args = {"command": "rm -rf /"}
    try:
        sentinel.inspect_tool_call("run_bash", toxic_args)
    except ToxicToolBlockedError as e:
        print(f"   [BLOCKED] {e}\n")

    # 4. Safe Tool Call (Permitted)
    print("4. Testing Benign Tool Execution:")
    safe_args = {"url": "https://api.github.com/repos/BenniAlencar/agent-cyber-sentinel"}
    res = sentinel.inspect_tool_call("http_get", safe_args)
    print(f"   [PERMITTED] Tool Call Allowed! Is Safe: {res.is_safe} | Threat Level: {res.threat_level.value}")


if __name__ == "__main__":
    main()
