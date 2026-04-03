"""
ShieldProxy — Output Leak Detection
Scans LLM responses for potential information leakage.
"""

import re

LEAK_PATTERNS = [
    (r"(system prompt|system message|initial instructions)", "system_prompt_leak"),
    (r"(password|secret key|private key|api.?key)\s*[:=]\s*\S+", "credential_leak"),
    (r"(SELECT|INSERT|UPDATE|DELETE)\s+.*(FROM|INTO|SET)", "sql_injection_echo"),
    (r"<script[^>]*>.*?</script>", "xss_echo"),
    (r"(internal\.company|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)", "internal_info_leak"),
]


def scan_output(text: str) -> dict:
    """
    Scan LLM output for potential data leakage.
    Returns { safe: bool, findings: list }.
    """
    findings = []
    lower = text.lower()

    for pattern, label in LEAK_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
            findings.append(label)

    return {
        "safe": len(findings) == 0,
        "findings": findings,
    }
