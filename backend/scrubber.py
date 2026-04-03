"""
ShieldProxy — PII Scrubber
Regex-based detection and redaction of personally identifiable information.
"""

import re
from typing import Tuple, List

# ─── PII regex patterns ────────────────────────────────────────
PII_PATTERNS = [
    # API keys (sk- prefix) — check first to avoid partial matches
    (r'sk-[A-Za-z0-9]{20,}', "[API_KEY]", "api_key"),
    # Email addresses
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "[EMAIL]", "email"),
    # Indian phone numbers (10 digits starting with 6-9)
    (r'\b[6-9]\d{9}\b', "[PHONE]", "phone"),
    # Aadhaar numbers (4-4-4 digit pattern)
    (r'\b\d{4}\s\d{4}\s\d{4}\b', "[AADHAAR]", "aadhaar"),
    # PAN card (5 letters + 4 digits + 1 letter)
    (r'\b[A-Z]{5}\d{4}[A-Z]\b', "[PAN]", "pan"),
    # Credit card numbers (16 digits, with optional spaces/dashes)
    (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', "[CARD]", "credit_card"),
]


def scrub_pii(text: str) -> Tuple[str, List[str]]:
    """
    Scan and redact PII from the given text.
    Returns (scrubbed_text, list_of_found_pii_types).
    """
    found: List[str] = []
    scrubbed = text

    for pattern, replacement, label in PII_PATTERNS:
        matches = re.findall(pattern, scrubbed)
        if matches:
            if label not in found:
                found.append(label)
            scrubbed = re.sub(pattern, replacement, scrubbed)

    return scrubbed, found
