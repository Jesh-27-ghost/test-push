"""
ShieldProxy — PII Scrubber
Dual-pipeline: Regex patterns + spaCy NER for comprehensive PII detection.

Pipeline Architecture:
  1. Regex pass — catches structured PII (emails, phones, Aadhaar, PAN,
     credit cards, API keys, SSN, passport, IP addresses, URLs with creds)
  2. spaCy NER pass — catches unstructured PII (person names, organizations,
     locations, dates, monetary values)
  3. Deduplication — merges findings from both passes
  4. Returns scrubbed text + detailed findings list

Optimizations:
  - spaCy model loaded once at module level (lazy init)
  - NER disabled for components we don't need (parser, lemmatizer)
  - Regex runs first so NER doesn't waste time on already-redacted text
"""

import logging
import re
from typing import Tuple, List, Dict, Optional

logger = logging.getLogger("shieldproxy.scrubber")

# ═══════════════════════════════════════════════════════════════
# spaCy NER engine (lazy-loaded singleton)
# ═══════════════════════════════════════════════════════════════

_nlp = None
_spacy_available = False


def _load_spacy():
    """Lazy-load the spaCy NER model on first use."""
    global _nlp, _spacy_available
    try:
        import spacy
        _nlp = spacy.load(
            "en_core_web_sm",
            disable=["parser", "lemmatizer", "textcat"],  # only need NER + tok
        )
        _spacy_available = True
        logger.info("✅ spaCy NER model loaded (en_core_web_sm)")
    except Exception as e:
        _spacy_available = False
        logger.warning(f"⚠️  spaCy unavailable: {e} — using regex-only")


def init_scrubber():
    """Initialize the scrubber (call on startup)."""
    _load_spacy()
    return _spacy_available


def is_spacy_available() -> bool:
    return _spacy_available


def get_scrubber_stats() -> dict:
    return {
        "spacy_available": _spacy_available,
        "spacy_model": "en_core_web_sm" if _spacy_available else None,
        "regex_patterns": len(REGEX_PATTERNS),
        "ner_entity_types": list(NER_ENTITY_MAP.keys()) if _spacy_available else [],
    }


# ═══════════════════════════════════════════════════════════════
# PASS 1: Regex patterns for structured PII
# ═══════════════════════════════════════════════════════════════

REGEX_PATTERNS = [
    # ── API keys / secrets ──────────────────────────
    {
        "pattern": r'(?:sk|pk|api|key|token|secret|access)[_-]?(?:live|test|prod)?[_-]?[A-Za-z0-9]{20,}',
        "replacement": "[API_KEY]",
        "label": "api_key",
        "description": "API key / secret token",
    },
    # ── Email addresses ─────────────────────────────
    {
        "pattern": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "replacement": "[EMAIL]",
        "label": "email",
        "description": "Email address",
    },
    # ── Indian Aadhaar (4-4-4 digit) ────────────────
    {
        "pattern": r'\b\d{4}\s\d{4}\s\d{4}\b',
        "replacement": "[AADHAAR]",
        "label": "aadhaar",
        "description": "Aadhaar number (India)",
    },
    # ── Indian PAN card (ABCDE1234F) ────────────────
    {
        "pattern": r'\b[A-Z]{5}\d{4}[A-Z]\b',
        "replacement": "[PAN]",
        "label": "pan",
        "description": "PAN card number (India)",
    },
    # ── Indian phone (10 digits, starts 6-9) ────────
    {
        "pattern": r'(?:\+91[\s-]?)?[6-9]\d{9}\b',
        "replacement": "[PHONE]",
        "label": "phone",
        "description": "Indian phone number",
    },
    # ── International phone numbers ─────────────────
    {
        "pattern": r'\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}',
        "replacement": "[PHONE]",
        "label": "phone",
        "description": "International phone number",
    },
    # ── Credit / debit card (16 digits) ─────────────
    {
        "pattern": r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        "replacement": "[CARD]",
        "label": "credit_card",
        "description": "Credit/debit card number",
    },
    # ── US SSN (xxx-xx-xxxx) ────────────────────────
    {
        "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
        "replacement": "[SSN]",
        "label": "ssn",
        "description": "US Social Security Number",
    },
    # ── Passport numbers (alphanumeric, 6-9 chars) ──
    {
        "pattern": r'\b[A-Z]{1,2}\d{6,8}\b',
        "replacement": "[PASSPORT]",
        "label": "passport",
        "description": "Passport number",
    },
    # ── IP addresses (IPv4) ─────────────────────────
    {
        "pattern": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "replacement": "[IP_ADDR]",
        "label": "ip_address",
        "description": "IPv4 address",
    },
    # ── URLs with credentials ───────────────────────
    {
        "pattern": r'https?://[^\s:]+:[^\s@]+@[^\s]+',
        "replacement": "[URL_WITH_CREDS]",
        "label": "url_credentials",
        "description": "URL with embedded credentials",
    },
    # ── AWS access keys ─────────────────────────────
    {
        "pattern": r'\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b',
        "replacement": "[AWS_KEY]",
        "label": "aws_key",
        "description": "AWS access key ID",
    },
    # ── JWT tokens ──────────────────────────────────
    {
        "pattern": r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
        "replacement": "[JWT_TOKEN]",
        "label": "jwt_token",
        "description": "JWT token",
    },
]

# Pre-compile all regex patterns for performance
_compiled_patterns = [
    {
        **p,
        "_re": re.compile(p["pattern"]),
    }
    for p in REGEX_PATTERNS
]


# ═══════════════════════════════════════════════════════════════
# PASS 2: spaCy NER entity mapping
# ═══════════════════════════════════════════════════════════════

NER_ENTITY_MAP = {
    "PERSON":     {"replacement": "[PERSON]",     "label": "person_name",  "description": "Person name"},
    "ORG":        {"replacement": "[ORG]",        "label": "organization", "description": "Organization name"},
    "GPE":        {"replacement": "[LOCATION]",   "label": "location",     "description": "Geo-political entity"},
    "LOC":        {"replacement": "[LOCATION]",   "label": "location",     "description": "Location"},
    "DATE":       {"replacement": "[DATE]",       "label": "date",         "description": "Date reference"},
    "MONEY":      {"replacement": "[MONEY]",      "label": "money",        "description": "Monetary value"},
    "CARDINAL":   None,  # Skip — too noisy (any number)
    "ORDINAL":    None,  # Skip
    "NORP":       None,  # Skip — nationalities/groups (too broad)
    "EVENT":      None,  # Skip
    "WORK_OF_ART": None, # Skip
    "LANGUAGE":   None,  # Skip
    "FAC":        None,  # Skip — facilities
    "PRODUCT":    None,  # Skip
    "LAW":        None,  # Skip
    "QUANTITY":   None,  # Skip
    "PERCENT":    None,  # Skip
    "TIME":       None,  # Skip
}

# Minimum entity length to avoid false positives
MIN_ENTITY_LENGTH = 2


# ═══════════════════════════════════════════════════════════════
# Regex scrubbing pass
# ═══════════════════════════════════════════════════════════════

def _scrub_regex(text: str) -> Tuple[str, List[Dict]]:
    """
    Pass 1: Regex-based PII detection and redaction.
    Returns (scrubbed_text, list of finding dicts).
    """
    findings: List[Dict] = []
    scrubbed = text

    for p in _compiled_patterns:
        matches = p["_re"].findall(scrubbed)
        if matches:
            for match_text in matches:
                findings.append({
                    "type": p["label"],
                    "original": _mask_value(match_text),
                    "replacement": p["replacement"],
                    "source": "regex",
                    "description": p["description"],
                })
            scrubbed = p["_re"].sub(p["replacement"], scrubbed)

    return scrubbed, findings


# ═══════════════════════════════════════════════════════════════
# spaCy NER scrubbing pass
# ═══════════════════════════════════════════════════════════════

def _scrub_ner(text: str) -> Tuple[str, List[Dict]]:
    """
    Pass 2: spaCy NER-based PII detection and redaction.
    Runs on already regex-scrubbed text.
    Returns (scrubbed_text, list of finding dicts).
    """
    if not _spacy_available or not _nlp:
        return text, []

    findings: List[Dict] = []
    doc = _nlp(text)

    # Collect entities to replace (process in reverse to preserve positions)
    entities_to_replace = []
    for ent in doc.ents:
        mapping = NER_ENTITY_MAP.get(ent.label_)
        if mapping is None:
            continue  # Skip this entity type

        # Skip very short entities (false positives)
        if len(ent.text.strip()) < MIN_ENTITY_LENGTH:
            continue

        # Skip if it's already a redaction tag
        if ent.text.startswith("[") and ent.text.endswith("]"):
            continue

        entities_to_replace.append({
            "start": ent.start_char,
            "end": ent.end_char,
            "text": ent.text,
            "label": ent.label_,
            "mapping": mapping,
        })

        findings.append({
            "type": mapping["label"],
            "original": _mask_value(ent.text),
            "replacement": mapping["replacement"],
            "source": "spacy_ner",
            "description": mapping["description"],
            "ner_label": ent.label_,
        })

    # Replace entities in reverse order to preserve character positions
    scrubbed = text
    for ent_info in reversed(entities_to_replace):
        scrubbed = (
            scrubbed[:ent_info["start"]]
            + ent_info["mapping"]["replacement"]
            + scrubbed[ent_info["end"]:]
        )

    return scrubbed, findings


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _mask_value(value: str) -> str:
    """
    Partially mask a detected PII value for audit logging.
    Shows first 2 and last 2 chars, rest masked.
    """
    v = str(value).strip()
    if len(v) <= 5:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


def _deduplicate_findings(findings: List[Dict]) -> List[str]:
    """
    Deduplicate findings into a clean list of PII types found.
    Returns unique labels only.
    """
    seen = set()
    unique = []
    for f in findings:
        label = f["type"]
        if label not in seen:
            seen.add(label)
            unique.append(label)
    return unique


# ═══════════════════════════════════════════════════════════════
# Main scrub pipeline
# ═══════════════════════════════════════════════════════════════

def scrub_pii(text: str) -> Tuple[str, List[str]]:
    """
    Full PII scrubbing pipeline:
      1. Regex pass → structured PII (emails, phones, cards, etc.)
      2. spaCy NER pass → unstructured PII (names, orgs, locations)
      3. Deduplicate findings
      4. Return (scrubbed_text, list_of_pii_types_found)
    """
    # ── Pass 1: Regex ───────────────────────────────────────────
    scrubbed, regex_findings = _scrub_regex(text)

    # ── Pass 2: spaCy NER (on already regex-cleaned text) ──────
    scrubbed, ner_findings = _scrub_ner(scrubbed)

    # ── Merge & deduplicate ─────────────────────────────────────
    all_findings = regex_findings + ner_findings
    pii_types = _deduplicate_findings(all_findings)

    return scrubbed, pii_types


def scrub_pii_detailed(text: str) -> Dict:
    """
    Full scrub with detailed findings (for debugging / auditing).
    Returns {
        scrubbed: str,
        pii_found: [str],
        details: [{ type, original, replacement, source, description }],
        regex_count: int,
        ner_count: int,
    }
    """
    scrubbed, regex_findings = _scrub_regex(text)
    scrubbed, ner_findings = _scrub_ner(scrubbed)

    all_findings = regex_findings + ner_findings
    pii_types = _deduplicate_findings(all_findings)

    return {
        "scrubbed": scrubbed,
        "pii_found": pii_types,
        "details": all_findings,
        "regex_count": len(regex_findings),
        "ner_count": len(ner_findings),
    }
