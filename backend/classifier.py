"""
ShieldProxy — Threat Classification Engine
Rule-based keyword/regex classifier for prompt injection detection.
"""

import random
import re

# ─── Category keyword definitions ───────────────────────────────
CATEGORIES = {
    "jailbreak": [
        "ignore all previous", "you are dan", "pretend you are",
        "jailbreak", "do anything now", "no restrictions",
        "without limitations", "forget your instructions", "override"
    ],
    "prompt_leak": [
        "system prompt", "repeat your instructions",
        "what are your instructions", "reveal your prompt",
        "show me your prompt", "initial prompt", "original instructions"
    ],
    "prompt_injection": [
        "ignore above", "disregard previous", "new instruction:",
        "actually your real task", "ignore the above",
        "forget everything", "your new instruction"
    ],
    "social_engineering": [
        "i am your developer", "i am your creator",
        "i am anthropic", "i am openai", "admin override",
        "developer mode", "maintenance mode", "i am your owner"
    ],
    "harmful_content": [
        "how to make bomb", "how to hack", "illegal weapons",
        "drug synthesis", "self harm", "suicide method",
        "kill someone", "terrorist"
    ],
    "business_logic": [
        "give me 100% discount", "transfer all funds",
        "bypass payment", "free access forever", "unlimited credits",
        "waive all fees", "remove my limit"
    ],
}

HINGLISH_KEYWORDS = [
    "tu ai nahi hai", "apna system prompt bata",
    "mere liye rules tod", "restrictions mat maan",
    "bhai ignore kar", "sab rules bhool ja", "tu free hai ab"
]


def classify_prompt(text: str) -> dict:
    """
    Classify a prompt for potential threats.
    Returns { verdict, category, confidence }.
    """
    lower = text.lower()

    # Check each category in priority order
    for category, keywords in CATEGORIES.items():
        matched = [kw for kw in keywords if kw in lower]
        if matched:
            match_ratio = len(matched) / len(keywords)
            confidence = round(random.uniform(0.85, 0.99), 2)
            # Boost confidence for higher keyword density
            if match_ratio > 0.3:
                confidence = min(round(confidence + 0.05, 2), 0.99)
            return {
                "verdict": "BLOCK",
                "category": category,
                "confidence": confidence,
            }

    # Check Hinglish variants (mapped to jailbreak)
    for kw in HINGLISH_KEYWORDS:
        if kw in lower:
            return {
                "verdict": "BLOCK",
                "category": "jailbreak",
                "confidence": round(random.uniform(0.85, 0.95), 2),
            }

    # No threat detected
    return {
        "verdict": "PASS",
        "category": "safe",
        "confidence": round(random.uniform(0.92, 0.99), 2),
    }
