"""
ShieldProxy — Rate Limiter
In-memory token bucket: 60 requests per minute per API key.
"""

import time
from typing import Dict

# ─── In-memory rate limit store ─────────────────────────────────
_buckets: Dict[str, dict] = {}

RATE_LIMIT = 60        # max requests
WINDOW_SECONDS = 60    # per minute


def check_rate_limit(api_key: str) -> dict:
    """
    Check if the given API key is within the rate limit.
    Returns { allowed, remaining, reset_in }.
    """
    now = time.time()

    if api_key not in _buckets:
        _buckets[api_key] = {"count": 0, "window_start": now}

    bucket = _buckets[api_key]
    elapsed = now - bucket["window_start"]

    # Reset the window if it has expired
    if elapsed >= WINDOW_SECONDS:
        bucket["count"] = 0
        bucket["window_start"] = now
        elapsed = 0

    remaining = RATE_LIMIT - bucket["count"]
    reset_in = round(WINDOW_SECONDS - elapsed, 1)

    if bucket["count"] >= RATE_LIMIT:
        return {"allowed": False, "remaining": 0, "reset_in": reset_in}

    bucket["count"] += 1
    remaining = RATE_LIMIT - bucket["count"]

    return {"allowed": True, "remaining": remaining, "reset_in": reset_in}
