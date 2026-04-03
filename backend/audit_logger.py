"""
ShieldProxy — Audit Logger
In-memory FIFO audit log (max 1000 entries).
"""

import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Optional

# ─── In-memory log store ────────────────────────────────────────
_logs: List[dict] = []
MAX_ENTRIES = 1000


def add_entry(
    api_key: str,
    prompt: str,
    verdict: str,
    category: str,
    confidence: float,
    latency_ms: float,
    pii_found: list,
    client_ip: str = "0.0.0.0",
    timestamp: Optional[float] = None,
) -> dict:
    """Add an audit log entry. Returns the created entry."""
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp or time.time(),
        "api_key": api_key,
        "prompt_snippet": prompt[:80],
        "verdict": verdict,
        "category": category,
        "confidence": confidence,
        "latency_ms": round(latency_ms, 2),
        "pii_found": pii_found,
        "client_ip": client_ip,
    }
    _logs.append(entry)
    # FIFO eviction
    if len(_logs) > MAX_ENTRIES:
        _logs.pop(0)
    return entry


def get_recent(limit: int = 50) -> List[dict]:
    """Return the most recent `limit` entries (newest first)."""
    return list(reversed(_logs[-limit:]))


def get_by_key(api_key: str) -> List[dict]:
    """Return all entries for a given API key."""
    return [e for e in _logs if e["api_key"] == api_key]


def get_stats() -> dict:
    """Compute aggregate statistics for the dashboard."""
    total = len(_logs)
    blocked = sum(1 for e in _logs if e["verdict"] == "BLOCK")
    latencies = [e["latency_ms"] for e in _logs]

    # Category breakdown
    cat_breakdown = defaultdict(int)
    for e in _logs:
        cat_breakdown[e["category"]] += 1

    # Hourly data for last 24h
    now = time.time()
    hourly: dict = {}
    for h in range(24):
        hour_start = now - (h + 1) * 3600
        hour_end = now - h * 3600
        hour_label = datetime.fromtimestamp(hour_end, tz=timezone.utc).strftime("%H:00")
        entries_in_hour = [
            e for e in _logs if hour_start <= e["timestamp"] < hour_end
        ]
        hourly[hour_label] = {
            "hour": hour_label,
            "requests": len(entries_in_hour),
            "blocked": sum(1 for e in entries_in_hour if e["verdict"] == "BLOCK"),
        }
    hourly_list = list(reversed(list(hourly.values())))

    # Top attack categories (exclude "safe")
    attack_cats = {k: v for k, v in cat_breakdown.items() if k != "safe"}
    total_attacks = sum(attack_cats.values()) or 1
    top_attacks = sorted(
        [
            {
                "category": k,
                "count": v,
                "percentage": round(v / total_attacks * 100, 1),
            }
            for k, v in attack_cats.items()
        ],
        key=lambda x: x["count"],
        reverse=True,
    )

    return {
        "total_requests": total,
        "total_blocked": blocked,
        "block_rate": round(blocked / total * 100, 1) if total else 0,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "category_breakdown": dict(cat_breakdown),
        "hourly_data": hourly_list,
        "top_attack_categories": top_attacks,
    }


def get_latest() -> Optional[dict]:
    """Return the latest entry, if any."""
    return _logs[-1] if _logs else None


def get_client_stats() -> list:
    """Return per-API-key aggregate statistics."""
    clients: dict = defaultdict(lambda: {
        "total_requests": 0,
        "blocked": 0,
        "categories": defaultdict(int),
        "last_seen": 0,
    })
    for e in _logs:
        c = clients[e["api_key"]]
        c["total_requests"] += 1
        if e["verdict"] == "BLOCK":
            c["blocked"] += 1
        c["categories"][e["category"]] += 1
        c["last_seen"] = max(c["last_seen"], e["timestamp"])

    result = []
    for key, data in clients.items():
        block_rate = round(data["blocked"] / data["total_requests"] * 100, 1) if data["total_requests"] else 0
        top_cat = max(data["categories"], key=data["categories"].get) if data["categories"] else "none"
        masked_key = f"***{key[-4:]}" if len(key) > 4 else key
        result.append({
            "api_key": masked_key,
            "api_key_full": key,
            "total_requests": data["total_requests"],
            "blocked": data["blocked"],
            "block_rate": block_rate,
            "top_category": top_cat,
            "last_seen": datetime.fromtimestamp(data["last_seen"], tz=timezone.utc).isoformat(),
            "status": "high_risk" if block_rate > 30 else "active",
            "category_breakdown": dict(data["categories"]),
        })

    return sorted(result, key=lambda x: x["total_requests"], reverse=True)
