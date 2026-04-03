"""
ShieldProxy — Audit Logger
SQLite-backed persistent audit log.
"""

import sqlite3
import time
import uuid
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Optional

DB_FILE = "shieldproxy_audit.db"


def _get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            api_key TEXT,
            prompt_snippet TEXT,
            verdict TEXT,
            category TEXT,
            confidence REAL,
            latency_ms REAL,
            pii_found TEXT,
            client_ip TEXT
        )
    ''')
    # Indices for performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_api_key ON audit_logs(api_key)')
    conn.commit()
    conn.close()


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
    ts = timestamp or time.time()
    entry_id = str(uuid.uuid4())
    snippet = prompt[:80]
    
    conn = _get_conn()
    c = conn.cursor()
    c.execute('''
        INSERT INTO audit_logs (
            id, timestamp, api_key, prompt_snippet, verdict,
            category, confidence, latency_ms, pii_found, client_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        entry_id, ts, api_key, snippet, verdict,
        category, confidence, round(latency_ms, 2),
        json.dumps(pii_found), client_ip
    ))
    conn.commit()
    conn.close()

    return {
        "id": entry_id,
        "timestamp": ts,
        "api_key": api_key,
        "prompt_snippet": snippet,
        "verdict": verdict,
        "category": category,
        "confidence": confidence,
        "latency_ms": round(latency_ms, 2),
        "pii_found": pii_found,
        "client_ip": client_ip,
    }


def get_recent(limit: int = 50) -> List[dict]:
    conn = _get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    
    res = []
    for r in rows:
        d = dict(r)
        d["pii_found"] = json.loads(d["pii_found"]) if d["pii_found"] else []
        res.append(d)
    return res


def get_by_key(api_key: str) -> List[dict]:
    conn = _get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM audit_logs WHERE api_key = ? ORDER BY timestamp DESC', (api_key,))
    rows = c.fetchall()
    conn.close()
    
    res = []
    for r in rows:
        d = dict(r)
        d["pii_found"] = json.loads(d["pii_found"]) if d["pii_found"] else []
        res.append(d)
    return res


def get_total_count() -> int:
    conn = _get_conn()
    c = conn.cursor()
    try:
        c.execute('SELECT COUNT(*) FROM audit_logs')
        count = c.fetchone()[0]
    except sqlite3.OperationalError:
        count = 0
    conn.close()
    return count


def get_stats() -> dict:
    conn = _get_conn()
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM audit_logs')
    total = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM audit_logs WHERE verdict = "BLOCK"')
    blocked = c.fetchone()[0]
    
    c.execute('SELECT AVG(latency_ms) FROM audit_logs')
    avg_lat = c.fetchone()[0] or 0.0
    
    # Category breakdown
    c.execute('SELECT category, COUNT(*) FROM audit_logs GROUP BY category')
    cat_rows = c.fetchall()
    cat_breakdown = {r[0]: r[1] for r in cat_rows}
    
    # Hourly data for last 24h
    now = time.time()
    hourly = []
    for h in range(23, -1, -1):
        hour_start = now - (h + 1) * 3600
        hour_end = now - h * 3600
        hour_label = datetime.fromtimestamp(hour_end, tz=timezone.utc).strftime("%H:00")
        
        c.execute('''
            SELECT COUNT(*), SUM(CASE WHEN verdict = 'BLOCK' THEN 1 ELSE 0 END)
            FROM audit_logs WHERE timestamp >= ? AND timestamp < ?
        ''', (hour_start, hour_end))
        reqs, blk = c.fetchone()
        
        hourly.append({
            "hour": hour_label,
            "requests": reqs or 0,
            "blocked": blk or 0,
        })
        
    conn.close()
    
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
        "avg_latency_ms": round(avg_lat, 2),
        "category_breakdown": cat_breakdown,
        "hourly_data": hourly,
        "top_attack_categories": top_attacks,
    }


def get_latest() -> Optional[dict]:
    conn = _get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
    r = c.fetchone()
    conn.close()
    if r:
        d = dict(r)
        d["pii_found"] = json.loads(d["pii_found"]) if d["pii_found"] else []
        return d
    return None


def get_client_stats() -> list:
    conn = _get_conn()
    c = conn.cursor()
    c.execute('''
        SELECT api_key, COUNT(*) as total_reqs,
               SUM(CASE WHEN verdict = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
               MAX(timestamp) as last_seen
        FROM audit_logs GROUP BY api_key
    ''')
    summary_rows = c.fetchall()
    
    c.execute('SELECT api_key, category, COUNT(*) FROM audit_logs GROUP BY api_key, category')
    cat_rows = c.fetchall()
    conn.close()
    
    cats_by_key = defaultdict(dict)
    for api_key, cat, count in cat_rows:
        cats_by_key[api_key][cat] = count
        
    result = []
    for r in summary_rows:
        key = r["api_key"]
        total = r["total_reqs"]
        blocked = r["blocked"] or 0
        last_seen = r["last_seen"]
        
        block_rate = round(blocked / total * 100, 1) if total else 0
        cats = cats_by_key[key]
        top_cat = max(cats, key=cats.get) if cats else "none"
        masked_key = f"***{key[-4:]}" if len(key) > 4 else key
        
        result.append({
            "api_key": masked_key,
            "api_key_full": key,
            "total_requests": total,
            "blocked": blocked,
            "block_rate": block_rate,
            "top_category": top_cat,
            "last_seen": datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat(),
            "status": "high_risk" if block_rate > 30 else "active",
            "category_breakdown": cats,
        })
        
    return sorted(result, key=lambda x: x["total_requests"], reverse=True)
