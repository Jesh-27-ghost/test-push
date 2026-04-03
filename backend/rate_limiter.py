"""
ShieldProxy — Rate Limiter
Redis-backed token bucket with in-memory fallback.

Token Bucket Algorithm:
  - Each API key gets a bucket with `capacity` tokens.
  - Tokens refill at `refill_rate` tokens per second.
  - Each request consumes 1 token.
  - If the bucket is empty, the request is rejected (429).

Redis Keys (per api_key):
  sp:rl:{api_key}:tokens   — current token count (float)
  sp:rl:{api_key}:ts        — last refill timestamp (float)

Graceful degradation: if Redis is unavailable, falls back to
an in-memory dict-based implementation automatically.
"""

import time
import logging
from typing import Dict, Optional

logger = logging.getLogger("shieldproxy.rate_limiter")

# ─── Configuration ──────────────────────────────────────────────
BUCKET_CAPACITY = 60       # max tokens (burst limit)
REFILL_RATE = 1.0          # tokens per second (60/min)
WINDOW_SECONDS = 60        # for 'reset_in' calculation

# ─── Redis connection ───────────────────────────────────────────
_redis_client = None
_redis_available = False

# ─── In-memory fallback store ───────────────────────────────────
_fallback_buckets: Dict[str, dict] = {}


# ─── Lua script for atomic token bucket in Redis ────────────────
# This runs atomically on the Redis server — no race conditions.
TOKEN_BUCKET_LUA = """
local key_tokens = KEYS[1]
local key_ts     = KEYS[2]

local capacity    = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now         = tonumber(ARGV[3])
local requested   = tonumber(ARGV[4])

-- Get current state
local tokens   = tonumber(redis.call('GET', key_tokens) or capacity)
local last_ts   = tonumber(redis.call('GET', key_ts) or now)

-- Refill tokens based on elapsed time
local elapsed = math.max(0, now - last_ts)
local new_tokens = math.min(capacity, tokens + (elapsed * refill_rate))

-- Try to consume
local allowed = 0
local remaining = new_tokens

if new_tokens >= requested then
    new_tokens = new_tokens - requested
    allowed = 1
    remaining = new_tokens
end

-- Persist state with TTL (auto-cleanup idle keys after 5 minutes)
redis.call('SET', key_tokens, new_tokens, 'EX', 300)
redis.call('SET', key_ts, now, 'EX', 300)

return {allowed, math.floor(remaining), math.floor(capacity - remaining)}
"""

_lua_sha = None


def init_redis(host: str = "localhost", port: int = 6379, db: int = 0):
    """
    Initialize the Redis connection for rate limiting.
    Falls back to in-memory if Redis is unavailable.
    """
    global _redis_client, _redis_available, _lua_sha

    try:
        import redis
        _redis_client = redis.Redis(
            host=host,
            port=port,
            db=db,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=1,
            retry_on_timeout=True,
        )
        # Test the connection
        _redis_client.ping()
        # Pre-load the Lua script
        _lua_sha = _redis_client.script_load(TOKEN_BUCKET_LUA)
        _redis_available = True
        logger.info(f"✅ Redis connected at {host}:{port} — token bucket active")
        return True
    except Exception as e:
        _redis_available = False
        _redis_client = None
        logger.warning(f"⚠️  Redis unavailable ({e}) — using in-memory fallback")
        return False


def is_redis_connected() -> bool:
    """Check if Redis is currently connected."""
    return _redis_available


# ─── Redis Token Bucket ─────────────────────────────────────────
def _check_redis(api_key: str) -> dict:
    """Token bucket check via Redis Lua script (atomic)."""
    global _redis_available

    try:
        key_tokens = f"sp:rl:{api_key}:tokens"
        key_ts = f"sp:rl:{api_key}:ts"
        now = time.time()

        result = _redis_client.evalsha(
            _lua_sha,
            2,                  # number of KEYS
            key_tokens, key_ts, # KEYS
            BUCKET_CAPACITY,    # ARGV[1]
            REFILL_RATE,        # ARGV[2]
            now,                # ARGV[3]
            1,                  # ARGV[4] — consume 1 token
        )

        allowed = int(result[0]) == 1
        remaining = int(result[1])
        used = int(result[2])

        # Estimate reset time
        if not allowed:
            reset_in = round(1.0 / REFILL_RATE, 1)  # time until next token
        else:
            reset_in = round(WINDOW_SECONDS - (used / REFILL_RATE), 1)

        return {
            "allowed": allowed,
            "remaining": max(0, remaining),
            "reset_in": max(0, reset_in),
            "backend": "redis",
        }

    except Exception as e:
        # Redis went down mid-operation — switch to fallback
        logger.warning(f"Redis error during rate check: {e} — falling back")
        _redis_available = False
        return _check_memory(api_key)


# ─── In-Memory Token Bucket Fallback ────────────────────────────
def _check_memory(api_key: str) -> dict:
    """Token bucket using in-memory dict (fallback)."""
    now = time.time()

    if api_key not in _fallback_buckets:
        _fallback_buckets[api_key] = {
            "tokens": BUCKET_CAPACITY,
            "last_refill": now,
        }

    bucket = _fallback_buckets[api_key]

    # Refill tokens
    elapsed = now - bucket["last_refill"]
    bucket["tokens"] = min(
        BUCKET_CAPACITY,
        bucket["tokens"] + (elapsed * REFILL_RATE),
    )
    bucket["last_refill"] = now

    # Try to consume 1 token
    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        remaining = int(bucket["tokens"])
        reset_in = round(WINDOW_SECONDS - ((BUCKET_CAPACITY - remaining) / REFILL_RATE), 1)
        return {
            "allowed": True,
            "remaining": remaining,
            "reset_in": max(0, reset_in),
            "backend": "memory",
        }
    else:
        reset_in = round(1.0 / REFILL_RATE, 1)
        return {
            "allowed": False,
            "remaining": 0,
            "reset_in": max(0, reset_in),
            "backend": "memory",
        }


# ─── Public API ──────────────────────────────────────────────────
def check_rate_limit(api_key: str) -> dict:
    """
    Check if the given API key is within the rate limit.
    Uses Redis if available, otherwise falls back to in-memory.
    Returns { allowed: bool, remaining: int, reset_in: float, backend: str }.
    """
    if _redis_available and _redis_client:
        return _check_redis(api_key)
    return _check_memory(api_key)


def get_rate_limit_info(api_key: str) -> dict:
    """Get current rate limit status without consuming a token."""
    if _redis_available and _redis_client:
        try:
            key_tokens = f"sp:rl:{api_key}:tokens"
            tokens = _redis_client.get(key_tokens)
            remaining = int(float(tokens)) if tokens else BUCKET_CAPACITY
            return {
                "api_key_masked": f"***{api_key[-4:]}" if len(api_key) > 4 else api_key,
                "capacity": BUCKET_CAPACITY,
                "remaining": remaining,
                "refill_rate": f"{REFILL_RATE} tokens/sec",
                "backend": "redis",
            }
        except Exception:
            pass

    # Memory fallback info
    bucket = _fallback_buckets.get(api_key)
    remaining = int(bucket["tokens"]) if bucket else BUCKET_CAPACITY
    return {
        "api_key_masked": f"***{api_key[-4:]}" if len(api_key) > 4 else api_key,
        "capacity": BUCKET_CAPACITY,
        "remaining": remaining,
        "refill_rate": f"{REFILL_RATE} tokens/sec",
        "backend": "memory",
    }


def get_rate_limit_stats() -> dict:
    """Get overall rate limiter statistics."""
    return {
        "backend": "redis" if _redis_available else "memory",
        "redis_connected": _redis_available,
        "bucket_capacity": BUCKET_CAPACITY,
        "refill_rate_per_sec": REFILL_RATE,
        "refill_rate_per_min": REFILL_RATE * 60,
        "tracked_keys_memory": len(_fallback_buckets),
    }
