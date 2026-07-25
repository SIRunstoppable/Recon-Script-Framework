"""
rate_limiter.py — shared request throttling AND automatic backoff on
429/503 responses, used by every active-scanning helper script
(check_sensitive_files.py, check_cors_headers.py, check_misconfig.py,
check_cloud_exposure.py, wordpress_scan.py, extract_api_endpoints.py,
extract_source_maps.py).

Env vars (set by recon-framework.sh, itself populated from .env or their
defaults, so one setting controls every script):

  RECON_RATE_LIMIT   requests/second cap, SHARED across all threads in a
                     given script (default: 10). Set to 0 to disable throttling.
  RECON_MAX_WORKERS  ThreadPoolExecutor worker count (default: 15).
  RECON_MAX_RETRIES  retries on a 429/503 response before giving up (default: 3).

Usage — replace requests.get/requests.post with the wrapped versions:
    from rate_limiter import get, post, MAX_WORKERS
    ...
    r = get(url, timeout=8, verify=False)   # throttled + auto-retries 429/503
    r = post(url, json=payload, timeout=8)

Both `get()` and `post()` throttle internally (no separate throttle() call
needed) and transparently retry on HTTP 429/503: they honor a Retry-After
header if the server sends one, otherwise back off exponentially
(2s, 4s, 8s, capped at 30s). A normal connection error/timeout still raises
and propagates to the caller exactly like a plain requests.get() would —
only the "server told us to slow down" case is special-cased here.
"""
import os
import time
import threading

import requests

RATE_LIMIT = float(os.environ.get("RECON_RATE_LIMIT", "10"))   # requests/sec, 0 = unlimited
MAX_WORKERS = int(os.environ.get("RECON_MAX_WORKERS", "15"))
MAX_RETRIES = int(os.environ.get("RECON_MAX_RETRIES", "3"))

_BACKOFF_BASE = 2.0     # seconds, doubles each retry
_BACKOFF_CAP = 30.0     # never sleep longer than this in one step, retry-after included

_lock = threading.Lock()
_last_call = 0.0
_min_interval = (1.0 / RATE_LIMIT) if RATE_LIMIT > 0 else 0.0


def throttle():
    """Blocks just long enough to keep the *combined* request rate across all
    worker threads under RECON_RATE_LIMIT. Called automatically by get()/post()
    — only call this directly if you need to throttle something that isn't a
    plain requests call."""
    global _last_call
    if _min_interval <= 0:
        return
    with _lock:
        now = time.monotonic()
        wait = _min_interval - (now - _last_call)
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()


def _parse_retry_after(response):
    header = response.headers.get("Retry-After")
    if not header:
        return None
    try:
        return float(header)
    except ValueError:
        return None  # Retry-After can also be an HTTP-date; not worth parsing here


def request(method, url, **kwargs):
    """Throttled request with automatic backoff on 429/503. Returns the
    Response object (possibly still 429/503 if every retry was exhausted —
    callers should keep checking status_code as normal)."""
    last_response = None
    for attempt in range(MAX_RETRIES + 1):
        throttle()
        r = requests.request(method, url, **kwargs)
        last_response = r
        if r.status_code in (429, 503) and attempt < MAX_RETRIES:
            wait = _parse_retry_after(r)
            if wait is None:
                wait = _BACKOFF_BASE * (2 ** attempt)
            time.sleep(min(wait, _BACKOFF_CAP))
            continue
        return r
    return last_response


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    return request("POST", url, **kwargs)
