"""
rate_limiter.py — shared request throttling for every active-scanning helper
script (check_sensitive_files.py, check_cors_headers.py, check_misconfig.py,
check_cloud_exposure.py, wordpress_scan.py, extract_api_endpoints.py,
extract_source_maps.py).

Reads two env vars (set by recon-framework.sh, itself populated from .env
or their defaults, so one setting controls every script):

  RECON_RATE_LIMIT   requests/second cap, SHARED across all threads in a
                     given script (default: 10). Set to 0 to disable throttling.
  RECON_MAX_WORKERS  ThreadPoolExecutor worker count (default: 15).

Usage in any script:
    from rate_limiter import throttle, MAX_WORKERS
    ...
    throttle()
    r = requests.get(url, ...)

`throttle()` blocks just long enough to keep the *combined* request rate
across all worker threads under RECON_RATE_LIMIT — it's a shared limiter,
not a per-thread one, so raising MAX_WORKERS doesn't let you exceed the cap.
"""
import os
import time
import threading

RATE_LIMIT = float(os.environ.get("RECON_RATE_LIMIT", "10"))   # requests/sec, 0 = unlimited
MAX_WORKERS = int(os.environ.get("RECON_MAX_WORKERS", "15"))

_lock = threading.Lock()
_last_call = 0.0
_min_interval = (1.0 / RATE_LIMIT) if RATE_LIMIT > 0 else 0.0


def throttle():
    """Call this immediately before every outbound request."""
    global _last_call
    if _min_interval <= 0:
        return
    with _lock:
        now = time.monotonic()
        wait = _min_interval - (now - _last_call)
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()
