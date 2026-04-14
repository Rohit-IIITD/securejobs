"""
utils/limiter.py — SecureJobs
==============================
Single shared slowapi Limiter instance.

Defined here (not in main.py) so route modules can import it
without creating a circular dependency:
    main.py → auth_routes.py → main.py  ← circular, breaks app

Correct import chain:
    main.py      → limiter.py  (attaches to app.state)
    auth_routes  → limiter.py  (uses @limiter.limit decorator)
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limit key = client IP address.
# No default_limits here — each sensitive route sets its own limit explicitly.
limiter = Limiter(key_func=get_remote_address)
