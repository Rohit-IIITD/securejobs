"""
main.py — SecureJobs
======================
Application entry point. Contains ONLY:
  - FastAPI app initialisation
  - CSRF config and exception handler
  - Security headers middleware
  - Rate limiter setup
  - Router registration
  - One-time admin seed call
  - create_all() (safe: models are imported before this runs)

SECURITY ADDITIONS:
  1. SecurityHeadersMiddleware — injects hardened HTTP response headers
     on every response to defend against XSS, clickjacking, MIME sniffing,
     and enforce HTTPS via HSTS.
  2. Rate limiting via slowapi — prevents brute-force on /login and
     /totp-login routes (5 attempts per minute per IP).
"""

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import BaseModel
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# ── 1. Config (must be first — everything else reads from it) ──
from config import RESUME_DIR, SECRET_KEY

# ── 2. Database infrastructure ────────────────────────────────
from database import Base, engine

# ── 3. Models — import ALL before create_all() ────────────────
import models  # noqa: F401  registers User, EmailOTP, Company, JobPosting …

# ── 4. Routes ─────────────────────────────────────────────────
from routes import admin_routes, auth_routes, job_routes, message_routes
from routes import profile_routes, recruiter_routes

# ── 5. Admin seed ─────────────────────────────────────────────
from services.seed import seed_admin

# ── 6. Shared rate limiter ────────────────────────────────────
from utils.limiter import limiter

# ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)

os.makedirs(RESUME_DIR, exist_ok=True)

Base.metadata.create_all(bind=engine)


# ══════════════════════════════════════════════════════════════
# SECURITY HEADERS MIDDLEWARE
# ══════════════════════════════════════════════════════════════
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Inject security-hardening HTTP headers on every response.

    Header-by-header explanation:
    ─────────────────────────────
    X-Frame-Options: DENY
        Prevents our pages from being embedded in <iframe> on other sites.
        Defends against clickjacking attacks.

    X-Content-Type-Options: nosniff
        Tells the browser to trust the Content-Type header and not try to
        "sniff" a different MIME type from the content bytes.
        Defends against MIME-confusion attacks (e.g., serving a JS file
        as text/plain but the browser executes it anyway).

    X-XSS-Protection: 1; mode=block
        Legacy header for older browsers (IE/Edge) — instructs the browser's
        built-in XSS filter to block the page if an attack is detected.
        Modern browsers ignore this in favour of CSP, but it costs nothing.

    Referrer-Policy: strict-origin-when-cross-origin
        When a user clicks a link to an external site, the browser will only
        send the origin (not the full URL path) as the Referrer.
        Prevents leaking sensitive URL parameters (e.g., email addresses
        in query strings) to third-party sites.

    Content-Security-Policy
        The most powerful XSS defence. Tells the browser exactly which
        origins are allowed to load scripts, styles, images, etc.
        - default-src 'self': only load resources from our own origin
        - script-src 'self' https://cdn.tailwindcss.com: allow Tailwind CDN
        - style-src 'self' 'unsafe-inline': allow inline styles (Tailwind needs this)
        - img-src 'self' data:: allow inline base64 images (QR codes use data: URIs)
        - object-src 'none': block Flash, Java applets, etc.
        - base-uri 'self': prevent <base> tag injection
        - frame-ancestors 'none': equivalent to X-Frame-Options: DENY (CSP version)

    Strict-Transport-Security: max-age=31536000; includeSubDomains
        HSTS — once a browser has visited our site over HTTPS, it will
        REFUSE to connect over HTTP for 31536000 seconds (1 year).
        Defends against SSL-stripping attacks.
        NOTE: Only takes effect after HTTPS/Nginx is configured.
        Set to 0 during development if you're still on HTTP.

    Permissions-Policy
        Restricts access to browser APIs that our app doesn't need.
        Disabling camera/microphone/geolocation reduces the attack surface
        if an XSS payload tries to access these APIs.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"]   = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Permissions-Policy"]        = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        return response


# ══════════════════════════════════════════════════════════════
# CSRF CONFIGURATION
# ══════════════════════════════════════════════════════════════
class CsrfSettings(BaseModel):
    secret_key: str = SECRET_KEY

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


# ══════════════════════════════════════════════════════════════
# APP INSTANCE
# ══════════════════════════════════════════════════════════════
app = FastAPI()

# ── Attach rate limiter state and middleware ──────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# ── Attach security headers middleware ────────────────────────
# Must be added AFTER SlowAPIMiddleware so headers appear on
# rate-limit rejection responses too.
app.add_middleware(SecurityHeadersMiddleware)

templates = Jinja2Templates(directory="templates")


# ── CSRF error handler ────────────────────────────────────────
@app.exception_handler(CsrfProtectError)
async def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={"detail": exc.message},
        status_code=exc.status_code,
    )


# ── Rate-limit error handler (JSON + HTML) ────────────────────
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Return a friendly HTML error page for browser requests,
    or JSON for API clients.
    """
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "detail": (
                    "Too many attempts. Please wait a minute before trying again."
                )
            },
            status_code=429,
        )
    return JSONResponse(
        {"detail": "Rate limit exceeded. Try again later."},
        status_code=429,
    )


# ══════════════════════════════════════════════════════════════
# ROUTER REGISTRATION
# Expose the limiter instance to route modules that apply
# per-route limits via @limiter.limit(...)
# ══════════════════════════════════════════════════════════════
app.include_router(auth_routes.router)
app.include_router(profile_routes.router)
app.include_router(admin_routes.router)
app.include_router(job_routes.router)
app.include_router(recruiter_routes.router)
app.include_router(message_routes.router)


# ── Seed admin (idempotent) ───────────────────────────────────
seed_admin()
