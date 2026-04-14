"""
utils/template_helpers.py — SecureJobs
========================================
Custom CSRF implementation — signs tokens with HMAC-SHA256.
Replaces fastapi-csrf-protect entirely.
"""
 
import hashlib
import hmac
import os
import secrets
 
from fastapi import Request
from fastapi.templating import Jinja2Templates
 
_SECRET = os.environ.get("SECRET_KEY", "fallback-secret").encode()
 
 
def _sign(token: str) -> str:
    return hmac.new(_SECRET, token.encode(), hashlib.sha256).hexdigest()
 
 
def generate_csrf_token() -> str:
    token = secrets.token_hex(32)
    return f"{token}.{_sign(token)}"
 
 
def validate_csrf_token(token: str) -> bool:
    try:
        raw, sig = token.rsplit(".", 1)
        return hmac.compare_digest(_sign(raw), sig)
    except Exception:
        return False
 
 
def csrf_response(request, templates, name, context, csrf_protect=None):
    context["csrf_token"] = generate_csrf_token()
    return templates.TemplateResponse(request=request, name=name, context=context)