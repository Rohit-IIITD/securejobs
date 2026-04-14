"""
utils/template_helpers.py — SecureJobs
========================================
Eliminates the repeated 3-line CSRF boilerplate that appears in
every GET route that returns a form.

Before (repeated ~15 times):
    csrf_token, signed = csrf_protect.generate_csrf_tokens()
    response = templates.TemplateResponse(...)
    csrf_protect.set_csrf_cookie(signed, response)
    return response

After:
    return csrf_response(request, templates, "page.html", {"key": val}, csrf_protect)
"""

from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect


def csrf_response(
    request:      Request,
    templates:    Jinja2Templates,
    name:         str,
    context:      dict,
    csrf_protect: CsrfProtect,
):
    """
    Generate a CSRF token pair, inject it into *context*, build the
    TemplateResponse, set the CSRF cookie, and return the response.
    *context* must NOT already contain a 'csrf_token' key.
    """
    csrf_token, signed = csrf_protect.generate_csrf_tokens()
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(
        request=request,
        name=name,
        context=context,
    )
    csrf_protect.set_csrf_cookie(signed, response)
    return response
