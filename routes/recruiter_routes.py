"""
routes/recruiter_routes.py — SecureJobs
==========================================
Recruiter-only routes:
  GET   /recruiter
  GET   /job/{job_id}/applicants
  POST  /application/{app_id}/status

SECURITY FIX: Added company_id ownership check on /job/{job_id}/applicants
  — previously any recruiter could view any job's applicants (horizontal
    privilege escalation). Now only the owning company's recruiter can view.

AUDIT LOGGING added to:
  - Application status updates
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from sqlalchemy.orm import Session

from auth.jwt import get_current_user
from database import get_db
from models.job import Application, JobPosting
from models.user import User
from services.audit_service import log_action
from utils.template_helpers import csrf_response

router    = APIRouter()
templates = Jinja2Templates(directory="templates")

_ALLOWED_STATUSES = {"Applied", "Reviewed", "Interviewed", "Rejected", "Offer"}


# ── Recruiter dashboard ───────────────────────────────────────

@router.get("/recruiter", response_class=HTMLResponse)
def recruiter_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)

    jobs = db.query(JobPosting).filter(
        JobPosting.company_id == user.company_id
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="recruiter_dashboard.html",
        context={"user": user, "jobs": jobs},
    )


# ── View applicants for a job ─────────────────────────────────

@router.get("/job/{job_id}/applicants", response_class=HTMLResponse)
async def view_applicants(
    job_id:  int,
    request: Request,
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)

    # SECURITY FIX: verify this job belongs to the recruiter's company
    # Previously missing — any recruiter could view any job's applicants
    job = db.query(JobPosting).filter(JobPosting.id == job_id).first()
    if not job or job.company_id != user.company_id:
        return RedirectResponse("/recruiter", status_code=303)

    applications = db.query(Application).filter(
        Application.job_id == job_id
    ).all()
    users = {u.id: u for u in db.query(User).all()}

    return csrf_response(
        request, templates, "applicants.html",
        {"applications": applications, "users": users,
         "job_id": job_id, "user": user},
        csrf_protect,
    )


# ── Update application status ─────────────────────────────────

@router.post("/application/{app_id}/status")
async def update_status(
    app_id:  int,
    request: Request,
    status:  str = Form(...),
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)

    if status not in _ALLOWED_STATUSES:
        return RedirectResponse("/recruiter", status_code=303)

    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        return RedirectResponse("/recruiter", status_code=303)

    # SECURITY FIX: verify the application's job belongs to this recruiter's company
    job = db.query(JobPosting).filter(JobPosting.id == app.job_id).first()
    if not job or job.company_id != user.company_id:
        return RedirectResponse("/recruiter", status_code=303)

    previous_status = app.status
    app.status = status
    db.commit()

    # ── AUDIT: application status changed ────────────────────
    log_action(
        db,
        actor_id = user.id,
        action   = "APPLICATION_STATUS_UPDATE",
        target   = f"application:{app.id}",
        detail   = (
            f"Recruiter {user.email} changed application {app.id} "
            f"status from '{previous_status}' to '{status}' "
            f"(job_id={app.job_id}, applicant_id={app.user_id})"
        ),
    )

    return RedirectResponse(f"/job/{app.job_id}/applicants", status_code=303)
