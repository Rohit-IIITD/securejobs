"""
routes/job_routes.py — SecureJobs
====================================
Job-seeker and recruiter job-posting routes:
  GET       /jobs
  GET/POST  /jobs/create
  GET       /jobs/{job_id}
  POST      /apply/{job_id}
  GET       /applications

AUDIT LOGGING added to:
  - Job posting creation
  - Job application submission
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from sqlalchemy.orm import Session

from auth.jwt import get_current_user
from database import get_db
from models.job import Application, JobPosting
from services.audit_service import log_action
from utils.template_helpers import csrf_response

router    = APIRouter()
templates = Jinja2Templates(directory="templates")


# ── Job listing ───────────────────────────────────────────────

@router.get("/jobs", response_class=HTMLResponse)
def list_jobs(request: Request, db: Session = Depends(get_db)):
    jobs = db.query(JobPosting).order_by(JobPosting.created_at.desc()).all()
    return templates.TemplateResponse(
        request=request,
        name="jobs.html",
        context={"jobs": jobs, "user": get_current_user(request, db)},
    )


# ── Job creation (recruiters only) ───────────────────────────

@router.get("/jobs/create", response_class=HTMLResponse)
async def create_job_page(
    request: Request,
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)
    return csrf_response(
        request, templates, "job_create.html", {"user": user}, csrf_protect
    )


@router.post("/jobs/create")
async def create_job(
    request:     Request,
    title:       str = Form(...),
    description: str = Form(...),
    skills:      str = Form(""),
    location:    str = Form(""),
    db:          Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)

    job = JobPosting(
        title       = title,
        description = description,
        skills      = skills,
        location    = location,
        company_id  = user.company_id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # ── AUDIT: new job posting ────────────────────────────────
    log_action(
        db,
        actor_id = user.id,
        action   = "JOB_CREATED",
        target   = f"job:{job.id}",
        detail   = (
            f"Recruiter {user.email} created job '{title}' "
            f"(id={job.id}, company_id={user.company_id})"
        ),
    )

    return RedirectResponse("/jobs", status_code=303)


# ── Job detail ────────────────────────────────────────────────

@router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail(
    job_id:  int,
    request: Request,
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    job = db.query(JobPosting).filter(JobPosting.id == job_id).first()
    if not job:
        return RedirectResponse("/jobs", status_code=303)

    return csrf_response(
        request, templates, "job_detail.html",
        {"job": job, "user": get_current_user(request, db)},
        csrf_protect,
    )


# ── Apply ─────────────────────────────────────────────────────

@router.post("/apply/{job_id}")
async def apply_job(
    job_id:     int,
    request:    Request,
    cover_note: str = Form(""),
    db:         Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # Prevent duplicate applications
    existing = db.query(Application).filter(
        Application.job_id  == job_id,
        Application.user_id == user.id,
    ).first()
    if existing:
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    application = Application(
        job_id     = job_id,
        user_id    = user.id,
        cover_note = cover_note,
    )
    db.add(application)
    db.commit()
    db.refresh(application)

    # ── AUDIT: job application submitted ─────────────────────
    log_action(
        db,
        actor_id = user.id,
        action   = "JOB_APPLIED",
        target   = f"job:{job_id}",
        detail   = (
            f"User {user.email} applied to job_id={job_id} "
            f"(application_id={application.id})"
        ),
    )

    return RedirectResponse("/applications", status_code=303)


# ── My applications ───────────────────────────────────────────

@router.get("/applications", response_class=HTMLResponse)
async def my_applications(
    request: Request,
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    applications = db.query(Application).filter(
        Application.user_id == user.id
    ).all()
    jobs = {job.id: job for job in db.query(JobPosting).all()}

    return csrf_response(
        request, templates, "applications.html",
        {"applications": applications, "jobs": jobs, "user": user},
        csrf_protect,
    )
