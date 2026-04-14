"""
routes/recruiter_routes.py — SecureJobs
"""
 
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
 
from auth.jwt import get_current_user
from database import get_db
from models.job import Application, JobPosting
from models.user import User
from services.audit_service import log_action
from utils.template_helpers import csrf_response, validate_csrf_token
 
router    = APIRouter()
templates = Jinja2Templates(directory="templates")
 
_ALLOWED_STATUSES = {"Applied", "Reviewed", "Interviewed", "Rejected", "Offer"}
 
 
@router.get("/recruiter", response_class=HTMLResponse)
def recruiter_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)
 
    jobs = db.query(JobPosting).filter(
        JobPosting.company_id == user.company_id).all()
 
    return templates.TemplateResponse(
        request=request, name="recruiter_dashboard.html",
        context={"user": user, "jobs": jobs},
    )
 
 
@router.get("/job/{job_id}/applicants", response_class=HTMLResponse)
async def view_applicants(job_id: int, request: Request,
                          db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)
 
    job = db.query(JobPosting).filter(JobPosting.id == job_id).first()
    if not job or job.company_id != user.company_id:
        return RedirectResponse("/recruiter", status_code=303)
 
    applications = db.query(Application).filter(
        Application.job_id == job_id).all()
    users = {u.id: u for u in db.query(User).all()}
 
    return csrf_response(request, templates, "applicants.html",
                         {"applications": applications, "users": users,
                          "job_id": job_id, "user": user})
 
 
@router.post("/application/{app_id}/status")
async def update_status(
    app_id:     int,
    request:    Request,
    status:     str = Form(...),
    csrf_token: str = Form(""),
    db:         Session = Depends(get_db),
):
    if not validate_csrf_token(csrf_token):
        return RedirectResponse("/recruiter?error=csrf", status_code=303)
 
    user = get_current_user(request, db)
    if not user or user.role != "recruiter":
        return RedirectResponse("/", status_code=303)
 
    if status not in _ALLOWED_STATUSES:
        return RedirectResponse("/recruiter", status_code=303)
 
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        return RedirectResponse("/recruiter", status_code=303)
 
    job = db.query(JobPosting).filter(JobPosting.id == app.job_id).first()
    if not job or job.company_id != user.company_id:
        return RedirectResponse("/recruiter", status_code=303)
 
    previous_status = app.status
    app.status = status
    db.commit()
 
    log_action(db, actor_id=user.id, action="APPLICATION_STATUS_UPDATE",
               target=f"application:{app.id}",
               detail=(f"Recruiter {user.email} changed application {app.id} "
                       f"status from '{previous_status}' to '{status}' "
                       f"(job_id={app.job_id}, applicant_id={app.user_id})"))
 
    return RedirectResponse(f"/job/{app.job_id}/applicants", status_code=303)