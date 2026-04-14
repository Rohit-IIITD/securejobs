"""
routes/profile_routes.py — SecureJobs
"""
 
import os
import time
 
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
 
from auth.jwt import get_current_user
from config import RESUME_DIR
from database import get_db
from services.audit_service import log_action
from services.crypto_service import encrypt_file
from services.pki_service import sign_resume, verify_resume
from utils.template_helpers import csrf_response, validate_csrf_token
 
router    = APIRouter()
templates = Jinja2Templates(directory="templates")
 
_ALLOWED_MIME     = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_MAX_RESUME_BYTES = 5 * 1024 * 1024
 
 
@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request=request, name="home.html",
        context={"user": get_current_user(request, db)},
    )
 
 
@router.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return csrf_response(request, templates, "profile.html", {"user": user})
 
 
@router.get("/profile/edit", response_class=HTMLResponse)
async def profile_edit_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return csrf_response(request, templates, "profile_edit.html", {"user": user})
 
 
@router.post("/profile/edit")
async def profile_edit(
    request:    Request,
    full_name:  str = Form(...),
    phone:      str = Form(""),
    headline:   str = Form(""),
    bio:        str = Form(""),
    location:   str = Form(""),
    csrf_token: str = Form(""),
    db:         Session = Depends(get_db),
):
    if not validate_csrf_token(csrf_token):
        return RedirectResponse("/profile/edit?error=csrf", status_code=303)
 
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
 
    changes = []
    if user.full_name != full_name.strip():
        changes.append("full_name")
    if (user.headline or "") != headline.strip()[:160]:
        changes.append("headline")
    if (user.location or "") != location.strip()[:120]:
        changes.append("location")
 
    user.full_name = full_name.strip()
    user.phone     = phone.strip()
    user.headline  = headline.strip()[:160]
    user.bio       = bio.strip()
    user.location  = location.strip()[:120]
    db.commit()
 
    log_action(db, actor_id=user.id, action="PROFILE_EDIT",
               target=f"user:{user.id}",
               detail=(f"User {user.email} updated profile fields: "
                       f"{', '.join(changes) if changes else 'no tracked fields changed'}"))
 
    return RedirectResponse("/profile", status_code=303)
 
 
@router.post("/upload")
async def upload(
    request:    Request,
    resume:     UploadFile = File(...),
    csrf_token: str = Form(""),
    db:         Session = Depends(get_db),
):
    if not validate_csrf_token(csrf_token):
        return RedirectResponse("/profile?error=csrf", status_code=303)
 
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
 
    if resume.content_type not in _ALLOWED_MIME:
        log_action(db, actor_id=user.id, action="RESUME_UPLOAD_REJECTED",
                   target=f"user:{user.id}",
                   detail=(f"User {user.email} attempted to upload disallowed "
                           f"file type: {resume.content_type}"))
        raise HTTPException(status_code=400,
                            detail="Only PDF and DOCX files are accepted.")
 
    data = await resume.read()
 
    if len(data) > _MAX_RESUME_BYTES:
        log_action(db, actor_id=user.id, action="RESUME_UPLOAD_REJECTED",
                   target=f"user:{user.id}",
                   detail=(f"User {user.email} attempted to upload oversized file "
                           f"({len(data)} bytes, limit={_MAX_RESUME_BYTES})"))
        raise HTTPException(status_code=413,
                            detail="Resume file must be smaller than 5 MB.")
 
    encrypted  = encrypt_file(data)
    resume_sig = sign_resume(encrypted)
 
    filename = f"user{user.id}_{int(time.time())}.enc"
    path     = os.path.join(RESUME_DIR, filename)
    with open(path, "wb") as f:
        f.write(encrypted)
 
    user.resume_path      = filename
    user.resume_signature = resume_sig
    db.commit()
 
    log_action(db, actor_id=user.id, action="RESUME_UPLOAD",
               target=f"user:{user.id}",
               detail=(f"User {user.email} uploaded resume "
                       f"(filename={filename}, size={len(data)} bytes, "
                       f"type={resume.content_type})"))
 
    return RedirectResponse("/profile", status_code=303)