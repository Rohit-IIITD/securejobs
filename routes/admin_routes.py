"""
routes/admin_routes.py — SecureJobs
"""
 
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.orm import Session
import hashlib
 
from auth.jwt import get_current_user
from auth.totp import verify_totp
from database import get_db
from models.user import User
from services.audit_service import log_action, verify_chain
from services.pki_service import get_public_key_pem, verify_audit_row
from utils.template_helpers import csrf_response, validate_csrf_token
 
router    = APIRouter()
templates = Jinja2Templates(directory="templates")
 
 
@router.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
 
    users = db.query(User).order_by(User.created_at.desc()).all()
    return csrf_response(request, templates, "admin.html",
                         {"user": user, "users": users})
 
 
@router.post("/admin/suspend/{user_id}")
async def admin_suspend(
    request:    Request,
    user_id:    int,
    csrf_token: str = Form(""),
    db:         Session = Depends(get_db),
):
    if not validate_csrf_token(csrf_token):
        return RedirectResponse("/admin?error=csrf", status_code=303)
 
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
 
    target = db.query(User).filter(User.id == user_id).first()
    if not target or target.is_admin:
        raise HTTPException(status_code=400, detail="Cannot modify this user")
 
    previous_state      = target.is_suspended
    target.is_suspended = not target.is_suspended
    db.commit()
 
    action = "USER_UNSUSPEND" if previous_state else "USER_SUSPEND"
    log_action(db, actor_id=admin.id, action=action,
               target=f"user:{target.id}",
               detail=(f"Admin {admin.email} "
                       f"{'unsuspended' if previous_state else 'suspended'} "
                       f"user {target.email} (id={target.id})"))
 
    return RedirectResponse("/admin", status_code=303)
 
 
@router.post("/admin/delete/{user_id}")
async def admin_delete(
    request:    Request,
    user_id:    int,
    otp:        str = Form(...),
    csrf_token: str = Form(""),
    db:         Session = Depends(get_db),
):
    if not validate_csrf_token(csrf_token):
        return RedirectResponse("/admin?error=csrf", status_code=303)
 
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403)
 
    if not verify_totp(admin.otp_secret, otp):
        log_action(db, actor_id=admin.id, action="USER_DELETE_FAIL_OTP",
                   target=f"user:{user_id}",
                   detail=(f"Admin {admin.email} failed TOTP check "
                           f"when attempting to delete user_id={user_id}"))
        raise HTTPException(status_code=403,
                            detail="Invalid authenticator code. Deletion cancelled.")
 
    target = db.query(User).filter(User.id == user_id).first()
    if not target or target.is_admin:
        raise HTTPException(status_code=400, detail="Cannot delete this user")
 
    log_action(db, actor_id=admin.id, action="USER_DELETE",
               target=f"user:{target.id}",
               detail=(f"Admin {admin.email} permanently deleted user "
                       f"{target.email} (id={target.id}, role={target.role}) "
                       f"— TOTP-verified"))
 
    db.delete(target)
    db.commit()
    return RedirectResponse("/admin", status_code=303)
 
 
@router.get("/admin/audit-logs", response_class=HTMLResponse)
async def audit_log_viewer(request: Request, db: Session = Depends(get_db)):
    admin = get_current_user(request, db)
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
 
    verification = verify_chain(db)
 
    raw_rows = db.execute(text("""
        SELECT id, actor_id, action, target, detail,
               prev_hash, row_hash, row_signature, logged_at
        FROM audit_logs ORDER BY id DESC
    """)).fetchall()
 
    asc_rows = db.execute(text("""
        SELECT id, actor_id, action, target, detail,
               prev_hash, row_hash, row_signature
        FROM audit_logs ORDER BY id ASC
    """)).fetchall()
 
    running_hash   = ""
    row_hash_valid = {}
    row_sig_valid  = {}
 
    for r in asc_rows:
        rid, actor_id, action, target, detail, prev_hash, stored_hash, row_signature = r
        raw      = f"{actor_id}|{action}|{target}|{detail}|{running_hash}"
        expected = hashlib.sha256(raw.encode()).hexdigest()
        row_hash_valid[rid] = (stored_hash == expected and prev_hash == running_hash)
        running_hash = stored_hash
 
        if row_signature:
            signed_raw = f"{actor_id}|{action}|{target}|{detail}|{prev_hash}"
            row_sig_valid[rid] = verify_audit_row(signed_raw, row_signature)
        else:
            row_sig_valid[rid] = None
 
    class LogRow:
        pass
 
    annotated = []
    for r in raw_rows:
        rid, actor_id, action, target, detail, prev_hash, row_hash, row_signature, logged_at = r
        obj               = LogRow()
        obj.id            = rid
        obj.actor_id      = actor_id
        obj.action        = action
        obj.target        = target
        obj.detail        = detail
        obj.prev_hash     = prev_hash
        obj.row_hash      = row_hash
        obj.row_signature = row_signature
        obj.logged_at     = logged_at
        obj.hash_valid    = row_hash_valid.get(rid, False)
        obj.sig_valid     = row_sig_valid.get(rid)
        annotated.append(obj)
 
    return csrf_response(request, templates, "audit_logs.html",
                         {"user": admin, "logs": annotated,
                          "verification": verification,
                          "public_key_pem": get_public_key_pem()})