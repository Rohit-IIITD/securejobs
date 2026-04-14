"""
routes/message_routes.py — SecureJobs
========================================
Encrypted messaging routes:
  GET   /messages/{user_id}
  POST  /message/send
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from sqlalchemy import text
from sqlalchemy.orm import Session

from auth.jwt import get_current_user
from database import get_db
from models.user import User
from services.crypto_service import decrypt_message, encrypt_message
from services.message_service import get_or_create_conversation
from utils.template_helpers import csrf_response

router    = APIRouter()
templates = Jinja2Templates(directory="templates")


# ── View conversation ─────────────────────────────────────────

@router.get("/messages/{user_id}", response_class=HTMLResponse)
async def view_messages(
    user_id: int,
    request: Request,
    db:      Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    convo_id = get_or_create_conversation(db, user.id, user_id)

    rows = db.execute(text("""
        SELECT sender_id, ciphertext, sent_at
        FROM messages
        WHERE conversation_id = :c
        ORDER BY sent_at ASC
    """), {"c": convo_id}).fetchall()

    messages = [
        {"sender": r[0], "text": decrypt_message(r[1]), "time": r[2]}
        for r in rows
    ]

    other_user = db.query(User).filter(User.id == user_id).first()

    return csrf_response(
        request, templates, "messages.html",
        {"messages": messages, "other_user": other_user,
         "receiver_id": user_id, "user": user},
        csrf_protect,
    )


# ── Send message ──────────────────────────────────────────────

@router.post("/message/send")
async def send_message(
    request:     Request,
    receiver_id: int = Form(...),
    content:     str = Form(...),
    db:          Session = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    await csrf_protect.validate_csrf(request)

    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)

    convo_id  = get_or_create_conversation(db, user.id, receiver_id)
    encrypted = encrypt_message(content)

    db.execute(text("""
        INSERT INTO messages (conversation_id, sender_id, ciphertext)
        VALUES (:c, :s, :ct)
    """), {"c": convo_id, "s": user.id, "ct": encrypted})
    db.commit()

    return RedirectResponse(f"/messages/{receiver_id}", status_code=303)
