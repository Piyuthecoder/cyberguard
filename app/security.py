import hashlib
import hmac
import json
import secrets
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from functools import wraps
import os

from flask import abort, current_app, flash, request
from flask_login import current_user

from . import db
from .models import AuditLog, now

GENESIS = "0" * 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- audit hash chain
def _digest(prev, ts, actor_id, action, target_type, target_id, details, ip):
    payload = "|".join(str(x) for x in (prev, ts, actor_id, action, target_type, target_id, details, ip))
    return hashlib.sha256(payload.encode()).hexdigest()


def log_audit(action, target_type=None, target_id=None, details=None, actor_id=None):
    """Append an entry to the tamper-evident audit log. Caller commits."""
    if actor_id is None and current_user and current_user.is_authenticated:
        actor_id = current_user.id
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev = last.hash if last else GENESIS
    ts = now().isoformat(timespec="microseconds")
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    ip = request.remote_addr if request else None
    entry = AuditLog(
        ts=ts, actor_id=actor_id, action=action, target_type=target_type, target_id=target_id,
        details=details_json, ip=ip, prev_hash=prev,
        hash=_digest(prev, ts, actor_id, action, target_type, target_id, details_json, ip),
    )
    db.session.add(entry)
    db.session.flush()
    return entry


def verify_chain():
    """Recompute every hash. Returns (ok, entries_checked, first_bad_id)."""
    prev, count = GENESIS, 0
    for e in AuditLog.query.order_by(AuditLog.id):
        expected = _digest(prev, e.ts, e.actor_id, e.action, e.target_type, e.target_id, e.details, e.ip)
        if e.prev_hash != prev or e.hash != expected:
            return False, count, e.id
        prev, count = e.hash, count + 1
    return True, count, None


# ---------------------------------------------------------------- RBAC
def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


# ---------------------------------------------------------------- OTP
def _otp_hash(code):
    return hmac.new(current_app.config["SECRET_KEY"].encode(), code.encode(), hashlib.sha256).hexdigest()


def send_otp(user, purpose="verification"):
    code = f"{secrets.randbelow(10**6):06d}"
    user.otp_hash = _otp_hash(code)
    user.otp_expires = now() + timedelta(minutes=current_app.config["OTP_MINUTES"])
    user.otp_attempts = 0
    body = f"Your CyberGuard {purpose} code is {code}. It expires in {current_app.config['OTP_MINUTES']} minutes. Never share it."
    host = os.environ.get("SMTP_HOST")
    if host:
        msg = EmailMessage()
        msg["Subject"], msg["To"] = f"CyberGuard {purpose} code", user.email
        msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "noreply@cyberguard.local"))
        msg.set_content(body)
        try:
            with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=15) as s:
                s.starttls()
                if os.environ.get("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                s.send_message(msg)
        except Exception as exc:  # never leak SMTP errors to the user
            current_app.logger.error("SMTP failure: %s", exc)
            flash("We could not send the email right now. Please try again.", "danger")
    else:
        current_app.logger.warning("[DEV] OTP for %s: %s", user.email, code)
        if current_app.config["DEV_SHOW_OTP"]:
            flash(f"Development mode (no SMTP configured): your code is {code}", "info")
    return code


def check_otp(user, code):
    if not user.otp_hash or not user.otp_expires or user.otp_expires < now():
        return False
    if (user.otp_attempts or 0) >= 5:
        return False
    user.otp_attempts = (user.otp_attempts or 0) + 1
    if hmac.compare_digest(user.otp_hash, _otp_hash((code or "").strip())):
        user.otp_hash = user.otp_expires = None
        user.otp_attempts = 0
        return True
    return False
