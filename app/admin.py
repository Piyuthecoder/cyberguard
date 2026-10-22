import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from . import db
from .models import AuditLog, ErasureRequest, User, now
from .privacy import erase_user, purge_expired
from .security import log_audit, roles_required, verify_chain

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@roles_required("admin")
def index():
    return render_template(
        "admin/index.html",
        users=User.query.filter_by(erased=False).order_by(User.role, User.id).all(),
        audit=AuditLog.query.order_by(AuditLog.id.desc()).limit(40).all(),
        requests=ErasureRequest.query.order_by(ErasureRequest.id.desc()).limit(30).all(),
        audit_total=AuditLog.query.count(),
    )


@bp.route("/officers", methods=["POST"])
@roles_required("admin")
def create_officer():
    f = request.form
    email, name, pw = f.get("email", "").strip().lower(), f.get("name", "").strip(), f.get("password", "")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(name) < 2:
        flash("Enter a valid name and email.", "danger")
    elif len(pw) < 12 or not re.search(r"\d", pw) or not re.search(r"[A-Za-z]", pw):
        flash("Officer passwords need 12+ characters with letters and digits.", "danger")
    elif User.query.filter_by(email=email).first():
        flash("That email is already registered.", "danger")
    else:
        u = User(email=email, name=name, role=f.get("role") if f.get("role") in ("officer", "admin") else "officer",
                 password_hash=generate_password_hash(pw), verified=True)
        db.session.add(u)
        db.session.flush()
        log_audit("STAFF_CREATED", "user", u.id, {"role": u.role})
        db.session.commit()
        flash(f"{u.role.title()} account created for {email}.", "success")
    return redirect(url_for("admin.index"))


@bp.route("/audit/verify", methods=["POST"])
@roles_required("admin")
def audit_verify():
    ok, n, bad = verify_chain()
    if ok:
        flash(f"Audit chain intact: {n} entries verified.", "success")
    else:
        flash(f"TAMPERING DETECTED: chain breaks at entry #{bad} (after {n} valid entries).", "danger")
    return redirect(url_for("admin.index"))


@bp.route("/erasure/<int:rid>", methods=["POST"])
@roles_required("admin")
def process_erasure(rid):
    r = db.session.get(ErasureRequest, rid)
    if r and r.status == "Pending":
        ok, msg = erase_user(r.user, "Data principal request")
        r.status, r.note, r.resolved_at = ("Completed" if ok else "Deferred"), msg, now()
        db.session.commit()
        flash(f"Request {r.status.lower()}: {msg}", "success" if ok else "warning")
    return redirect(url_for("admin.index"))


@bp.route("/purge", methods=["POST"])
@roles_required("admin")
def purge():
    n = purge_expired()
    flash(f"Retention policy applied: {n} account(s) erased.", "success")
    return redirect(url_for("admin.index"))
