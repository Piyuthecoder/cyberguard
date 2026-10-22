import re
from datetime import timedelta

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .models import User, now
from .privacy import record_consent
from .security import check_otp, log_audit, send_otp

bp = Blueprint("auth", __name__)

MAX_FAILS, LOCK_MINUTES = 5, 15
# constant dummy hash so unknown emails take the same time as wrong passwords
_DUMMY = generate_password_hash("not-a-real-password")


def _home():
    return url_for({"citizen": "citizen.dashboard", "officer": "officer.dashboard", "admin": "admin.index"}[current_user.role])


def _strong(pw):
    return len(pw) >= 10 and re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(_home())
    if request.method == "POST":
        f = request.form
        email, name = f.get("email", "").strip().lower(), f.get("name", "").strip()
        phone = re.sub(r"\D", "", f.get("phone", ""))[-10:] or None
        errors = []
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors.append("Enter a valid email address.")
        if len(name) < 2:
            errors.append("Enter your name.")
        if not _strong(f.get("password", "")):
            errors.append("Password must be at least 10 characters with letters and digits.")
        if f.get("password") != f.get("confirm"):
            errors.append("Passwords do not match.")
        if not f.get("consent"):
            errors.append("Consent to process your personal data is required to create an account.")
        existing = User.query.filter_by(email=email).first()
        if existing and existing.verified:
            errors.append("An account with this email already exists.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", form=f), 400
        user = existing or User(email=email, role="citizen")
        user.name, user.phone = name, phone
        user.password_hash = generate_password_hash(f["password"])
        db.session.add(user)
        db.session.flush()
        record_consent(user, "account")
        send_otp(user, "email verification")
        log_audit("USER_REGISTERED", "user", user.id, actor_id=user.id)
        db.session.commit()
        session["otp_uid"], session["otp_purpose"] = user.id, "verify"
        return redirect(url_for("auth.otp"))
    return render_template("register.html", form={})


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(_home())
    if request.method == "POST":
        email, pw = request.form.get("email", "").strip().lower(), request.form.get("password", "")
        user = User.query.filter_by(email=email, erased=False).first()
        if user and user.locked_until and user.locked_until > now():
            flash("Account temporarily locked after repeated failed attempts. Try again later.", "danger")
            return render_template("login.html"), 429
        ok = check_password_hash(user.password_hash if user else _DUMMY, pw) and user is not None
        if not ok:
            if user:
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= MAX_FAILS:
                    user.locked_until = now() + timedelta(minutes=LOCK_MINUTES)
                    user.failed_logins = 0
                log_audit("LOGIN_FAILED", "user", user.id, actor_id=user.id)
                db.session.commit()
            flash("Incorrect email or password.", "danger")
            return render_template("login.html"), 401
        user.failed_logins = 0
        if not user.verified or user.role in ("officer", "admin"):
            send_otp(user, "login" if user.verified else "email verification")
            db.session.commit()
            session["otp_uid"] = user.id
            session["otp_purpose"] = "login" if user.verified else "verify"
            return redirect(url_for("auth.otp"))
        _finish_login(user)
        return redirect(_home())
    return render_template("login.html")


def _finish_login(user):
    session.clear()
    login_user(user)
    session.permanent = True
    log_audit("LOGIN", "user", user.id, actor_id=user.id)
    db.session.commit()


@bp.route("/otp", methods=["GET", "POST"])
def otp():
    user = db.session.get(User, session.get("otp_uid") or 0)
    if not user:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        if request.form.get("resend"):
            send_otp(user, "login" if user.verified else "email verification")
            db.session.commit()
            return redirect(url_for("auth.otp"))
        if check_otp(user, request.form.get("code", "")):
            user.verified = True
            db.session.commit()
            _finish_login(user)
            flash("You are signed in.", "success")
            return redirect(_home())
        db.session.commit()
        flash("That code is incorrect or has expired.", "danger")
        return render_template("otp.html", email=user.email), 400
    return render_template("otp.html", email=user.email)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_audit("LOGOUT", "user", current_user.id)
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("main.index"))
