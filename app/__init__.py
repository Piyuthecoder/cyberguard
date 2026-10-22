import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet
from flask import Flask, render_template
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def _persisted(path: Path, generate) -> str:
    """Read a secret from disk, creating it on first run (dev convenience)."""
    if path.exists():
        return path.read_text().strip()
    value = generate()
    path.write_text(value)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    inst = Path(app.instance_path)
    inst.mkdir(parents=True, exist_ok=True)

    db_url = os.environ.get("DATABASE_URL", f"sqlite:///{(inst / 'cyberguard.db').as_posix()}")
    if db_url.startswith("postgres://"):  # Render/Railway style URL
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or _persisted(inst / "secret.key", lambda: secrets.token_hex(32)),
        EVIDENCE_KEY=os.environ.get("EVIDENCE_KEY") or _persisted(inst / "evidence.key", lambda: Fernet.generate_key().decode()),
        SQLALCHEMY_DATABASE_URI=db_url,
        EVIDENCE_DIR=os.environ.get("EVIDENCE_DIR", str(inst / "evidence")),
        MAX_CONTENT_LENGTH=25 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=60 * 60,  # 1 hour
        DEV_SHOW_OTP=os.environ.get("DEV_SHOW_OTP", "1") == "1",  # set 0 in production
        RETENTION_YEARS=int(os.environ.get("RETENTION_YEARS", "3")),
        POLICY_VERSION="1.0",
        OTP_MINUTES=10,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.config["EVIDENCE_DIR"]).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "warning"

    from .models import User

    @login_manager.user_loader
    def load_user(uid):
        user = db.session.get(User, int(uid))
        return user if user and not user.erased else None

    from . import auth, citizen, officer, admin, main, cli

    for bp in (main.bp, auth.bp, citizen.bp, officer.bp, admin.bp):
        app.register_blueprint(bp)
    cli.register(app)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
        )
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, msg="You do not have access to this page."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, msg="Page not found."), 404

    @app.errorhandler(413)
    def too_large(_):
        return render_template("error.html", code=413, msg="Upload too large (limit 25 MB per request)."), 413

    with app.app_context():
        db.create_all()
    return app
