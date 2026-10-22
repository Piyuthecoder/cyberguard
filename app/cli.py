import secrets

import click
from werkzeug.security import generate_password_hash

from . import db
from .models import User
from .privacy import purge_expired


def register(app):
    @app.cli.command("create-admin")
    @click.option("--email", prompt=True)
    @click.option("--name", prompt=True)
    @click.password_option()
    def create_admin(email, name, password):
        """Create the first administrator account."""
        if User.query.filter_by(email=email.lower()).first():
            raise click.ClickException("User already exists")
        db.session.add(User(email=email.lower(), name=name, role="admin", verified=True,
                            password_hash=generate_password_hash(password)))
        db.session.commit()
        click.echo("Admin created.")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Create demo admin/officer/citizen accounts with random passwords (development only)."""
        for email, name, role in [("admin@demo.test", "Demo Admin", "admin"),
                                  ("officer@demo.test", "Demo Officer", "officer"),
                                  ("citizen@demo.test", "Demo Citizen", "citizen")]:
            if User.query.filter_by(email=email).first():
                continue
            pw = secrets.token_urlsafe(12) + "9"
            db.session.add(User(email=email, name=name, role=role, verified=True,
                                password_hash=generate_password_hash(pw)))
            click.echo(f"{role:8} {email}  password: {pw}")
        db.session.commit()

    @app.cli.command("purge-expired")
    def purge_cmd():
        """Apply the data-retention policy (run daily from a scheduler)."""
        click.echo(f"Erased {purge_expired()} account(s).")
