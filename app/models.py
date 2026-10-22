from datetime import datetime, timezone

from flask_login import UserMixin

from . import db


def now():
    """Naive UTC timestamp (SQLite-friendly)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


STATUSES = ["Submitted", "Under Review", "Investigating", "Resolved", "Closed"]
OPEN_STATUSES = {"Submitted", "Under Review", "Investigating"}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="citizen")  # citizen | officer | admin
    verified = db.Column(db.Boolean, default=False)
    otp_hash = db.Column(db.String(64))
    otp_expires = db.Column(db.DateTime)
    otp_attempts = db.Column(db.Integer, default=0)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    erased = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now)


class Consent(db.Model):
    """DPDP Act 2023: record of what the Data Principal agreed to, when, and under which policy version."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    purpose = db.Column(db.String(60), nullable=False)  # account | complaint_processing
    policy_version = db.Column(db.String(10), nullable=False)
    granted = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now)
    withdrawn_at = db.Column(db.DateTime)
    user = db.relationship("User", backref="consents")


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ref = db.Column(db.String(24), unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    officer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    category = db.Column(db.String(60), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    incident_date = db.Column(db.Date)
    amount_lost = db.Column(db.Numeric(12, 2), default=0)
    status = db.Column(db.String(20), default="Submitted", index=True)
    created_at = db.Column(db.DateTime, default=now)
    updated_at = db.Column(db.DateTime, default=now, onupdate=now)
    closed_at = db.Column(db.DateTime)
    redacted = db.Column(db.Boolean, default=False)

    user = db.relationship("User", foreign_keys=[user_id], backref="complaints")
    officer = db.relationship("User", foreign_keys=[officer_id])
    identifiers = db.relationship("Identifier", backref="complaint", cascade="all, delete-orphan")
    evidence = db.relationship("Evidence", backref="complaint", order_by="Evidence.id")
    notes = db.relationship("CaseNote", backref="complaint", order_by="CaseNote.id")


class Identifier(db.Model):
    """Suspect identifier (UPI ID, phone, bank account, ...) stored in normalised form for linking."""
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey("complaint.id"), nullable=False)
    kind = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(300), nullable=False)
    __table_args__ = (db.Index("ix_identifier_lookup", "kind", "value"),)


class Link(db.Model):
    """Two complaints sharing an identifier, found by the Complaint Linking Engine."""
    id = db.Column(db.Integer, primary_key=True)
    complaint_a = db.Column(db.Integer, db.ForeignKey("complaint.id"), nullable=False)
    complaint_b = db.Column(db.Integer, db.ForeignKey("complaint.id"), nullable=False)
    kind = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=now)
    __table_args__ = (db.UniqueConstraint("complaint_a", "complaint_b", "kind", "value"),)


class Evidence(db.Model):
    """Write-once evidence record. There is deliberately no update route for any of these fields."""
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey("complaint.id"), nullable=False)
    object_id = db.Column(db.String(32), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    transit_verified = db.Column(db.Boolean)  # browser-computed hash matched server hash
    uploaded_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    uploaded_at = db.Column(db.DateTime, default=now)
    erased = db.Column(db.Boolean, default=False)


class CaseNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey("complaint.id"), nullable=False)
    officer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=now)
    officer = db.relationship("User")


class AuditLog(db.Model):
    """Append-only hash chain: every row's hash covers the previous row's hash."""
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(32), nullable=False)
    actor_id = db.Column(db.Integer)
    action = db.Column(db.String(40), nullable=False)
    target_type = db.Column(db.String(20))
    target_id = db.Column(db.Integer)
    details = db.Column(db.Text, default="{}")
    ip = db.Column(db.String(45))
    prev_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), nullable=False)


class ErasureRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(12), default="Pending")  # Pending | Completed | Deferred
    note = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=now)
    resolved_at = db.Column(db.DateTime)
    user = db.relationship("User")
