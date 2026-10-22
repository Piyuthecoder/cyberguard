"""DPDP Act 2023 helpers: consent, access/export, retention, erasure."""
import json
import secrets
from datetime import timedelta

from flask import current_app

from . import db
from .evidence import erase_evidence
from .models import Complaint, Consent, ErasureRequest, OPEN_STATUSES, User, now
from .security import log_audit


def record_consent(user, purpose):
    db.session.add(Consent(user_id=user.id, purpose=purpose, policy_version=current_app.config["POLICY_VERSION"]))
    log_audit("CONSENT_GIVEN", "user", user.id, {"purpose": purpose, "policy": current_app.config["POLICY_VERSION"]},
              actor_id=user.id)


def export_user_data(user):
    return {
        "profile": {"name": user.name, "email": user.email, "phone": user.phone,
                    "created_at": user.created_at.isoformat()},
        "consents": [{"purpose": c.purpose, "policy_version": c.policy_version, "granted": c.granted,
                      "given_at": c.created_at.isoformat(),
                      "withdrawn_at": c.withdrawn_at.isoformat() if c.withdrawn_at else None}
                     for c in user.consents],
        "complaints": [{
            "reference": c.ref, "category": c.category, "title": c.title, "description": c.description,
            "status": c.status, "filed_at": c.created_at.isoformat(),
            "identifiers": [{"type": i.kind, "value": i.value} for i in c.identifiers],
            "evidence": [{"file": e.filename, "sha256": e.sha256, "uploaded_at": e.uploaded_at.isoformat()}
                         for e in c.evidence],
        } for c in user.complaints],
    }


def erase_user(user, note="Erased on request"):
    """Erase a Data Principal. Only allowed when none of their complaints are still under investigation
    (DPDP s.17 lets the State retain data needed for investigation; we defer instead of deleting)."""
    open_cases = [c for c in user.complaints if c.status in OPEN_STATUSES]
    if open_cases:
        return False, f"{len(open_cases)} complaint(s) are still under investigation; data is retained until they close."
    for c in user.complaints:
        for ev in c.evidence:
            if not ev.erased:
                erase_evidence(ev)
        c.description = "[erased at the request of the data principal]"
        c.title = "[erased]"
        c.redacted = True
        for ident in list(c.identifiers):
            db.session.delete(ident)  # suspect identifiers are third-party data tied to this victim's report
    uid = user.id
    user.email = f"erased-{uid}@deleted.invalid"
    user.name, user.phone = "Erased user", None
    user.password_hash = secrets.token_hex(32)
    user.erased = True
    user.verified = False
    log_audit("USER_ERASED", "user", uid, {"note": note})
    return True, "Erased"


def purge_expired():
    """Retention policy: erase users whose complaints are all closed longer ago than RETENTION_YEARS."""
    cutoff = now() - timedelta(days=365 * current_app.config["RETENTION_YEARS"])
    purged = 0
    for u in User.query.filter_by(role="citizen", erased=False):
        cs = u.complaints
        if cs and all(c.status == "Closed" and c.closed_at and c.closed_at < cutoff for c in cs):
            ok, _ = erase_user(u, "Retention period expired")
            purged += int(ok)
    db.session.commit()
    return purged
