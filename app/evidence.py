"""Encrypted, tamper-evident, write-once evidence storage.

Pipeline on upload:
  1. SHA-256 of the original bytes (and compared with the hash the browser computed before upload)
  2. Encrypt with Fernet (AES-128-CBC + HMAC) and write to a NEW file (mode 'xb' => never overwrites)
  3. Make the file read-only on disk
  4. Anchor filename + hash in the hash-chained audit log
Verification decrypts, re-hashes and compares against BOTH the database and the audit log anchor,
so altering the file, the DB row, or the log is each detected.
"""
import json
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
from werkzeug.utils import secure_filename

from . import db
from .models import AuditLog, Evidence
from .security import log_audit, sha256_hex

ALLOWED_EXT = {
    "pdf", "png", "jpg", "jpeg", "gif", "webp", "txt", "log", "eml", "msg", "csv", "json",
    "mp4", "mov", "mp3", "wav", "zip", "docx", "xlsx",
}


class EvidenceError(Exception):
    pass


def _path(object_id):
    return Path(current_app.config["EVIDENCE_DIR"]) / f"{object_id}.enc"


def _fernet():
    return Fernet(current_app.config["EVIDENCE_KEY"].encode())


def check_name(file_storage):
    """Validate a filename/extension before anything is written. Returns the safe name."""
    name = secure_filename(file_storage.filename or "")
    if not name or "." not in name or name.rsplit(".", 1)[1].lower() not in ALLOWED_EXT:
        raise EvidenceError(f"'{file_storage.filename}': file type not allowed")
    return name


def add_evidence(complaint, file_storage, client_hash=None, actor_id=None):
    name = check_name(file_storage)
    data = file_storage.read()
    if not data:
        raise EvidenceError(f"'{name}' is empty")
    digest = sha256_hex(data)
    transit_ok = None
    if client_hash:
        transit_ok = client_hash.lower() == digest
    object_id = secrets.token_hex(16)
    path = _path(object_id)
    with open(path, "xb") as fh:  # exclusive create: cannot overwrite an existing object
        fh.write(_fernet().encrypt(data))
    try:
        os.chmod(path, 0o444)  # read-only (WORM-style) at the OS level
    except OSError:
        pass
    ev = Evidence(
        complaint_id=complaint.id, object_id=object_id, filename=name, size=len(data),
        sha256=digest, transit_verified=transit_ok, uploaded_by=actor_id,
    )
    db.session.add(ev)
    db.session.flush()
    log_audit("EVIDENCE_UPLOADED", "evidence", ev.id,
              {"complaint": complaint.ref, "file": name, "sha256": digest, "size": len(data),
               "transit_verified": transit_ok}, actor_id=actor_id)
    return ev


def read_evidence(ev):
    """Decrypt and return bytes. Raises EvidenceError if the object is missing/corrupt."""
    if ev.erased:
        raise EvidenceError("This evidence was erased under the retention/erasure policy.")
    try:
        return _fernet().decrypt(_path(ev.object_id).read_bytes())
    except FileNotFoundError:
        raise EvidenceError("Stored object is missing")
    except InvalidToken:
        raise EvidenceError("Stored object failed its authenticity check (modified or wrong key)")


def verify_evidence(ev):
    """Return dict describing integrity against DB hash and the audit-log anchor."""
    result = {"db_match": False, "log_match": False, "anchor_found": False, "error": None, "sha256": ev.sha256}
    anchor = None
    for e in AuditLog.query.filter_by(action="EVIDENCE_UPLOADED", target_type="evidence", target_id=ev.id):
        anchor = json.loads(e.details).get("sha256")
    result["anchor_found"] = anchor is not None
    try:
        actual = sha256_hex(read_evidence(ev))
    except EvidenceError as exc:
        result["error"] = str(exc)
        return result
    result["actual"] = actual
    result["db_match"] = actual == ev.sha256
    result["log_match"] = anchor is not None and actual == anchor
    result["ok"] = result["db_match"] and result["log_match"]
    return result


def erase_evidence(ev):
    """Administrative erasure (retention expiry / DPDP erasure of a closed case). Logged with the hash."""
    p = _path(ev.object_id)
    try:
        os.chmod(p, 0o644)
        p.unlink()
    except FileNotFoundError:
        pass
    ev.erased = True
    log_audit("EVIDENCE_ERASED", "evidence", ev.id, {"sha256": ev.sha256, "file": ev.filename})
