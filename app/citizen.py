import io
import json
from datetime import date

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template, request,
                   send_file, url_for)
from flask_login import current_user, login_required

from . import db
from .evidence import EvidenceError, add_evidence, check_name, read_evidence, verify_evidence
from .laws import CATEGORIES, IDENTIFIER_KINDS, category_label, category_sections
from .linking import InvalidIdentifier, link_complaint, links_for, normalise
from .models import Complaint, Consent, ErasureRequest, Evidence, Identifier, OPEN_STATUSES, now
from .privacy import export_user_data, record_consent
from .security import log_audit, roles_required

bp = Blueprint("citizen", __name__)


def _can_see(complaint):
    return current_user.role in ("officer", "admin") or complaint.user_id == current_user.id


def _get_complaint(cid):
    c = db.session.get(Complaint, cid) or abort(404)
    if not _can_see(c):
        abort(403)
    return c


def _get_evidence(eid):
    ev = db.session.get(Evidence, eid) or abort(404)
    _get_complaint(ev.complaint_id)
    return ev


def _hashes():
    try:
        h = json.loads(request.form.get("client_hashes") or "{}")
        return h if isinstance(h, dict) else {}
    except ValueError:
        return {}


@bp.route("/dashboard")
@roles_required("citizen")
def dashboard():
    cs = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.id.desc()).all()
    return render_template("citizen/dashboard.html", complaints=cs, label=category_label)


@bp.route("/complaints/new", methods=["GET", "POST"])
@roles_required("citizen")
def new_complaint():
    if request.method == "POST":
        f, errors = request.form, []
        category = f.get("category")
        title, desc = f.get("title", "").strip(), f.get("description", "").strip()
        if category not in CATEGORIES:
            errors.append("Choose a complaint category.")
        if len(title) < 5:
            errors.append("Give the complaint a short title (min 5 characters).")
        if len(desc) < 20:
            errors.append("Describe what happened (min 20 characters).")
        incident = None
        if f.get("incident_date"):
            try:
                incident = date.fromisoformat(f["incident_date"])
                if incident > date.today():
                    errors.append("Incident date cannot be in the future.")
            except ValueError:
                errors.append("Invalid incident date.")
        try:
            amount = max(0, float(f.get("amount_lost") or 0))
        except ValueError:
            amount, _ = 0, errors.append("Amount lost must be a number.")
        if not f.get("consent"):
            errors.append("Consent to process this complaint is required.")

        idents = []
        for kind, raw in zip(f.getlist("id_kind"), f.getlist("id_value")):
            if not raw.strip():
                continue
            try:
                idents.append((kind, normalise(kind, raw)))
            except InvalidIdentifier as exc:
                errors.append(f"{IDENTIFIER_KINDS.get(kind, kind)}: {exc}")
        files = [x for x in request.files.getlist("evidence") if x and x.filename]
        for x in files:
            try:
                check_name(x)
            except EvidenceError as exc:
                errors.append(str(exc))
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("citizen/new_complaint.html", form=f, categories=CATEGORIES,
                                   kinds=IDENTIFIER_KINDS), 400

        c = Complaint(user_id=current_user.id, category=category, title=title, description=desc,
                      incident_date=incident, amount_lost=amount, ref="PENDING")
        db.session.add(c)
        db.session.flush()
        c.ref = f"CG-{now().year}-{c.id:06d}"
        for kind, val in set(idents):
            db.session.add(Identifier(complaint_id=c.id, kind=kind, value=val))
        db.session.flush()
        record_consent(current_user, "complaint_processing")
        log_audit("COMPLAINT_FILED", "complaint", c.id, {"ref": c.ref, "category": category})
        hashes = _hashes()
        for x in files:
            add_evidence(c, x, hashes.get(x.filename), current_user.id)
        db.session.refresh(c)
        for link in link_complaint(c):
            log_audit("LINK_DETECTED", "complaint", c.id, {"with": link.complaint_a + link.complaint_b - c.id,
                                                          "kind": link.kind})
        db.session.commit()
        flash(f"Complaint registered. Your reference number is {c.ref}.", "success")
        return redirect(url_for("citizen.complaint", cid=c.id))
    return render_template("citizen/new_complaint.html", form={}, categories=CATEGORIES, kinds=IDENTIFIER_KINDS)


@bp.route("/complaints/<int:cid>")
@login_required
def complaint(cid):
    c = _get_complaint(cid)
    if current_user.role != "citizen":
        return redirect(url_for("officer.case", cid=cid))
    return render_template("citizen/complaint.html", c=c, label=category_label, sections=category_sections,
                           kinds=IDENTIFIER_KINDS, can_upload=c.status in OPEN_STATUSES)


@bp.route("/complaints/<int:cid>/evidence", methods=["POST"])
@roles_required("citizen")
def upload_evidence(cid):
    c = _get_complaint(cid)
    if c.user_id != current_user.id or c.status not in OPEN_STATUSES:
        abort(403)
    files = [x for x in request.files.getlist("evidence") if x and x.filename]
    if not files:
        flash("Choose at least one file.", "danger")
        return redirect(url_for("citizen.complaint", cid=cid))
    try:
        for x in files:
            check_name(x)
    except EvidenceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("citizen.complaint", cid=cid))
    hashes = _hashes()
    for x in files:
        add_evidence(c, x, hashes.get(x.filename), current_user.id)
    db.session.commit()
    flash(f"{len(files)} file(s) stored securely. They cannot be edited or replaced.", "success")
    return redirect(url_for("citizen.complaint", cid=cid))


@bp.route("/evidence/<int:eid>/verify", methods=["POST"])
@login_required
def verify(eid):
    ev = _get_evidence(eid)
    result = verify_evidence(ev)
    log_audit("EVIDENCE_VERIFIED", "evidence", ev.id, {"ok": bool(result.get("ok"))})
    db.session.commit()
    return jsonify(result)


@bp.route("/evidence/<int:eid>/download")
@login_required
def download(eid):
    ev = _get_evidence(eid)
    try:
        data = read_evidence(ev)
    except EvidenceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("citizen.complaint", cid=ev.complaint_id))
    log_audit("EVIDENCE_DOWNLOADED", "evidence", ev.id, {"file": ev.filename})
    db.session.commit()
    return send_file(io.BytesIO(data), as_attachment=True, download_name=ev.filename,
                     mimetype="application/octet-stream")


@bp.route("/evidence/<int:eid>/certificate")
@login_required
def certificate(eid):
    ev = _get_evidence(eid)
    result = verify_evidence(ev)
    log_audit("CERTIFICATE_ISSUED", "evidence", ev.id)
    db.session.commit()
    return render_template("certificate.html", ev=ev, c=ev.complaint, result=result, now=now())


# ------------------------------------------------------------------ DPDP: My data
@bp.route("/my-data")
@roles_required("citizen")
def my_data():
    reqs = ErasureRequest.query.filter_by(user_id=current_user.id).order_by(ErasureRequest.id.desc()).all()
    return render_template("citizen/my_data.html", consents=current_user.consents, requests=reqs)


@bp.route("/my-data/export")
@roles_required("citizen")
def export():
    log_audit("DATA_EXPORTED", "user", current_user.id)
    db.session.commit()
    payload = json.dumps(export_user_data(current_user), indent=2).encode()
    return send_file(io.BytesIO(payload), as_attachment=True, download_name="my-cyberguard-data.json",
                     mimetype="application/json")


@bp.route("/my-data/erase", methods=["POST"])
@roles_required("citizen")
def request_erasure():
    if ErasureRequest.query.filter_by(user_id=current_user.id, status="Pending").first():
        flash("You already have a pending request.", "info")
        return redirect(url_for("citizen.my_data"))
    for c in Consent.query.filter_by(user_id=current_user.id, withdrawn_at=None):
        c.granted, c.withdrawn_at = False, now()
    db.session.add(ErasureRequest(user_id=current_user.id))
    log_audit("ERASURE_REQUESTED", "user", current_user.id)
    db.session.commit()
    flash("Consent withdrawn and erasure requested. Data tied to open investigations is retained until they close.", "success")
    return redirect(url_for("citizen.my_data"))
