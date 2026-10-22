from collections import Counter
from datetime import timedelta

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func

from . import db
from .laws import CATEGORIES, IDENTIFIER_KINDS, category_label, category_sections
from .linking import clusters, links_for
from .models import CaseNote, Complaint, Identifier, Link, STATUSES, User, now
from .security import log_audit, roles_required

bp = Blueprint("officer", __name__, url_prefix="/officer")


def _link_counts():
    counts = Counter()
    for l in Link.query.all():
        counts[l.complaint_a] += 1
        counts[l.complaint_b] += 1
    return counts


@bp.route("/")
@roles_required("officer", "admin")
def dashboard():
    q = Complaint.query
    status, cat, view = request.args.get("status"), request.args.get("category"), request.args.get("view")
    if status in STATUSES:
        q = q.filter_by(status=status)
    if cat in CATEGORIES:
        q = q.filter_by(category=cat)
    if view == "mine":
        q = q.filter_by(officer_id=current_user.id)
    elif view == "unassigned":
        q = q.filter(Complaint.officer_id.is_(None))
    counts = _link_counts()
    complaints = q.order_by(Complaint.id.desc()).limit(200).all()
    if view == "linked":
        complaints = [c for c in complaints if counts[c.id]]
    stats = {
        "total": Complaint.query.count(),
        "open": Complaint.query.filter(Complaint.status.in_(["Submitted", "Under Review", "Investigating"])).count(),
        "unassigned": Complaint.query.filter(Complaint.officer_id.is_(None), Complaint.status != "Closed").count(),
        "linked": len(counts),
    }
    return render_template("officer/dashboard.html", complaints=complaints, counts=counts, stats=stats,
                           statuses=STATUSES, categories=CATEGORIES, label=category_label, args=request.args)


@bp.route("/case/<int:cid>")
@roles_required("officer", "admin")
def case(cid):
    c = db.session.get(Complaint, cid) or abort(404)
    log_audit("CASE_VIEWED", "complaint", c.id)
    db.session.commit()
    officers = User.query.filter(User.role == "officer", User.erased.is_(False)).all() if current_user.role == "admin" else []
    return render_template("officer/case.html", c=c, links=links_for(c.id), statuses=STATUSES, officers=officers,
                           label=category_label, sections=category_sections, kinds=IDENTIFIER_KINDS)


@bp.route("/case/<int:cid>/status", methods=["POST"])
@roles_required("officer", "admin")
def set_status(cid):
    c = db.session.get(Complaint, cid) or abort(404)
    new = request.form.get("status")
    if new not in STATUSES:
        abort(400)
    old, c.status = c.status, new
    c.closed_at = now() if new == "Closed" else None
    log_audit("STATUS_CHANGED", "complaint", c.id, {"from": old, "to": new})
    db.session.commit()
    flash(f"Status changed to {new}.", "success")
    return redirect(url_for("officer.case", cid=cid))


@bp.route("/case/<int:cid>/note", methods=["POST"])
@roles_required("officer", "admin")
def add_note(cid):
    c = db.session.get(Complaint, cid) or abort(404)
    text = request.form.get("text", "").strip()
    if text:
        db.session.add(CaseNote(complaint_id=c.id, officer_id=current_user.id, text=text))
        log_audit("NOTE_ADDED", "complaint", c.id)
        db.session.commit()
    return redirect(url_for("officer.case", cid=cid))


@bp.route("/case/<int:cid>/assign", methods=["POST"])
@roles_required("officer", "admin")
def assign(cid):
    c = db.session.get(Complaint, cid) or abort(404)
    target = current_user.id
    if current_user.role == "admin" and request.form.get("officer_id"):
        target = int(request.form["officer_id"])
        u = db.session.get(User, target)
        if not u or u.role != "officer":
            abort(400)
    c.officer_id = target
    if c.status == "Submitted":
        c.status = "Under Review"
    log_audit("CASE_ASSIGNED", "complaint", c.id, {"officer": target})
    db.session.commit()
    flash("Case assigned.", "success")
    return redirect(url_for("officer.case", cid=cid))


@bp.route("/clusters")
@roles_required("officer", "admin")
def cluster_view():
    return render_template("officer/clusters.html", groups=clusters(), kinds=IDENTIFIER_KINDS, label=category_label)


@bp.route("/analytics")
@roles_required("officer", "admin")
def analytics():
    return render_template("officer/analytics.html")


@bp.route("/api/analytics")
@roles_required("officer", "admin")
def analytics_data():
    by_cat = dict(db.session.query(Complaint.category, func.count()).group_by(Complaint.category).all())
    by_status = dict(db.session.query(Complaint.status, func.count()).group_by(Complaint.status).all())
    since = now() - timedelta(days=29)
    per_day = Counter(c.created_at.date().isoformat() for c in Complaint.query.filter(Complaint.created_at >= since))
    days = [(since + timedelta(days=i)).date().isoformat() for i in range(30)]
    repeat = (
        db.session.query(Identifier.kind, Identifier.value, func.count(func.distinct(Identifier.complaint_id)).label("n"))
        .group_by(Identifier.kind, Identifier.value).having(func.count(func.distinct(Identifier.complaint_id)) > 1)
        .order_by(func.count(func.distinct(Identifier.complaint_id)).desc()).limit(10).all()
    )
    return jsonify({
        "categories": {category_label(k): v for k, v in by_cat.items()},
        "statuses": {s: by_status.get(s, 0) for s in STATUSES},
        "daily": {"labels": days, "values": [per_day.get(d, 0) for d in days]},
        "total_loss": float(db.session.query(func.coalesce(func.sum(Complaint.amount_lost), 0)).scalar()),
        "repeat_identifiers": [{"kind": IDENTIFIER_KINDS.get(k, k), "value": v, "complaints": n} for k, v, n in repeat],
    })
