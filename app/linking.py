"""Complaint Linking Engine.

Every suspect identifier is normalised (so "+91 98765-43210", "09876543210" and "9876543210"
are the same phone). When a complaint is filed, any earlier complaint sharing an identifier is
linked to it. Officers then see clusters of complaints that point to the same fraudster.
"""
import re
from collections import defaultdict
from urllib.parse import urlparse

from . import db
from .models import Complaint, Identifier, Link

UPI_RE = re.compile(r"^[a-z0-9.\-_]{2,100}@[a-z]{2,40}$")


class InvalidIdentifier(ValueError):
    pass


def normalise(kind, raw):
    v = (raw or "").strip()
    if kind == "upi":
        v = v.lower().replace(" ", "")
        if not UPI_RE.match(v):
            raise InvalidIdentifier("UPI ID must look like name@bank")
    elif kind == "phone":
        digits = re.sub(r"\D", "", v)
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        digits = digits.lstrip("0") if len(digits) == 11 else digits
        if not re.fullmatch(r"[6-9]\d{9}", digits):
            raise InvalidIdentifier("Enter a valid 10-digit Indian mobile number")
        v = digits
    elif kind == "bank_account":
        v = re.sub(r"[\s-]", "", v)
        if not re.fullmatch(r"\d{9,18}", v):
            raise InvalidIdentifier("Bank account number must be 9-18 digits")
    elif kind == "email":
        v = v.lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise InvalidIdentifier("Enter a valid email address")
    elif kind == "url":
        parsed = urlparse(v if "://" in v else "//" + v)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if "." not in host:
            raise InvalidIdentifier("Enter a valid website address")
        v = host  # link on the domain
    else:
        raise InvalidIdentifier("Unknown identifier type")
    return v


def link_complaint(complaint):
    """Create Link rows between this complaint and any earlier one sharing an identifier."""
    created = []
    for ident in complaint.identifiers:
        others = (
            Identifier.query.filter(
                Identifier.kind == ident.kind,
                Identifier.value == ident.value,
                Identifier.complaint_id != complaint.id,
            ).all()
        )
        for o in others:
            a, b = sorted((complaint.id, o.complaint_id))
            exists = Link.query.filter_by(complaint_a=a, complaint_b=b, kind=ident.kind, value=ident.value).first()
            if not exists:
                link = Link(complaint_a=a, complaint_b=b, kind=ident.kind, value=ident.value)
                db.session.add(link)
                created.append(link)
    db.session.flush()
    return created


def links_for(complaint_id):
    """Return [(other_complaint, kind, value)] for one complaint."""
    rows = Link.query.filter((Link.complaint_a == complaint_id) | (Link.complaint_b == complaint_id)).all()
    out = []
    for r in rows:
        other_id = r.complaint_b if r.complaint_a == complaint_id else r.complaint_a
        out.append((db.session.get(Complaint, other_id), r.kind, r.value))
    return out


def clusters():
    """Connected components of the link graph (union-find), largest first."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    shared = defaultdict(set)
    for l in Link.query.all():
        parent[find(l.complaint_a)] = find(l.complaint_b)
        shared[(l.kind, l.value)].update((l.complaint_a, l.complaint_b))

    groups = defaultdict(lambda: {"complaints": set(), "identifiers": set()})
    for cid in list(parent):
        groups[find(cid)]["complaints"].add(cid)
    for key, cids in shared.items():
        groups[find(next(iter(cids)))]["identifiers"].add(key)

    result = []
    for g in groups.values():
        comps = Complaint.query.filter(Complaint.id.in_(g["complaints"])).order_by(Complaint.id).all()
        result.append({
            "complaints": comps,
            "identifiers": sorted(g["identifiers"]),
            "victims": len({c.user_id for c in comps}),
            "loss": sum(float(c.amount_lost or 0) for c in comps),
        })
    return sorted(result, key=lambda g: (-len(g["complaints"]), -g["loss"]))
