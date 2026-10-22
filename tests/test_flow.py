import io
import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app, db  # noqa: E402
from app import auth as auth_mod  # noqa: E402
from app.models import AuditLog, Complaint, Evidence, User  # noqa: E402
from app.privacy import erase_user  # noqa: E402
from app.security import send_otp as real_send_otp, verify_chain  # noqa: E402

PW = "CorrectHorse123"


@pytest.fixture()
def app(tmp_path, monkeypatch):
    app = create_app({
        "TESTING": True, "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 't.db'}",
        "EVIDENCE_DIR": str(tmp_path / "ev"), "DEV_SHOW_OTP": False,
    })
    app.codes = []
    monkeypatch.setattr(auth_mod, "send_otp", lambda u, p="x": app.codes.append(real_send_otp(u, p)) or app.codes[-1])
    yield app


def register(client, app, email, name="Test User"):
    r = client.post("/register", data={"name": name, "email": email, "password": PW, "confirm": PW, "consent": "1"})
    assert r.status_code == 302, r.data
    r = client.post("/otp", data={"code": app.codes[-1]})
    assert r.status_code == 302


def file_complaint(client, phone="98765 43210", upi="Fraud.Guy@okbank", files=None):
    data = {
        "category": "upi_fraud", "title": "Fake refund scam", "description": "Caller asked me to scan a QR to get a refund.",
        "amount_lost": "5000", "consent": "1", "id_kind": ["phone", "upi"], "id_value": [phone, upi],
        "client_hashes": "{}",
    }
    if files:
        data["evidence"] = [(io.BytesIO(b), n) for n, b in files]
    return client.post("/complaints/new", data=data, content_type="multipart/form-data")


def make_staff(app, role="officer", email="off@x.test"):
    with app.app_context():
        db.session.add(User(email=email, name=role.title(), role=role, verified=True, password_hash=generate_password_hash(PW)))
        db.session.commit()


def staff_login(client, app, email):
    client.post("/login", data={"email": email, "password": PW})
    client.post("/otp", data={"code": app.codes[-1]})


def test_filing_and_evidence_integrity(app):
    c = app.test_client()
    register(c, app, "a@x.test")
    r = file_complaint(c, files=[("screenshot.png", b"\x89PNG-fake-bytes")])
    assert r.status_code == 302
    with app.app_context():
        ev = Evidence.query.one()
        assert len(ev.sha256) == 64
        path = Path(app.config["EVIDENCE_DIR"]) / f"{ev.object_id}.enc"
        assert b"PNG-fake" not in path.read_bytes()  # encrypted at rest
        assert not os.access(path, os.W_OK) or os.geteuid() == 0  # read-only (root ignores mode bits)
        assert c.post(f"/evidence/{ev.id}/verify").get_json()["ok"] is True

        # Attack 1: file replaced with garbage
        os.chmod(path, 0o644)
        path.write_bytes(b"garbage")
        res = c.post(f"/evidence/{ev.id}/verify").get_json()
        assert not res.get("ok") and res["error"]

        # Attack 2: attacker re-encrypts altered content with a stolen key
        path.write_bytes(Fernet(app.config["EVIDENCE_KEY"].encode()).encrypt(b"forged"))
        res = c.post(f"/evidence/{ev.id}/verify").get_json()
        assert res["db_match"] is False and not res["ok"]

        # Attack 3: attacker ALSO rewrites the DB hash -> audit-log anchor still catches it
        import hashlib
        ev.sha256 = hashlib.sha256(b"forged").hexdigest()
        db.session.commit()
        res = c.post(f"/evidence/{ev.id}/verify").get_json()
        assert res["db_match"] is True and res["log_match"] is False and not res["ok"]


def test_rejects_disallowed_file_type(app):
    c = app.test_client()
    register(c, app, "a@x.test")
    r = file_complaint(c, files=[("evil.exe", b"MZ")])
    assert r.status_code == 400
    with app.app_context():
        assert Complaint.query.count() == 0


def test_linking_engine_across_formats(app):
    a, b = app.test_client(), app.test_client()
    register(a, app, "a@x.test")
    register(b, app, "b@x.test")
    file_complaint(a, phone="+91 98765-43210", upi="fraud.guy@okbank")
    file_complaint(b, phone="09876543210", upi="other@ybl")  # same phone, different format
    make_staff(app)
    o = app.test_client()
    staff_login(o, app, "off@x.test")
    page = o.get("/officer/clusters").get_data(as_text=True)
    assert "Cluster of 2 complaints" in page and "9876543210" in page
    stats = o.get("/officer/api/analytics").get_json()
    assert stats["repeat_identifiers"][0]["complaints"] == 2


def test_rbac_and_isolation(app):
    a, b = app.test_client(), app.test_client()
    register(a, app, "a@x.test")
    register(b, app, "b@x.test")
    file_complaint(a)
    assert a.get("/officer/").status_code == 403
    assert a.get("/admin/").status_code == 403
    assert b.get("/complaints/1").status_code == 403  # another citizen's complaint
    assert app.test_client().get("/complaints/1").status_code == 302  # anonymous -> login


def test_audit_chain_detects_tampering(app):
    c = app.test_client()
    register(c, app, "a@x.test")
    file_complaint(c)
    with app.app_context():
        ok, n, _ = verify_chain()
        assert ok and n > 3
        row = AuditLog.query.filter_by(action="COMPLAINT_FILED").one()
        row.details = '{"ref":"CG-FORGED"}'
        db.session.commit()
        ok, _, bad = verify_chain()
        assert not ok and bad == row.id


def test_staff_login_requires_otp_and_lockout(app):
    make_staff(app)
    c = app.test_client()
    r = c.post("/login", data={"email": "off@x.test", "password": PW})
    assert r.headers["Location"].endswith("/otp")
    assert c.get("/officer/").status_code == 302  # password alone is not enough
    for _ in range(5):
        app.test_client().post("/login", data={"email": "off@x.test", "password": "wrong-password1"})
    assert app.test_client().post("/login", data={"email": "off@x.test", "password": PW}).status_code == 429


def test_erasure_deferred_until_case_closed(app):
    c = app.test_client()
    register(c, app, "a@x.test")
    file_complaint(c, files=[("note.txt", b"evidence text")])
    with app.app_context():
        user = User.query.filter_by(email="a@x.test").one()
        ok, msg = erase_user(user)
        assert not ok and "investigation" in msg
        cm = Complaint.query.one()
        cm.status = "Closed"
        ok, _ = erase_user(user)
        db.session.commit()
        assert ok and user.erased and user.email.endswith("@deleted.invalid")
        assert Evidence.query.one().erased
        assert not any(Path(app.config["EVIDENCE_DIR"]).iterdir())
        assert verify_chain()[0]  # chain stays valid after erasure
