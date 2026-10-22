# CyberGuard

Cybercrime complaint portal with tamper-evident digital evidence, a complaint-linking engine and a DPDP Act 2023 privacy module.

**Stack:** Python 3.11+ · Flask · SQLAlchemy (SQLite by default, PostgreSQL via `DATABASE_URL`) · Jinja templates · plain HTML/CSS/JS · `cryptography` (Fernet) · Chart.js (CDN). All free and open source.

## Run it (Windows / Linux / macOS)

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
flask --app run create-admin      # first administrator
python run.py                     # http://127.0.0.1:5000
```

Optional: `flask --app run seed-demo` prints demo admin/officer/citizen logins. Tests: `python -m pytest`.

Without SMTP configured, one-time codes are printed in the terminal and shown on screen (dev only).
For real email set `SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM` and `DEV_SHOW_OTP=0`.

## Mapping to the abstract's objectives

| Objective | Where |
|---|---|
| Complaint registration, categories mapped to IT Act sections | `app/laws.py`, `citizen.py`, `new_complaint.html` |
| Encrypted tamper-evident evidence, SHA-256, write-once storage | `app/evidence.py` |
| Complaint Linking Engine (UPI / phone / bank account / email / domain) | `app/linking.py`, `officer/clusters.html` |
| Role-based access (citizen / officer / admin), secure auth | `security.roles_required`, `auth.py` |
| Officer dashboard: assignment, status, notes, analytics | `officer.py`, `officer/*.html` |
| DPDP: consent, retention, erasure, data export | `privacy.py`, `citizen/my_data.html`, `flask purge-expired` |
| Hash-chain audit log of all evidence access | `security.log_audit / verify_chain`, admin page |
| Free-tier deployment | `Procfile` (gunicorn) for Render/Railway; set `DATABASE_URL`, `SECRET_KEY`, `EVIDENCE_KEY`, `COOKIE_SECURE=1` |

## How evidence stays tamper-evident

1. The browser computes SHA-256 of each file before upload; the server recomputes it and flags any mismatch (transit integrity).
2. The file is encrypted (Fernet), written to a new object that can never be overwritten, and set read-only.
3. Filename + hash are anchored in a hash-chained audit log (each entry covers the previous one).
4. "Verify" decrypts, re-hashes and compares against both the database and the log anchor. The tests simulate three attacks: file replaced, file re-encrypted with a stolen key, and database hash rewritten.

## Deviations from the abstract (and why)

- **Python/Flask instead of React + Node/Express**, as requested. Server-rendered pages keep the attack surface small.
- **Session cookies instead of JWT.** For a server-rendered site, HttpOnly SameSite cookies + CSRF tokens are safer than JWTs held in browser storage. OTP is used for email verification and for officer/admin login.
- **Local write-once store instead of MinIO.** `app/evidence.py` is the only module that touches storage; a MinIO Object Lock backend can replace it without changing the rest. Local files are protected by encryption, read-only mode and the audit anchor, but a server admin could still delete them (deletion shows up as "missing" on verify). True WORM needs MinIO/S3 Object Lock.
- **Law references:** since 1 July 2024 the Indian Evidence Act is replaced by the **Bharatiya Sakshya Adhiniyam 2023** (s.63 replaces s.65B) and the IPC by the **BNS 2023**. The certificate and category mapping use the new numbering. Please have these reviewed by your guide or a legal expert.

## Before real use

Treat this as a college prototype: add a legal review of the privacy notice, password-reset flow, rate limiting at the proxy, malware scanning of uploads, backups of `instance/evidence.key` (losing it makes evidence unreadable), and HTTPS.
