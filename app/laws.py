"""Complaint categories mapped to indicative legal provisions.

The mapping is a triage aid for the complainant and officer; it is NOT legal advice and
should be reviewed by a legal expert before real-world use.
Note: the IPC was replaced by the Bharatiya Nyaya Sanhita (BNS) 2023 and the Indian Evidence
Act by the Bharatiya Sakshya Adhiniyam (BSA) 2023, both in force from 1 July 2024.
"""

CATEGORIES = {
    "upi_fraud": ("UPI / Online Banking Fraud", "IT Act 66C, 66D; BNS 318 (cheating)"),
    "phishing": ("Phishing / Fake Website / Impersonation", "IT Act 66C, 66D; BNS 319"),
    "identity_theft": ("Identity Theft", "IT Act 66C"),
    "hacking": ("Hacking / Unauthorised Access", "IT Act 43, 66"),
    "ransomware": ("Ransomware / Data Theft", "IT Act 43, 66; IT Act 72A (disclosure)"),
    "stalking": ("Cyberstalking / Online Harassment", "BNS 78 (stalking), 351 (criminal intimidation)"),
    "sextortion": ("Sextortion / Privacy Violation", "IT Act 66E, 67, 67A; BNS 308 (extortion)"),
    "csam": ("Child Sexual Abuse Material", "IT Act 67B; POCSO Act"),
    "fake_profile": ("Fake Profile / Social Media Abuse", "IT Act 66C, 66D"),
    "other": ("Other Cybercrime", "IT Act 2000 (to be determined by officer)"),
}

IDENTIFIER_KINDS = {
    "upi": "UPI ID",
    "phone": "Phone number",
    "bank_account": "Bank account number",
    "email": "Email address",
    "url": "Website / URL",
}


def category_label(key):
    return CATEGORIES.get(key, (key, ""))[0]


def category_sections(key):
    return CATEGORIES.get(key, ("", ""))[1]
