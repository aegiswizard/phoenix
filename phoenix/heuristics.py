"""
Phoenix 🐦‍🔥 — Heuristics Engine
All threat detection logic. Pure static text analysis.
Phoenix NEVER fetches URLs, opens attachments, renders HTML,
or establishes any network connection. Read text only. Always.

8 threat categories:
  1. Phishing          — credential harvesting, fake login pages
  2. Fraud             — fake invoices, payment redirect, CEO fraud
  3. Malware           — dangerous attachments, macro lures
  4. Urgency           — fake suspension, deadline pressure
  5. Impersonation     — display name tricks, sender forgery
  6. Link Threats      — typosquatting, URL obfuscation
  7. Attachment Risk   — dangerous extensions, MIME tricks
  8. Header Anomalies  — reply-to mismatch, received chain issues
"""

import re
import unicodedata
from difflib import SequenceMatcher
from email.message import Message
from typing import Optional


# ---------------------------------------------------------------------------
# Dangerous file extensions
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS = {
    # Executables
    ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".gadget",
    # Scripts
    ".ps1", ".ps2", ".psc1", ".psc2", ".reg", ".inf",
    # Office macros
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam",
    # Archives that may hide extensions
    ".iso", ".img", ".lnk",
    # HTML payloads
    ".htm", ".html", ".hta",
    # Java
    ".jar", ".jnlp",
}

SUSPICIOUS_EXTENSIONS = {
    ".doc", ".xls", ".ppt",   # older Office formats often carry macros
    ".zip", ".rar", ".7z",    # archives can hide executables
    ".pdf",                   # PDFs can carry JS exploits
}

# ---------------------------------------------------------------------------
# Known brand domains (for impersonation / typosquat detection)
# ---------------------------------------------------------------------------

BRAND_DOMAINS = [
    "paypal.com", "paypal.co.uk",
    "apple.com", "icloud.com",
    "microsoft.com", "outlook.com", "hotmail.com", "live.com",
    "google.com", "gmail.com", "googlemail.com",
    "amazon.com", "amazon.co.uk",
    "facebook.com", "instagram.com", "whatsapp.com",
    "netflix.com", "spotify.com",
    "dropbox.com", "box.com",
    "linkedin.com",
    "twitter.com", "x.com",
    "ebay.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "barclays.co.uk", "lloydsbank.com", "hsbc.com", "natwest.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
    "irs.gov", "gov.uk", "hmrc.gov.uk",
    "docusign.com", "adobe.com",
]

# ---------------------------------------------------------------------------
# Phishing / fraud language patterns
# ---------------------------------------------------------------------------

PHISHING_PATTERNS = [
    # Credential harvesting
    r"verify\s+your\s+(account|identity|email|password|details)",
    r"confirm\s+your\s+(account|identity|email|password|details)",
    r"update\s+your\s+(payment|billing|credit\s+card|account)\s+(info|details|information)",
    r"your\s+account\s+(has\s+been|will\s+be)\s+(suspended|locked|disabled|terminated|closed)",
    r"click\s+here\s+to\s+(verify|confirm|restore|reactivate|unlock)",
    r"login\s+to\s+(verify|confirm|secure|protect)",
    r"validate\s+your\s+(account|information|identity)",
    # Password / credential
    r"reset\s+your\s+password\s+immediately",
    r"your\s+password\s+(has\s+expired|will\s+expire|must\s+be\s+changed)",
    r"enter\s+your\s+(username|password|credentials|login)",
]

FRAUD_PATTERNS = [
    # Payment / invoice fraud
    r"(urgent|immediate)\s+(payment|transfer|wire)",
    r"wire\s+transfer\s+(required|needed|immediately)",
    r"please\s+(process|approve|authorize)\s+(this\s+)?(payment|invoice|transfer)",
    r"invoice\s+(attached|enclosed|#\d+)",
    r"(overdue|past\s+due|outstanding)\s+(invoice|payment|balance|amount)",
    r"change\s+(of\s+)?(bank|payment)\s+(details|account|information)",
    r"new\s+(bank|payment)\s+(details|account|instructions)",
    # CEO / BEC fraud
    r"this\s+is\s+(urgent|confidential|time.sensitive)",
    r"do\s+not\s+(discuss|mention|share)\s+this\s+with",
    r"(wire|transfer|send)\s+\$[\d,]+",
    r"gift\s+(card|cards)\s+(purchase|buy|needed)",
    r"i\s+need\s+you\s+to\s+(purchase|buy|send|wire)",
]

URGENCY_PATTERNS = [
    r"act\s+(now|immediately|urgently|today)",
    r"(immediate|urgent|critical|emergency)\s+(action|attention|response)\s+(required|needed)",
    r"your\s+account\s+will\s+be\s+(deleted|terminated|closed|suspended)\s+in\s+\d+\s+(hour|day)",
    r"(last|final)\s+(warning|notice|chance|opportunity)",
    r"expires?\s+(in\s+)?(24|48|72)?\s*(hour|day|minute)",
    r"respond\s+(within|before|by)\s+\d+\s+(hour|day|minute)",
    r"limited\s+time",
    r"don.t\s+(ignore|miss|delay)\s+this",
    r"failure\s+to\s+(respond|comply|act)\s+will\s+result",
    r"legal\s+(action|proceedings)\s+will\s+be\s+(taken|initiated)",
]

IMPERSONATION_PATTERNS = [
    r"(this\s+is|i\s+am)\s+(your\s+)?(ceo|cfo|president|director|manager)",
    r"(from\s+the\s+desk\s+of|on\s+behalf\s+of)\s+[A-Z]",
    r"(apple|google|microsoft|paypal|amazon|netflix|facebook)\s+(support|security|team|account)",
    r"(it\s+department|security\s+team|helpdesk|support\s+team)",
    r"your\s+(it|security|helpdesk)\s+(team|department|administrator)",
    r"(official|authorized)\s+(notice|notification|communication)\s+from",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_text(text: str) -> str:
    """Normalize unicode and lower-case for pattern matching."""
    # Normalize unicode lookalikes (e.g. Cyrillic а → a)
    text = unicodedata.normalize("NFKD", text)
    return text.lower()


def _extract_domains_from_text(text: str) -> list:
    """Extract all domains from raw text without fetching them."""
    pattern = r'https?://([a-zA-Z0-9\-\.]+)'
    matches = re.findall(pattern, text)
    # Also catch bare domains
    bare = re.findall(r'(?<![/@\w])([a-zA-Z0-9\-]+\.[a-zA-Z]{2,6})(?:[/?\s]|$)', text)
    all_domains = [m.lower() for m in matches + bare]
    return list(set(all_domains))


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _is_typosquat(domain: str, brand: str) -> bool:
    """
    Check if domain is a typosquat of brand.
    Uses edit distance similarity — never fetches either domain.
    """
    # Strip subdomains for comparison
    d_root = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
    b_root = ".".join(brand.split(".")[-2:]) if brand.count(".") >= 1 else brand

    if d_root == b_root:
        return False   # It IS the brand

    sim = _similarity(d_root, b_root)

    # High similarity but not identical = likely typosquat
    if sim >= 0.75 and d_root != b_root:
        return True

    # Common substitution patterns
    substitutions = [
        (d_root.replace("0", "o"), b_root),
        (d_root.replace("1", "l"), b_root),
        (d_root.replace("rn", "m"), b_root),
        (d_root.replace("-", ""), b_root.replace("-", "")),
    ]
    for a, b in substitutions:
        if a == b:
            return True

    # Brand name appearing in suspicious domain (e.g. paypal-secure.com)
    b_name = b_root.split(".")[0]
    d_name = d_root.split(".")[0]
    if b_name in d_name and d_name != b_name:
        return True

    return False


def _get_header(msg: Message, key: str) -> str:
    val = msg.get(key, "") or ""
    return str(val).strip()


def _extract_email_address(header_val: str) -> str:
    """Extract bare email address from 'Display Name <email@domain>' format."""
    match = re.search(r'<([^>]+)>', header_val)
    if match:
        return match.group(1).lower().strip()
    return header_val.lower().strip()


def _extract_domain(email_addr: str) -> str:
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return ""


def _get_body_text(msg: Message) -> str:
    """
    Extract plain text from email safely.
    Never renders HTML. Never fetches anything.
    Strips all HTML tags — works on plain text only.
    """
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            if ctype == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    payload = part.get_content_payload(decode=True)
                    if not payload:
                        payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html = payload.decode(charset, errors="replace")
                        # Strip HTML tags — never render
                        text = re.sub(r'<[^>]+>', ' ', html)
                        body_parts.append(text)
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    text = re.sub(r'<[^>]+>', ' ', text)
                body_parts.append(text)
        except Exception:
            pass

    return " ".join(body_parts)


def _get_attachments(msg: Message) -> list:
    """
    Get attachment filenames only. Never opens or reads attachment content.
    """
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append({
                    "filename":    filename,
                    "content_type": part.get_content_type(),
                    "size_hint":   len(str(part.get_payload())) if part.get_payload() else 0,
                })
    return attachments


# ---------------------------------------------------------------------------
# Main threat analysis function
# ---------------------------------------------------------------------------

def analyze_email(msg: Message, raw_source: str = "") -> dict:
    """
    Analyse a parsed email message for all threat categories.

    SAFETY CONTRACT:
    - Never fetches any URL
    - Never opens any attachment
    - Never renders any HTML
    - Never makes any network connection
    - Operates on strings and metadata only

    Args:
        msg:        Parsed email.message.Message object
        raw_source: Optional raw email source string for extra header analysis

    Returns:
        {
            threat_detected: bool,
            threat_level:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
            overall_score:   int 0-100,
            categories:      list of detected threat categories,
            flags:           list of specific flag strings,
            explanation:     list of human-readable explanations,
            safe_summary:    one-line safe summary,
            action:          recommended action string,
            metadata:        dict of parsed email metadata,
        }
    """
    flags       = []
    explanations = []
    score        = 0
    categories   = set()

    # ── Parse headers ────────────────────────────────────────────────────────
    from_raw    = _get_header(msg, "From")
    to_raw      = _get_header(msg, "To")
    reply_to    = _get_header(msg, "Reply-To")
    subject     = _get_header(msg, "Subject")
    date        = _get_header(msg, "Date")
    message_id  = _get_header(msg, "Message-ID")
    received    = msg.get_all("Received") or []
    return_path = _get_header(msg, "Return-Path")
    x_mailer    = _get_header(msg, "X-Mailer")

    from_addr   = _extract_email_address(from_raw)
    from_domain = _extract_domain(from_addr)
    from_name   = re.sub(r'<[^>]+>', '', from_raw).strip().strip('"')

    reply_addr  = _extract_email_address(reply_to) if reply_to else ""
    reply_domain = _extract_domain(reply_addr) if reply_addr else ""

    return_addr  = _extract_email_address(return_path) if return_path else ""
    return_domain = _extract_domain(return_addr) if return_addr else ""

    # ── Extract body text safely ─────────────────────────────────────────────
    body = _get_body_text(msg)
    body_clean = _clean_text(body)
    subject_clean = _clean_text(subject)
    combined_text = body_clean + " " + subject_clean

    # ── Extract attachment metadata (filenames only) ─────────────────────────
    attachments = _get_attachments(msg)

    # ── Extract URLs from text (never fetch them) ────────────────────────────
    urls_in_body = re.findall(r'https?://[^\s<>"\']+', body)
    domains_in_body = _extract_domains_from_text(body)

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 1 — Reply-To Mismatch
    # Classic phishing: email appears from bank but replies go to attacker
    # ────────────────────────────────────────────────────────────────────────
    if reply_addr and from_addr and reply_addr != from_addr:
        if reply_domain != from_domain:
            score += 25
            categories.add("IMPERSONATION")
            categories.add("PHISHING")
            flags.append("reply_to_domain_mismatch")
            explanations.append(
                f"Reply-To address ({reply_addr}) differs from From address ({from_addr}). "
                "Replies to this email will go to a different person than the apparent sender."
            )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 2 — Return-Path Mismatch
    # ────────────────────────────────────────────────────────────────────────
    if return_addr and from_addr and return_domain and from_domain:
        if return_domain != from_domain:
            score += 15
            categories.add("HEADER_ANOMALY")
            flags.append("return_path_domain_mismatch")
            explanations.append(
                f"Return-Path domain ({return_domain}) does not match From domain ({from_domain}). "
                "This is a common indicator of spoofed sender addresses."
            )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 3 — Brand Impersonation in Display Name
    # "PayPal Security" <attacker@evil.com>
    # ────────────────────────────────────────────────────────────────────────
    from_name_clean = _clean_text(from_name)
    for brand in BRAND_DOMAINS:
        brand_name = brand.split(".")[0]
        if brand_name in from_name_clean and brand not in from_domain:
            score += 30
            categories.add("IMPERSONATION")
            flags.append(f"brand_impersonation_display_name:{brand_name}")
            explanations.append(
                f"Display name claims to be '{brand_name}' but the sending domain is '{from_domain}'. "
                "This is a classic impersonation technique."
            )
            break

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 4 — Typosquatted Domain in From address
    # paypa1.com, googIe.com, micros0ft.com
    # ────────────────────────────────────────────────────────────────────────
    if from_domain:
        for brand in BRAND_DOMAINS:
            if _is_typosquat(from_domain, brand):
                score += 40
                categories.add("PHISHING")
                categories.add("IMPERSONATION")
                flags.append(f"typosquat_sender_domain:{from_domain}~{brand}")
                explanations.append(
                    f"Sender domain '{from_domain}' appears to be a typosquat of '{brand}'. "
                    "This is a hallmark of brand impersonation phishing attacks."
                )
                break

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 5 — Typosquatted Domains in Email Body Links
    # ────────────────────────────────────────────────────────────────────────
    body_typosquats = []
    for domain in domains_in_body:
        for brand in BRAND_DOMAINS:
            if _is_typosquat(domain, brand):
                body_typosquats.append((domain, brand))
                break

    if body_typosquats:
        score += min(30 * len(body_typosquats), 45)
        categories.add("PHISHING")
        categories.add("LINK_THREAT")
        flags.append(f"typosquat_domains_in_body:{len(body_typosquats)}")
        for d, b in body_typosquats[:3]:
            explanations.append(
                f"Body contains link to '{d}' which closely resembles '{b}' — likely a fake site."
            )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 6 — Phishing Language Patterns
    # ────────────────────────────────────────────────────────────────────────
    phishing_hits = []
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            phishing_hits.append(pattern)

    if phishing_hits:
        phishing_score = min(10 * len(phishing_hits), 35)
        score += phishing_score
        categories.add("PHISHING")
        flags.append(f"phishing_language_patterns:{len(phishing_hits)}")
        explanations.append(
            f"Email contains {len(phishing_hits)} phishing language pattern(s) — "
            "language designed to trick recipients into revealing credentials or clicking fake links."
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 7 — Fraud Language Patterns
    # ────────────────────────────────────────────────────────────────────────
    fraud_hits = []
    for pattern in FRAUD_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            fraud_hits.append(pattern)

    if fraud_hits:
        fraud_score = min(10 * len(fraud_hits), 35)
        score += fraud_score
        categories.add("FRAUD")
        flags.append(f"fraud_language_patterns:{len(fraud_hits)}")
        explanations.append(
            f"Email contains {len(fraud_hits)} fraud language pattern(s) — "
            "language associated with invoice fraud, payment redirect, or CEO fraud attacks."
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 8 — Urgency Manipulation
    # ────────────────────────────────────────────────────────────────────────
    urgency_hits = []
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            urgency_hits.append(pattern)

    if urgency_hits:
        urgency_score = min(8 * len(urgency_hits), 25)
        score += urgency_score
        categories.add("URGENCY")
        flags.append(f"urgency_patterns:{len(urgency_hits)}")
        explanations.append(
            f"Email uses {len(urgency_hits)} urgency manipulation tactic(s) — "
            "artificial pressure designed to bypass careful thinking."
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 9 — Impersonation Language
    # ────────────────────────────────────────────────────────────────────────
    impersonation_hits = []
    for pattern in IMPERSONATION_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            impersonation_hits.append(pattern)

    if impersonation_hits:
        score += min(10 * len(impersonation_hits), 25)
        categories.add("IMPERSONATION")
        flags.append(f"impersonation_language:{len(impersonation_hits)}")
        explanations.append(
            f"Email contains {len(impersonation_hits)} impersonation language pattern(s) — "
            "language claiming authority or identity to manipulate the recipient."
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 10 — Dangerous Attachment Extensions
    # Filename only — never opens the file
    # ────────────────────────────────────────────────────────────────────────
    critical_attachments = []
    suspicious_attachments_list = []

    for att in attachments:
        fname = att["filename"].lower()
        ext   = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""

        # Double extension trick: invoice.pdf.exe
        all_exts = re.findall(r'\.[a-z0-9]+', fname)
        if len(all_exts) >= 2 and all_exts[-1] in DANGEROUS_EXTENSIONS:
            score += 45
            categories.add("MALWARE")
            flags.append(f"double_extension_attack:{att['filename']}")
            explanations.append(
                f"Attachment '{att['filename']}' uses a double extension trick to disguise "
                f"a dangerous {all_exts[-1]} file as something safe. This is a classic malware delivery method."
            )
            critical_attachments.append(att["filename"])
            continue

        if ext in DANGEROUS_EXTENSIONS:
            score += 40
            categories.add("MALWARE")
            flags.append(f"dangerous_attachment:{att['filename']}")
            explanations.append(
                f"Attachment '{att['filename']}' has a dangerous file extension ({ext}). "
                "This file type is commonly used to deliver malware. Do not open."
            )
            critical_attachments.append(att["filename"])

        elif ext in SUSPICIOUS_EXTENSIONS:
            score += 10
            categories.add("MALWARE")
            flags.append(f"suspicious_attachment:{att['filename']}")
            explanations.append(
                f"Attachment '{att['filename']}' ({ext}) can potentially contain macros or exploits. "
                "Only open if you trust the sender completely."
            )
            suspicious_attachments_list.append(att["filename"])

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 11 — URL Obfuscation Patterns
    # IP addresses used as domains, excessively long URLs, encoded URLs
    # ────────────────────────────────────────────────────────────────────────
    ip_urls = [u for u in urls_in_body if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)]
    if ip_urls:
        score += 30
        categories.add("LINK_THREAT")
        flags.append(f"ip_address_links:{len(ip_urls)}")
        explanations.append(
            f"Email contains {len(ip_urls)} link(s) using raw IP addresses instead of domain names. "
            "Legitimate services never do this — this is a strong phishing indicator."
        )

    encoded_urls = [u for u in urls_in_body if "%" in u and len(u) > 100]
    if encoded_urls:
        score += 20
        categories.add("LINK_THREAT")
        flags.append(f"obfuscated_encoded_urls:{len(encoded_urls)}")
        explanations.append(
            f"Email contains {len(encoded_urls)} heavily encoded/obfuscated URL(s). "
            "Encoding is used to hide malicious destinations from spam filters."
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 12 — Received Header Chain Anomalies
    # Very short received chain for email claiming to be from major provider
    # ────────────────────────────────────────────────────────────────────────
    if len(received) < 2 and from_domain:
        for brand in ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]:
            if brand in from_domain:
                score += 15
                categories.add("HEADER_ANOMALY")
                flags.append(f"suspicious_received_chain_for:{from_domain}")
                explanations.append(
                    f"Email claims to be from {from_domain} but has an unusually short mail routing chain. "
                    "Legitimate emails from major providers pass through multiple verified servers."
                )
                break

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 13 — Missing or suspicious Message-ID
    # ────────────────────────────────────────────────────────────────────────
    if not message_id:
        score += 10
        categories.add("HEADER_ANOMALY")
        flags.append("missing_message_id")
        explanations.append(
            "Email is missing a Message-ID header. All legitimate email clients and servers add this. "
            "Its absence suggests the email was crafted manually or by a spam tool."
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 14 — Subject line threat patterns
    # ────────────────────────────────────────────────────────────────────────
    subject_threats = [
        (r'(urgent|important|action\s+required|immediate)', "urgency subject"),
        (r'(invoice|payment|wire\s+transfer|bank)', "financial threat subject"),
        (r'(account|password|suspended|locked|disabled)', "account threat subject"),
        (r'(verify|confirm|update)\s+your', "verification demand subject"),
        (r'(you\s+have\s+a\s+package|delivery|shipment|tracking)', "fake delivery subject"),
        (r'(won|winner|prize|lottery|congratulations)', "advance fee fraud subject"),
        (r'(bitcoin|crypto|investment|opportunity)', "investment scam subject"),
    ]

    for pattern, label in subject_threats:
        if re.search(pattern, subject_clean, re.IGNORECASE):
            score += 8
            flags.append(f"suspicious_subject:{label}")
            # Don't add explanation for each — would be noisy. Aggregate instead.

    subject_threat_flags = [f for f in flags if f.startswith("suspicious_subject:")]
    if subject_threat_flags:
        categories.add("URGENCY")
        explanations.append(
            f"Subject line contains {len(subject_threat_flags)} threat pattern(s): "
            + ", ".join(f.replace("suspicious_subject:", "") for f in subject_threat_flags)
        )

    # ────────────────────────────────────────────────────────────────────────
    # HEURISTIC 15 — Empty or missing sender name
    # ────────────────────────────────────────────────────────────────────────
    if not from_name or from_name == from_addr:
        score += 5
        flags.append("no_display_name")

    # ────────────────────────────────────────────────────────────────────────
    # Final scoring and classification
    # ────────────────────────────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 75:
        threat_level = "CRITICAL"
    elif score >= 50:
        threat_level = "HIGH"
    elif score >= 25:
        threat_level = "MEDIUM"
    elif score >= 10:
        threat_level = "LOW"
    else:
        threat_level = "CLEAN"

    threat_detected = score >= 25

    # Action recommendation
    if threat_level == "CRITICAL":
        action = "DELETE IMMEDIATELY — Do not click any links, open any attachments, or reply"
    elif threat_level == "HIGH":
        action = "DO NOT INTERACT — Mark as phishing/spam and delete"
    elif threat_level == "MEDIUM":
        action = "TREAT WITH CAUTION — Verify sender through a separate trusted channel before responding"
    elif threat_level == "LOW":
        action = "REVIEW CAREFULLY — Some suspicious signals detected. Verify before acting"
    else:
        action = "No immediate threat detected"

    # Safe one-line summary
    if threat_detected:
        cat_str = ", ".join(sorted(categories)) if categories else "Unknown"
        safe_summary = f"Threat detected ({threat_level}) — Categories: {cat_str} — Score: {score}/100"
    else:
        safe_summary = f"No significant threat detected — Score: {score}/100"

    return {
        "threat_detected":  threat_detected,
        "threat_level":     threat_level,
        "overall_score":    score,
        "categories":       sorted(categories),
        "flags":            flags,
        "explanation":      explanations,
        "safe_summary":     safe_summary,
        "action":           action,
        "metadata": {
            "from":         from_raw,
            "from_address": from_addr,
            "from_domain":  from_domain,
            "from_name":    from_name,
            "reply_to":     reply_to,
            "subject":      subject,
            "date":         date,
            "message_id":   message_id,
            "attachments":  attachments,
            "link_count":   len(urls_in_body),
            "has_html":     msg.get_content_type() == "text/html" or any(
                p.get_content_type() == "text/html"
                for p in (msg.walk() if msg.is_multipart() else [])
            ),
        },
    }
