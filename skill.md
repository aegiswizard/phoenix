# 🐦‍🔥 Phoenix — Email Threat Detector Skill

**Version:** 1.0.0
**License:** MIT
**Source:** https://github.com/aegiswizard/phoenix
**Compatible with:** OpenClaw · Hermes · Claude agents · Any Python agent

---

## What This Skill Does

Phoenix detects phishing, malware, fraud, and impersonation in any email.
It works on .eml files, mbox exports, Maildir folders, stdin, and live IMAP inboxes.

**Safety architecture:** Phoenix is a static text analyser.
It NEVER fetches URLs, opens attachments, renders HTML, or makes network connections.
It reads strings and scores patterns only. Safe to run on any email, no matter how dangerous.

---

## Trigger Phrases

Your agent should invoke Phoenix when the user says:

- `"check this email for phishing"`
- `"scan my inbox for threats"`
- `"is this email safe"`
- `"check email.eml"`
- `"scan last 50 emails on gmail"`
- `"phoenix check [file or source]"`
- `"analyse this email"`
- `"is this invoice email legit"`
- `"check for malware in my inbox"`

---

## Setup (one-time, zero dependencies)

```bash
git clone https://github.com/aegiswizard/phoenix.git
cd phoenix
pip install -e .
# No other dependencies. Uses Python stdlib only.
```

---

## Usage — CLI

```bash
# Single .eml file
phoenix check suspicious.eml

# From stdin (pipe any email in)
cat email.eml | phoenix check --stdin

# JSON output
phoenix check email.eml --output json

# mbox file (Thunderbird, Apple Mail exports, etc.)
phoenix scan --mbox ~/mail/inbox.mbox

# Maildir folder
phoenix scan --maildir ~/Maildir/INBOX

# Gmail — user defines how many to scan
phoenix scan --imap gmail --user me@gmail.com --limit 50

# Outlook
phoenix scan --imap outlook --user me@outlook.com --limit 100

# Yahoo
phoenix scan --imap yahoo --user me@yahoo.com --limit 25

# Custom IMAP host
phoenix scan --imap imap.company.com --user me@company.com --limit 200

# All emails, no limit (user defines)
phoenix scan --imap gmail --user me@gmail.com

# Secure password via environment variable (recommended)
export PHOENIX_IMAP_PASSWORD="abcd efgh ijkl mnop"
phoenix scan --imap gmail --user me@gmail.com --limit 100

# Threats-only output (suppresses clean emails)
phoenix scan --imap gmail --user me@gmail.com --limit 100 --threats-only
```

---

## Usage — Python API (agent code)

```python
from phoenix.agent import check_eml, check_imap, check_string, check_mbox

# Single file
result = check_eml("email.eml")

# Raw string (agent receives email content as text)
result = check_string(raw_email_text)

# IMAP — user defines limit
result = check_imap("gmail", "me@gmail.com", "app-password", limit=50)
result = check_imap("outlook", "me@outlook.com", "app-password", limit=100)
result = check_imap("imap.company.com", "me@co.com", "password")  # no limit = all

# mbox
result = check_mbox("/path/to/inbox.mbox", limit=500)

# All available response keys:
result["report"]           # Full text report (like Fortune)
result["threat_detected"]  # bool
result["threat_level"]     # CLEAN | LOW | MEDIUM | HIGH | CRITICAL
result["overall_score"]    # 0-100
result["categories"]       # list of threat categories
result["action"]           # recommended action string
result["safe_summary"]     # one-line summary
result["report_json"]      # full structured dict
result["is_batch"]         # True for inbox/mbox/maildir scans

# Batch-only keys:
result["batch_summary"]    # totals by severity
result["threats"]          # list of flagged messages only
```

---

## Threat Categories

| Category           | What it catches                                       |
|--------------------|-------------------------------------------------------|
| `PHISHING`         | Credential harvesting, fake login pages               |
| `FRAUD`            | Fake invoices, payment redirect, CEO fraud            |
| `MALWARE`          | Dangerous attachments, macro lures, script drops      |
| `URGENCY`          | Fake suspension, deadline pressure, fear triggers     |
| `IMPERSONATION`    | Display name tricks, reply-to mismatch, brand spoofing|
| `LINK_THREAT`      | Typosquatting, IP-based URLs, obfuscated links        |
| `ATTACHMENT`       | Dangerous extensions, double extension attacks        |
| `HEADER_ANOMALY`   | SPF hints, DKIM hints, routing chain anomalies        |

---

## Threat Levels

| Level      | Score   | Meaning                                         |
|------------|---------|-------------------------------------------------|
| `CRITICAL` | 75-100  | Delete immediately. High-confidence attack.     |
| `HIGH`     | 50-74   | Do not interact. Strong threat signals.         |
| `MEDIUM`   | 25-49   | Treat with caution. Verify sender separately.   |
| `LOW`      | 10-24   | Some signals. Review before acting.             |
| `CLEAN`    | 0-9     | No significant threat detected.                 |

---

## Heuristics Applied (15 signals)

| # | Signal                                          |
|---|-------------------------------------------------|
| 1 | Reply-To domain differs from From domain        |
| 2 | Return-Path domain differs from From domain     |
| 3 | Brand name in display name, wrong domain        |
| 4 | Typosquatted sender domain                      |
| 5 | Typosquatted domains in email body links        |
| 6 | Phishing language patterns (9 patterns)         |
| 7 | Fraud language patterns (11 patterns)           |
| 8 | Urgency manipulation patterns (10 patterns)     |
| 9 | Impersonation language patterns (5 patterns)    |
| 10| Dangerous attachment file extensions            |
| 11| Double-extension attachment attacks             |
| 12| IP-address based links in body                  |
| 13| Heavily encoded/obfuscated URLs                 |
| 14| Suspicious mail routing chain                   |
| 15| Missing Message-ID header                       |

---

## IMAP Provider Shorthands

| Shorthand  | Host                          |
|------------|-------------------------------|
| `gmail`    | imap.gmail.com                |
| `outlook`  | outlook.office365.com         |
| `yahoo`    | imap.mail.yahoo.com           |
| `hotmail`  | outlook.office365.com         |
| `icloud`   | imap.mail.me.com              |
| `fastmail` | imap.fastmail.com             |
| `proton`   | imap.protonmail.ch            |
| `zoho`     | imap.zoho.com                 |

For any other provider, use the full IMAP hostname directly.

---

## App Password Setup (Required for Gmail/Outlook)

Gmail and Outlook require App Passwords — not your account password.

**Gmail:**
1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" and your device
3. Copy the 16-character password (includes spaces, that's fine)

**Outlook/Hotmail:**
1. Go to https://account.microsoft.com/security
2. Under "Advanced security options" → App passwords
3. Create and copy the password

**Environment variable (recommended — never hardcode passwords):**
```bash
export PHOENIX_IMAP_PASSWORD="abcd efgh ijkl mnop"
phoenix scan --imap gmail --user me@gmail.com --limit 50
```

---

## Exit Codes

| Code | Meaning                             |
|------|-------------------------------------|
| 0    | No threats detected                 |
| 1    | Error (connection failed, file not found, etc.) |
| 2    | Threat(s) detected                  |

Exit code 2 is useful for scripting:
```bash
phoenix check email.eml || echo "THREAT DETECTED"
```

---

## Safety Architecture

```
Phoenix NEVER:                   Phoenix ALWAYS:
  ✗ Fetches any URL                ✓ Reads raw email text
  ✗ Opens any attachment           ✓ Analyses strings and metadata
  ✗ Renders any HTML               ✓ Strips HTML tags before reading
  ✗ Follows any redirect           ✓ Extracts filenames only
  ✗ Makes network connections      ✓ Checks patterns in text
  ✗ Executes any content           ✓ Returns text report
```

This makes Phoenix safe to run on the most dangerous emails ever written.
The analysis cannot trigger the attack.

---

## Zero Dependencies

Phoenix uses Python standard library only:
`email` · `imaplib` · `mailbox` · `re` · `difflib` · `unicodedata` · `pathlib`

No pip installs required beyond `pip install -e .` for the package itself.
Works offline. Works on Raspberry Pi. Works everywhere Python runs.

---

## Disclaimer

Phoenix uses heuristics. False positives exist.
Always apply human judgement before deleting emails.
Phoenix is a detection aid, not a definitive verdict.
