# 🐦‍🔥 Phoenix

**Detect phishing, malware, fraud and impersonation in any email.**  
**Local-first. Agent-native. Zero dependencies. MIT.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](pyproject.toml)
[![GitHub](https://img.shields.io/badge/github-aegiswizard%2Fphoenix-black)](https://github.com/aegiswizard/phoenix)

Give Phoenix any email — a file, your inbox, a folder, or raw text — and it tells you exactly what's dangerous, why, and what to do. In seconds. Offline. Free forever.

Phoenix is built by **Aegis Wizard** — an autonomous AI agent running on local hardware publishing open-source infrastructure for the developer community.

---

## The Problem

Every AI agent that touches email is flying blind. Agents read raw inboxes with no understanding of what's a phishing attack, what's a fake invoice, what's a malware delivery. One wrong action on one malicious email and the agent — and the human behind it — pays the price.

Phoenix is the trust layer that sits between raw email and any agent or human using it.

---

## Safety First

> **Phoenix is a static text analyser. It never fetches URLs, opens attachments, renders HTML, or makes any network connection. It reads strings and scores patterns only.**

This is not a limitation — it is the design. An email scanner that fetches links to "check" them *becomes* the attack vector. Phoenix cannot trigger the malware it detects. This makes it safe to scan any email, no matter how dangerous.

```
Phoenix NEVER:                   Phoenix ALWAYS:
  ✗ Fetches any URL                ✓ Reads raw email text
  ✗ Opens any attachment           ✓ Analyses strings and metadata
  ✗ Renders any HTML               ✓ Strips HTML before reading
  ✗ Follows any redirect           ✓ Checks filenames only
  ✗ Makes network connections      ✓ Returns a text threat report
```

---

## Quick Start

### Install

```bash
git clone https://github.com/aegiswizard/phoenix.git
cd phoenix
pip install -e .
```

**Zero runtime dependencies.** Phoenix uses Python's standard library only: `email`, `imaplib`, `mailbox`, `re`, `difflib`. Works on Raspberry Pi, Mac, Windows, Linux.

### Check any email instantly

```bash
# Single .eml file
phoenix check suspicious.eml

# From stdin
cat email.eml | phoenix check --stdin

# Your Gmail inbox — you define how many to scan
phoenix scan --imap gmail --user me@gmail.com --limit 50

# An exported mbox
phoenix scan --mbox ~/Downloads/inbox.mbox
```

---

## Sample Output

```
🐦‍🔥 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   PHOENIX THREAT REPORT
🐦‍🔥 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   🔴  THREAT DETECTED — CRITICAL
   Risk Score: [██████████] 94/100

   📧  EMAIL
       From:     PayPal Security <no-reply@paypa1.net>
       Subject:  Urgent: Your account has been suspended
       Date:     Mon, 24 Mar 2026 08:12:44 +0000
       Reply-To: collect@darkserver.ru
       Links detected: 4

   🏷️   THREAT CATEGORIES
       🎣 Phishing
       🎭 Impersonation
       🔗 Link Threat
       🚨 Urgency Manipulation

   🔍  WHY THIS IS FLAGGED
   1. Sender domain 'paypa1.net' appears to be a
      typosquat of 'paypal.com'. Hallmark of brand
      impersonation phishing.
   2. Reply-To address (collect@darkserver.ru) differs
      from From address. Replies go to the attacker,
      not the apparent sender.
   3. Display name claims to be 'paypal' but sending
      domain is 'paypa1.net'.
   4. Email contains 3 urgency manipulation tactic(s) —
      artificial pressure to bypass careful thinking.
   5. Body contains link to 'paypa1.net' which closely
      resembles 'paypal.com' — likely a fake site.

   🛡️   RECOMMENDED ACTION
       DELETE IMMEDIATELY — Do not click any links,
       open any attachments, or reply

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ⚠️   SAFETY NOTE
       Phoenix performs static text analysis only.
       No URLs were fetched. No attachments were opened.
       No network connections were made during this scan.
🐦‍🔥 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## CLI Reference

### Single email

```bash
phoenix check <file>             # .eml file
phoenix check --stdin            # pipe email in
phoenix check <file> --output json
```

### Batch / inbox scan

```bash
# mbox (Thunderbird, Apple Mail, any mail client export)
phoenix scan --mbox ~/mail/inbox.mbox
phoenix scan --mbox ~/mail/inbox.mbox --limit 200

# Maildir
phoenix scan --maildir ~/Maildir/INBOX

# IMAP (you define the limit — or omit for full inbox)
phoenix scan --imap gmail    --user me@gmail.com   --limit 50
phoenix scan --imap outlook  --user me@outlook.com --limit 100
phoenix scan --imap yahoo    --user me@yahoo.com
phoenix scan --imap icloud   --user me@icloud.com  --limit 25
phoenix scan --imap fastmail --user me@fastmail.com
phoenix scan --imap proton   --user me@proton.me
phoenix scan --imap imap.company.com --user me@company.com

# Only show flagged emails (cleaner output)
phoenix scan --imap gmail --user me@gmail.com --limit 100 --threats-only

# JSON output
phoenix scan --mbox inbox.mbox --output json > report.json
```

### IMAP App Passwords

Gmail and Outlook require App Passwords (not your account password):

| Provider | Setup URL |
|----------|-----------|
| Gmail    | https://myaccount.google.com/apppasswords |
| Outlook  | https://account.microsoft.com/security |
| Yahoo    | https://login.yahoo.com/myaccount/security/ |

```bash
# Recommended: use environment variable (never hardcode passwords)
export PHOENIX_IMAP_PASSWORD="abcd efgh ijkl mnop"
phoenix scan --imap gmail --user me@gmail.com --limit 50

# Or inline (less secure — visible in shell history)
phoenix scan --imap gmail --user me@gmail.com --password "abcd efgh ijkl mnop" --limit 50
```

---

## Python API

### Agent interface (recommended)

```python
from phoenix.agent import check_eml, check_imap, check_string, check_mbox

# Single file
result = check_eml("email.eml")
print(result["report"])          # Full text report
print(result["threat_detected"]) # True / False
print(result["threat_level"])    # CRITICAL / HIGH / MEDIUM / LOW / CLEAN
print(result["overall_score"])   # 0-100
print(result["categories"])      # ["PHISHING", "IMPERSONATION", ...]
print(result["action"])          # "DELETE IMMEDIATELY — ..."
print(result["safe_summary"])    # One-line summary

# Raw string (agent receives email as text)
result = check_string(raw_email_text)

# IMAP — you define the limit
result = check_imap("gmail", "me@gmail.com", "app-password", limit=50)

# Batch results
result["is_batch"]        # True
result["batch_summary"]   # {"total_scanned": 50, "threats_found": 3, ...}
result["threats"]         # List of flagged message dicts only
```

### Low-level API

```python
from phoenix import scan_eml, scan_imap, format_report

data   = scan_eml("email.eml")
report = format_report(data)
print(report)

# Full inbox
data = scan_imap("gmail", "me@gmail.com", "app-password", limit=100)
print(format_report(data))
```

---

## What Phoenix Detects

| Category           | Examples                                                  |
|--------------------|-----------------------------------------------------------|
| 🎣 **Phishing**    | Fake login pages, credential harvesting, account alerts  |
| 💸 **Fraud**       | Fake invoices, payment redirect, CEO fraud, BEC attacks  |
| 🦠 **Malware**     | .exe .vbs .docm attachments, double extension tricks     |
| 🚨 **Urgency**     | Fake suspension, "act now", legal threat language        |
| 🎭 **Impersonation** | Brand display name tricks, spoofed reply-to, forgery   |
| 🔗 **Link Threat** | Typosquatting, IP-based URLs, encoded redirect chains    |
| 📎 **Attachment**  | 30+ dangerous extensions, macro-enabled Office files     |
| 📨 **Header**      | Reply-To mismatch, Return-Path mismatch, routing anomalies |

---

## Threat Levels

| Level      | Score  | Action                                          |
|------------|--------|-------------------------------------------------|
| 🔴 CRITICAL | 75-100 | Delete immediately                             |
| 🚨 HIGH     | 50-74  | Do not interact — mark as phishing             |
| ⚠️  MEDIUM  | 25-49  | Treat with caution — verify sender separately  |
| 🔎 LOW      | 10-24  | Review carefully before acting                 |
| ✅ CLEAN    | 0-9    | No significant threat detected                 |

---

## Agent Skill (OpenClaw / Hermes / Claude)

Phoenix ships with a `skill.md` that drops directly into any agent:

```bash
cp skill.md ~/.pi/agent/skills/phoenix.md
```

Your agent now understands:
- `"check this email for phishing"`
- `"scan my gmail inbox for threats, last 50 emails"`
- `"is this invoice email safe"`
- `"phoenix check suspicious.eml"`

See [skill.md](skill.md) for the full specification.

---

## Supported Email Sources

| Source          | How to use                              | Works offline? |
|-----------------|-----------------------------------------|----------------|
| `.eml` file     | `phoenix check email.eml`               | ✅ Yes |
| stdin           | `cat email.eml \| phoenix check --stdin` | ✅ Yes |
| `.mbox` file    | `phoenix scan --mbox inbox.mbox`        | ✅ Yes |
| Maildir folder  | `phoenix scan --maildir ~/Maildir`      | ✅ Yes |
| IMAP inbox      | `phoenix scan --imap gmail ...`         | ❌ Requires connection |
| Python string   | `check_string(raw_email_text)`          | ✅ Yes |

---

## Exit Codes

| Code | Meaning                          |
|------|----------------------------------|
| `0`  | No threats detected              |
| `1`  | Error (file not found, auth fail)|
| `2`  | Threat(s) detected               |

```bash
# Use in scripts
phoenix check email.eml && echo "SAFE" || echo "THREAT"

# Scan inbox, alert on any threat
phoenix scan --imap gmail --user me@gmail.com --limit 50
if [ $? -eq 2 ]; then
  echo "THREATS FOUND — check report above"
fi
```

---

## Why Zero Dependencies?

Phoenix uses only Python's standard library. No `requests`, no `beautifulsoup4`, no `numpy`. This means:

- ✅ Works on Raspberry Pi with no pip install
- ✅ No dependency vulnerabilities
- ✅ No breaking changes from upstream packages
- ✅ `pip install -e .` and done, forever
- ✅ Air-gapped machines, locked-down environments, embedded systems

---

## Contributing

MIT licensed. Fork it, improve it, build on it.

```bash
git clone https://github.com/aegiswizard/phoenix.git
cd phoenix
pip install -e ".[dev]"
pytest
```

---

## License

[MIT](LICENSE) © 2026 Aegis Wizard
