"""
Phoenix 🐦‍🔥 — Agent Interface
One clean function for any agent framework to call.
OpenClaw · Hermes · Claude · Any Python agent.

Usage:
    from phoenix.agent import check_eml, check_imap, check_string

    # Check a file
    result = check_eml("/path/to/email.eml")
    print(result["report"])
    print(result["threat_detected"])
    print(result["threat_level"])

    # Check IMAP inbox (user defines how many)
    result = check_imap("gmail", "you@gmail.com", "app-password", limit=50)
    print(result["report"])

    # Check raw string (pipe from any source)
    result = check_string(raw_email_text)
"""

import os
from typing import Optional, Callable

from .scanner import scan_eml, scan_stdin, scan_string, scan_mbox, scan_maildir, scan_imap
from .report import format_report, format_json


def _build_response(data: dict, fmt: str = "text") -> dict:
    """Standardise agent response structure."""
    is_batch = data.get("batch", False)

    base = {
        "report":          format_report(data, fmt="text"),
        "report_json":     data,
        "threat_detected": data.get("threat_detected", False) if not is_batch else data["summary"]["threats_found"] > 0,
        "threat_level":    data.get("threat_level", "CLEAN") if not is_batch else _batch_max_level(data),
        "overall_score":   data.get("overall_score", 0) if not is_batch else _batch_max_score(data),
        "categories":      data.get("categories", []) if not is_batch else list(data["summary"].get("top_categories", {}).keys()),
        "action":          data.get("action", "") if not is_batch else _batch_action(data),
        "safe_summary":    data.get("safe_summary", "") if not is_batch else _batch_summary(data),
        "is_batch":        is_batch,
    }

    if is_batch:
        base["batch_summary"] = data.get("summary", {})
        base["threats"]       = data.get("threat_messages", [])

    return base


def _batch_max_level(data: dict) -> str:
    s = data["summary"]
    if s.get("critical", 0): return "CRITICAL"
    if s.get("high", 0):     return "HIGH"
    if s.get("medium", 0):   return "MEDIUM"
    if s.get("low", 0):      return "LOW"
    return "CLEAN"


def _batch_max_score(data: dict) -> int:
    threats = data.get("threat_messages", [])
    if not threats:
        return 0
    return max(t.get("overall_score", 0) for t in threats)


def _batch_action(data: dict) -> str:
    level = _batch_max_level(data)
    n     = data["summary"]["threats_found"]
    if n == 0:
        return "No action required — inbox is clean"
    return f"Review {n} flagged message(s). Highest severity: {level}"


def _batch_summary(data: dict) -> str:
    s = data["summary"]
    return (
        f"Scanned {s['total_scanned']} emails. "
        f"{s['threats_found']} threat(s) found ({s['threat_rate_pct']}%). "
        f"Critical: {s['critical']}, High: {s['high']}, Medium: {s['medium']}."
    )


# ---------------------------------------------------------------------------
# Public agent functions
# ---------------------------------------------------------------------------

def check_eml(
    path: str,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Check a single .eml email file for threats.

    Args:
        path:              Path to .eml file
        progress_callback: Optional callable(str) for progress messages

    Returns dict with keys:
        report           (str)   Full text threat report
        report_json      (dict)  Structured data
        threat_detected  (bool)
        threat_level     (str)   CLEAN | LOW | MEDIUM | HIGH | CRITICAL
        overall_score    (int)   0-100
        categories       (list)  Detected threat categories
        action           (str)   Recommended action
        safe_summary     (str)   One-line summary
    """
    data = scan_eml(path, progress=progress_callback)
    return _build_response(data)


def check_string(
    raw_email: str,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Check a raw email string for threats.
    Useful for agents that receive email content as a string.
    """
    data = scan_string(raw_email, progress=progress_callback)
    return _build_response(data)


def check_stdin(
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Check email piped via stdin.
    Usage: cat email.eml | python -c "from phoenix.agent import check_stdin; ..."
    """
    data = scan_stdin(progress=progress_callback)
    return _build_response(data)


def check_mbox(
    path: str,
    limit: Optional[int] = None,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Check all (or N) emails in an mbox file.

    Args:
        path:   Path to .mbox file
        limit:  Max emails to scan (None = all)
    """
    data = scan_mbox(path, limit=limit, progress=progress_callback)
    return _build_response(data)


def check_maildir(
    path: str,
    limit: Optional[int] = None,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Check all (or N) emails in a Maildir directory.

    Args:
        path:   Path to Maildir directory
        limit:  Max emails to scan (None = all)
    """
    data = scan_maildir(path, limit=limit, progress=progress_callback)
    return _build_response(data)


def check_imap(
    host_or_provider: str,
    username: str,
    password: str,
    folder: str = "INBOX",
    limit: Optional[int] = None,
    progress_callback: Optional[Callable] = None,
) -> dict:
    """
    Check emails from an IMAP inbox.

    Args:
        host_or_provider: IMAP hostname or shorthand:
                          "gmail" | "outlook" | "yahoo" | "icloud" |
                          "fastmail" | "proton" | "zoho" |
                          or any IMAP hostname e.g. "mail.company.com"
        username:         Email address
        password:         App password (NOT your account password for Gmail/Outlook)
        folder:           Mailbox folder (default: INBOX)
        limit:            How many emails to scan (None = all — user defines this)

    IMPORTANT — App Passwords:
        Gmail:   https://myaccount.google.com/apppasswords
        Outlook: https://account.microsoft.com/security
        Yahoo:   https://login.yahoo.com/myaccount/security/
    """
    data = scan_imap(
        host_or_provider=host_or_provider,
        username=username,
        password=password,
        folder=folder,
        limit=limit,
        progress=progress_callback,
    )
    return _build_response(data)
