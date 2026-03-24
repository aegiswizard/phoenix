"""
Phoenix 🐦‍🔥 — Scanner
Orchestrates email source parsing and threat analysis.
"""

from datetime import datetime, timezone
from typing import Optional, Callable

from .heuristics import analyze_email
from .parsers import (
    parse_eml, parse_stdin, parse_string,
    iter_mbox, iter_maildir,
    IMAPConnection, resolve_imap_host,
)


# ---------------------------------------------------------------------------
# Single email scan
# ---------------------------------------------------------------------------

def scan_eml(path: str, progress: Optional[Callable] = None) -> dict:
    """Scan a single .eml file."""
    log = progress or (lambda _: None)
    log(f"Parsing email file: {path}")
    msg, raw = parse_eml(path)
    log("Analysing for threats...")
    result = analyze_email(msg, raw)
    return _wrap_single(result, source="eml", source_ref=path)


def scan_stdin(progress: Optional[Callable] = None) -> dict:
    """Scan email piped via stdin."""
    log = progress or (lambda _: None)
    log("Reading email from stdin...")
    msg, raw = parse_stdin()
    log("Analysing for threats...")
    result = analyze_email(msg, raw)
    return _wrap_single(result, source="stdin", source_ref="<stdin>")


def scan_string(raw: str, progress: Optional[Callable] = None) -> dict:
    """Scan email from a raw string (agent/API use)."""
    log = progress or (lambda _: None)
    log("Parsing email string...")
    msg, raw_str = parse_string(raw)
    log("Analysing for threats...")
    result = analyze_email(msg, raw_str)
    return _wrap_single(result, source="string", source_ref="<string>")


# ---------------------------------------------------------------------------
# Multi-email scan
# ---------------------------------------------------------------------------

def scan_mbox(
    path: str,
    limit: Optional[int] = None,
    progress: Optional[Callable] = None,
) -> dict:
    """Scan all (or N) emails in an mbox file."""
    log = progress or (lambda _: None)
    log(f"Opening mbox: {path}")
    results = []
    count = 0
    for msg, raw in iter_mbox(path, limit=limit):
        count += 1
        log(f"Analysing message {count}...")
        result = analyze_email(msg, raw)
        results.append(_wrap_single(result, source="mbox", source_ref=f"{path}:{count}"))
    return _wrap_batch(results, source="mbox", source_ref=path)


def scan_maildir(
    path: str,
    limit: Optional[int] = None,
    progress: Optional[Callable] = None,
) -> dict:
    """Scan all (or N) emails in a Maildir directory."""
    log = progress or (lambda _: None)
    log(f"Opening Maildir: {path}")
    results = []
    count = 0
    for msg, raw in iter_maildir(path, limit=limit):
        count += 1
        log(f"Analysing message {count}...")
        result = analyze_email(msg, raw)
        results.append(_wrap_single(result, source="maildir", source_ref=f"{path}:{count}"))
    return _wrap_batch(results, source="maildir", source_ref=path)


def scan_imap(
    host_or_provider: str,
    username: str,
    password: str,
    folder: str = "INBOX",
    limit: Optional[int] = None,
    progress: Optional[Callable] = None,
) -> dict:
    """Scan emails from an IMAP server."""
    log = progress or (lambda _: None)
    host, port = resolve_imap_host(host_or_provider)
    log(f"Connecting to {host}:{port} as {username}...")

    results = []
    count = 0

    with IMAPConnection(host=host, username=username, password=password, port=port, folder=folder) as conn:
        ids = conn.get_message_ids(limit=limit)
        total = len(ids)
        log(f"Found {total} message(s) to analyse.")

        for msg_id in ids:
            count += 1
            msg, raw = conn.fetch_message(msg_id)
            if msg is None:
                continue
            subject = msg.get("Subject", "<no subject>")[:60]
            log(f"[{count}/{total}] {subject}")
            result = analyze_email(msg, raw)
            results.append(_wrap_single(
                result,
                source="imap",
                source_ref=f"{username}@{host}/{folder}:{msg_id.decode()}"
            ))

    return _wrap_batch(results, source="imap", source_ref=f"{username}@{host}/{folder}")


# ---------------------------------------------------------------------------
# Wrappers
# ---------------------------------------------------------------------------

def _wrap_single(result: dict, source: str, source_ref: str) -> dict:
    """Wrap a single heuristics result with source metadata."""
    return {
        "source":      source,
        "source_ref":  source_ref,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),
        **result,
    }


def _wrap_batch(results: list, source: str, source_ref: str) -> dict:
    """Aggregate multiple scan results into a batch report."""
    total        = len(results)
    threats      = [r for r in results if r["threat_detected"]]
    clean        = [r for r in results if not r["threat_detected"]]
    critical     = [r for r in threats if r["threat_level"] == "CRITICAL"]
    high         = [r for r in threats if r["threat_level"] == "HIGH"]
    medium       = [r for r in threats if r["threat_level"] == "MEDIUM"]
    low          = [r for r in threats if r["threat_level"] == "LOW"]

    # Category frequency
    all_categories = []
    for r in threats:
        all_categories.extend(r.get("categories", []))
    from collections import Counter
    category_counts = dict(Counter(all_categories).most_common())

    return {
        "batch":       True,
        "source":      source,
        "source_ref":  source_ref,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_scanned":  total,
            "threats_found":  len(threats),
            "clean":          len(clean),
            "critical":       len(critical),
            "high":           len(high),
            "medium":         len(medium),
            "low":            len(low),
            "threat_rate_pct": round(len(threats) / total * 100, 1) if total > 0 else 0.0,
            "top_categories": category_counts,
        },
        "threat_messages": threats,
        "all_results":     results,
    }
