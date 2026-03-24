"""
Phoenix 🐦‍🔥 — Email Parsers
Safely parse emails from every source.
All parsers are READ-ONLY. Nothing is executed, fetched, or opened.

Supported sources:
  - .eml file
  - .mbox file
  - Maildir directory
  - IMAP server (via app password)
  - stdin / raw string
"""

import email
import imaplib
import mailbox
import os
import sys
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Generator, Optional


# ---------------------------------------------------------------------------
# Shared email parser
# ---------------------------------------------------------------------------

def _parse_raw(raw: bytes | str) -> Message:
    """Parse raw email bytes or string into a Message object safely."""
    if isinstance(raw, bytes):
        return email.message_from_bytes(raw)
    return email.message_from_string(raw)


# ---------------------------------------------------------------------------
# .eml file
# ---------------------------------------------------------------------------

def parse_eml(path: str) -> tuple:
    """
    Parse a single .eml file.
    Returns (message, raw_source_string).
    Never executes or renders any content.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not p.is_file():
        raise ValueError(f"Not a file: {path}")

    raw = p.read_bytes()
    msg = _parse_raw(raw)
    return msg, raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# stdin / raw string
# ---------------------------------------------------------------------------

def parse_stdin() -> tuple:
    """
    Read raw email from stdin.
    Usage: cat email.eml | phoenix check --stdin
    """
    raw = sys.stdin.buffer.read()
    msg = _parse_raw(raw)
    return msg, raw.decode("utf-8", errors="replace")


def parse_string(raw: str) -> tuple:
    """Parse email from a raw string (for agent/API use)."""
    msg = _parse_raw(raw)
    return msg, raw


# ---------------------------------------------------------------------------
# .mbox file
# ---------------------------------------------------------------------------

def iter_mbox(path: str, limit: Optional[int] = None) -> Generator:
    """
    Iterate over messages in an mbox file.
    Yields (message, raw_source) tuples.
    Never executes or renders any content.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"mbox file not found: {path}")

    mbox = mailbox.mbox(str(p))
    count = 0

    try:
        for key in mbox.keys():
            if limit and count >= limit:
                break
            msg = mbox[key]
            raw = msg.as_string()
            yield msg, raw
            count += 1
    finally:
        mbox.close()


# ---------------------------------------------------------------------------
# Maildir directory
# ---------------------------------------------------------------------------

def iter_maildir(path: str, limit: Optional[int] = None) -> Generator:
    """
    Iterate over messages in a Maildir directory.
    Yields (message, raw_source) tuples.
    Never executes or renders any content.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Maildir not found: {path}")
    if not p.is_dir():
        raise ValueError(f"Not a directory: {path}")

    mdir = mailbox.Maildir(str(p), factory=None)
    count = 0

    try:
        for key in mdir.keys():
            if limit and count >= limit:
                break
            msg = mdir[key]
            raw = msg.as_string()
            yield msg, raw
            count += 1
    finally:
        mdir.close()


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------

class IMAPConnection:
    """
    Safe IMAP connection wrapper.
    Fetches email headers and body text only.
    Never fetches URLs, opens attachments, or executes content.
    Uses app passwords — does not support or store OAuth tokens.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 993,
        use_ssl: bool = True,
        folder: str = "INBOX",
    ):
        self.host     = host
        self.username = username
        self.password = password
        self.port     = port
        self.use_ssl  = use_ssl
        self.folder   = folder
        self._conn    = None

    def connect(self) -> None:
        try:
            if self.use_ssl:
                self._conn = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self._conn = imaplib.IMAP4(self.host, self.port)
            self._conn.login(self.username, self.password)
        except imaplib.IMAP4.error as e:
            raise ConnectionError(
                f"IMAP login failed for {self.username}@{self.host}: {e}\n\n"
                "For Gmail: use an App Password, not your account password.\n"
                "Generate one at: https://myaccount.google.com/apppasswords\n\n"
                "For Outlook: use an App Password from:\n"
                "https://account.microsoft.com/security"
            ) from e

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def get_message_ids(self, limit: Optional[int] = None) -> list:
        """Get list of message IDs, newest first."""
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")

        status, data = self._conn.select(f'"{self.folder}"', readonly=True)
        if status != "OK":
            raise RuntimeError(f"Cannot select folder '{self.folder}': {data}")

        status, data = self._conn.search(None, "ALL")
        if status != "OK":
            raise RuntimeError("Cannot search inbox")

        ids = data[0].split()
        ids = list(reversed(ids))   # Newest first

        if limit:
            ids = ids[:limit]

        return ids

    def fetch_message(self, msg_id: bytes) -> tuple:
        """
        Fetch a single message by ID.
        Returns (message, raw_source).
        Fetches RFC822 (full message) safely.
        """
        if not self._conn:
            raise RuntimeError("Not connected.")

        status, data = self._conn.fetch(msg_id, "(RFC822)")
        if status != "OK" or not data or data[0] is None:
            return None, None

        raw = data[0][1]
        if not isinstance(raw, bytes):
            return None, None

        msg = _parse_raw(raw)
        return msg, raw.decode("utf-8", errors="replace")

    def iter_messages(self, limit: Optional[int] = None) -> Generator:
        """
        Iterate over inbox messages safely.
        Yields (message, raw_source) tuples.
        """
        ids = self.get_message_ids(limit=limit)
        for msg_id in ids:
            msg, raw = self.fetch_message(msg_id)
            if msg is not None:
                yield msg, raw

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()


# ---------------------------------------------------------------------------
# IMAP host presets
# ---------------------------------------------------------------------------

IMAP_PRESETS = {
    "gmail":    {"host": "imap.gmail.com",   "port": 993},
    "outlook":  {"host": "outlook.office365.com", "port": 993},
    "yahoo":    {"host": "imap.mail.yahoo.com", "port": 993},
    "hotmail":  {"host": "outlook.office365.com", "port": 993},
    "icloud":   {"host": "imap.mail.me.com", "port": 993},
    "fastmail": {"host": "imap.fastmail.com", "port": 993},
    "proton":   {"host": "imap.protonmail.ch", "port": 993},
    "zoho":     {"host": "imap.zoho.com",    "port": 993},
}


def resolve_imap_host(provider_or_host: str) -> tuple:
    """
    Resolve a provider shorthand or custom host to (host, port).
    e.g. "gmail" → ("imap.gmail.com", 993)
         "imap.mycompany.com" → ("imap.mycompany.com", 993)
    """
    key = provider_or_host.lower().strip()
    if key in IMAP_PRESETS:
        p = IMAP_PRESETS[key]
        return p["host"], p["port"]
    return provider_or_host, 993
