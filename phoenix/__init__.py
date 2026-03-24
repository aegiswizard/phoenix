"""
Phoenix 🐦‍🔥 — Email Threat Detector
MIT License | github.com/aegiswizard/phoenix

Detect phishing, malware, fraud and impersonation in any email.
Works on any email source. Pure static analysis. Zero network calls.

Quick start:
    from phoenix.agent import check_eml
    result = check_eml("suspicious.eml")
    print(result["report"])
"""

__version__ = "1.0.0"
__author__  = "Aegis Wizard"
__license__ = "MIT"
__url__     = "https://github.com/aegiswizard/phoenix"

from .scanner import scan_eml, scan_string, scan_mbox, scan_maildir, scan_imap
from .report  import format_report

__all__ = [
    "scan_eml",
    "scan_string",
    "scan_mbox",
    "scan_maildir",
    "scan_imap",
    "format_report",
]
