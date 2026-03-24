"""
Phoenix 🐦‍🔥 — Command-Line Interface
Usage: phoenix check [source] [options]
"""

import argparse
import os
import sys

BANNER = """
  🐦‍🔥  Phoenix — Email Threat Detector  v1.0.0
      github.com/aegiswizard/phoenix  ·  MIT License
      Static analysis only. No URLs fetched. No attachments opened.
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phoenix",
        description="🐦‍🔥 Phoenix — Detect phishing, malware, fraud and impersonation in any email",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
sources:
  phoenix check email.eml                          Single .eml file
  cat email.eml | phoenix check --stdin            From stdin
  phoenix scan --mbox ~/mail/inbox.mbox            Entire mbox file
  phoenix scan --maildir ~/Maildir/INBOX           Maildir folder
  phoenix scan --imap gmail --user x@gmail.com     Gmail inbox
  phoenix scan --imap outlook --user x@outlook.com Outlook inbox
  phoenix scan --imap imap.company.com --user x@co Custom IMAP host

imap provider shorthands:
  gmail | outlook | yahoo | icloud | fastmail | proton | zoho

examples:
  phoenix check suspicious.eml
  phoenix check suspicious.eml --output json
  phoenix scan --imap gmail --user me@gmail.com --password "abcd efgh ijkl mnop" --limit 100
  phoenix scan --mbox ~/Maildir/inbox.mbox --limit 500
  cat raw_email.txt | phoenix check --stdin

app password setup (required for Gmail/Outlook):
  Gmail:   https://myaccount.google.com/apppasswords
  Outlook: https://account.microsoft.com/security
  Yahoo:   https://login.yahoo.com/myaccount/security/
        """,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # ── check (single email) ────────────────────────────────────────────────
    check_p = subparsers.add_parser(
        "check",
        help="Check a single email file or stdin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check_source = check_p.add_mutually_exclusive_group()
    check_source.add_argument("file", nargs="?", help=".eml file path")
    check_source.add_argument("--stdin", action="store_true", help="Read from stdin")
    check_p.add_argument("--output", "-o", choices=["text", "json"], default="text")
    check_p.add_argument("--quiet", "-q", action="store_true")

    # ── scan (batch / inbox) ────────────────────────────────────────────────
    scan_p = subparsers.add_parser(
        "scan",
        help="Scan multiple emails from mbox, maildir, or IMAP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_source = scan_p.add_mutually_exclusive_group(required=True)
    scan_source.add_argument("--mbox",    metavar="PATH",     help="Path to .mbox file")
    scan_source.add_argument("--maildir", metavar="PATH",     help="Path to Maildir directory")
    scan_source.add_argument("--imap",    metavar="PROVIDER", help="IMAP provider or hostname")

    scan_p.add_argument("--user",     "-u", metavar="EMAIL",    help="Email address (IMAP)")
    scan_p.add_argument("--password", "-p", metavar="PASSWORD", help="App password (IMAP). Use env var PHOENIX_IMAP_PASSWORD for security.")
    scan_p.add_argument("--folder",         metavar="FOLDER",   default="INBOX", help="IMAP folder (default: INBOX)")
    scan_p.add_argument("--limit",    "-n", metavar="N",        type=int,        help="Max emails to scan (default: all)")
    scan_p.add_argument("--output",   "-o", choices=["text", "json"], default="text")
    scan_p.add_argument("--quiet",    "-q", action="store_true")
    scan_p.add_argument("--threats-only", action="store_true", help="Only show emails where threats were detected")

    # ── version ─────────────────────────────────────────────────────────────
    subparsers.add_parser("version", help="Print version and exit")

    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print("phoenix 1.0.0")
        sys.exit(0)

    # ────────────────────────────────────────────────────────────────────────
    # CHECK — single email
    # ────────────────────────────────────────────────────────────────────────
    if args.command == "check":
        from phoenix.scanner import scan_eml, scan_stdin
        from phoenix.report import format_report

        def progress(msg: str) -> None:
            if not args.quiet and args.output == "text":
                print(f"  ⏳ {msg}", file=sys.stderr)

        print(BANNER, file=sys.stderr)

        try:
            if args.stdin:
                progress("Reading from stdin...")
                data = scan_stdin(progress=progress)
            elif args.file:
                progress(f"Checking: {args.file}")
                data = scan_eml(args.file, progress=progress)
            else:
                print("  ❌  Provide a .eml file or use --stdin\n", file=sys.stderr)
                check_p.print_help()
                sys.exit(1)
        except FileNotFoundError as e:
            print(f"\n  ❌  {e}\n", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"\n  ❌  {e}\n", file=sys.stderr)
            sys.exit(1)

        print(format_report(data, fmt=args.output))

        # Exit code: 2 = threat detected, 0 = clean (useful for scripting)
        sys.exit(2 if data.get("threat_detected") else 0)

    # ────────────────────────────────────────────────────────────────────────
    # SCAN — batch
    # ────────────────────────────────────────────────────────────────────────
    if args.command == "scan":
        from phoenix.scanner import scan_mbox, scan_maildir, scan_imap
        from phoenix.report import format_report, format_batch_report

        def progress(msg: str) -> None:
            if not args.quiet and args.output == "text":
                print(f"  ⏳ {msg}", file=sys.stderr)

        print(BANNER, file=sys.stderr)

        try:
            if args.mbox:
                progress(f"Scanning mbox: {args.mbox}")
                data = scan_mbox(args.mbox, limit=args.limit, progress=progress)

            elif args.maildir:
                progress(f"Scanning Maildir: {args.maildir}")
                data = scan_maildir(args.maildir, limit=args.limit, progress=progress)

            elif args.imap:
                if not args.user:
                    print("  ❌  --user is required for IMAP scanning\n", file=sys.stderr)
                    sys.exit(1)

                # Get password from env or arg (env preferred for security)
                password = (
                    os.environ.get("PHOENIX_IMAP_PASSWORD")
                    or args.password
                )
                if not password:
                    print(
                        "\n  ❌  No IMAP password provided.\n\n"
                        "     Option 1 (secure):  export PHOENIX_IMAP_PASSWORD='your app password'\n"
                        "     Option 2 (inline):  --password 'your app password'\n\n"
                        "     For Gmail/Outlook you MUST use an App Password:\n"
                        "     Gmail:   https://myaccount.google.com/apppasswords\n"
                        "     Outlook: https://account.microsoft.com/security\n",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                limit_display = str(args.limit) if args.limit else "all"
                progress(f"Scanning IMAP ({args.imap}) as {args.user} — {limit_display} email(s)")
                data = scan_imap(
                    host_or_provider=args.imap,
                    username=args.user,
                    password=password,
                    folder=args.folder,
                    limit=args.limit,
                    progress=progress,
                )

        except ConnectionError as e:
            print(f"\n  ❌  {e}\n", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError as e:
            print(f"\n  ❌  {e}\n", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\n  Scan interrupted.\n", file=sys.stderr)
            sys.exit(0)
        except Exception as e:
            print(f"\n  ❌  {e}\n", file=sys.stderr)
            sys.exit(1)

        # Filter to threats-only if requested
        if getattr(args, "threats_only", False) and data.get("batch"):
            data["all_results"] = data.get("threat_messages", [])

        print(format_report(data, fmt=args.output))

        threats = data.get("summary", {}).get("threats_found", 0)
        sys.exit(2 if threats > 0 else 0)


if __name__ == "__main__":
    main()
