"""
Phoenix 🐦‍🔥 — Report Formatter
Human-readable text reports and structured JSON output.
"""

import json
from typing import Union


DIVIDER = "━" * 56

THREAT_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🚨",
    "MEDIUM":   "⚠️ ",
    "LOW":      "🔎",
    "CLEAN":    "✅",
}

CATEGORY_LABELS = {
    "PHISHING":       "🎣 Phishing",
    "FRAUD":          "💸 Fraud",
    "MALWARE":        "🦠 Malware",
    "URGENCY":        "🚨 Urgency Manipulation",
    "IMPERSONATION":  "🎭 Impersonation",
    "LINK_THREAT":    "🔗 Link Threat",
    "ATTACHMENT":     "📎 Dangerous Attachment",
    "HEADER_ANOMALY": "📨 Header Anomaly",
}


def _score_bar(score: int, width: int = 10) -> str:
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


# ---------------------------------------------------------------------------
# Single email text report
# ---------------------------------------------------------------------------

def format_single_report(data: dict) -> str:
    level    = data.get("threat_level", "CLEAN")
    score    = data.get("overall_score", 0)
    icon     = THREAT_ICONS.get(level, "❓")
    meta     = data.get("metadata", {})
    cats     = data.get("categories", [])
    flags    = data.get("flags", [])
    expls    = data.get("explanation", [])
    action   = data.get("action", "")
    detected = data.get("threat_detected", False)

    lines = [
        "",
        f"🐦‍🔥 {DIVIDER}",
        f"   PHOENIX THREAT REPORT",
        f"🐦‍🔥 {DIVIDER}",
        "",
    ]

    # Verdict banner
    if detected:
        lines += [
            f"   {icon}  THREAT DETECTED — {level}",
            f"   Risk Score: [{_score_bar(score)}] {score}/100",
        ]
    else:
        lines += [
            f"   {icon}  CLEAN — No significant threat detected",
            f"   Risk Score: [{_score_bar(score)}] {score}/100",
        ]

    lines.append("")

    # Email metadata
    lines += [
        "   📧  EMAIL",
        f"       From:     {meta.get('from', '—')}",
        f"       Subject:  {meta.get('subject', '—')}",
        f"       Date:     {meta.get('date', '—')}",
    ]

    reply_to = meta.get("reply_to")
    if reply_to:
        lines.append(f"       Reply-To: {reply_to}")

    atts = meta.get("attachments", [])
    if atts:
        lines.append(f"       Attachments: {len(atts)} file(s)")
        for att in atts[:5]:
            lines.append(f"           📎 {att['filename']}")

    lines.append(f"       Links detected: {meta.get('link_count', 0)}")
    lines.append("")

    # Threat categories
    if cats:
        lines.append("   🏷️   THREAT CATEGORIES")
        for cat in cats:
            label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"       {label}")
        lines.append("")

    # Explanations
    if expls:
        lines.append("   🔍  WHY THIS IS FLAGGED")
        for i, expl in enumerate(expls, 1):
            # Word-wrap at 60 chars
            words = expl.split()
            line_acc = []
            wrapped = []
            for word in words:
                if len(" ".join(line_acc + [word])) > 60:
                    wrapped.append("       " + " ".join(line_acc))
                    line_acc = [word]
                else:
                    line_acc.append(word)
            if line_acc:
                wrapped.append("       " + " ".join(line_acc))

            lines.append(f"   {i}. {wrapped[0].strip()}")
            for wl in wrapped[1:]:
                lines.append(wl)
        lines.append("")

    # Action
    lines += [
        "   🛡️   RECOMMENDED ACTION",
        f"       {action}",
        "",
    ]

    # All flags (compact)
    if flags:
        lines.append("   🚩  TECHNICAL FLAGS")
        for flag in flags[:15]:
            lines.append(f"       · {flag}")
        if len(flags) > 15:
            lines.append(f"       … +{len(flags) - 15} more flags")
        lines.append("")

    lines += [
        f"   {DIVIDER}",
        "   ⚠️   SAFETY NOTE",
        "       Phoenix performs static text analysis only.",
        "       No URLs were fetched. No attachments were opened.",
        "       No network connections were made during this scan.",
        "",
        "   🛠️   Phoenix v1.0.0  ·  MIT License",
        "       https://github.com/aegiswizard/phoenix",
        "",
        f"🐦‍🔥 {DIVIDER}",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Batch scan text report
# ---------------------------------------------------------------------------

def format_batch_report(data: dict) -> str:
    summary = data.get("summary", {})
    threats = data.get("threat_messages", [])
    source  = data.get("source_ref", "")

    total    = summary.get("total_scanned", 0)
    n_threat = summary.get("threats_found", 0)
    n_clean  = summary.get("clean", 0)
    critical = summary.get("critical", 0)
    high     = summary.get("high", 0)
    medium   = summary.get("medium", 0)
    low_c    = summary.get("low", 0)
    rate     = summary.get("threat_rate_pct", 0)
    top_cats = summary.get("top_categories", {})

    lines = [
        "",
        f"🐦‍🔥 {DIVIDER}",
        f"   PHOENIX BATCH SCAN REPORT",
        f"🐦‍🔥 {DIVIDER}",
        "",
        f"   Source: {source}",
        f"   Scanned: {data.get('scanned_at', '')[:19].replace('T', ' ')} UTC",
        "",
        "   📊  SUMMARY",
        f"       Total scanned:    {total}",
        f"       Threats found:    {n_threat}  ({rate}%)",
        f"       Clean:            {n_clean}",
        "",
        "   🔴  BY SEVERITY",
        f"       Critical:  {critical}",
        f"       High:      {high}",
        f"       Medium:    {medium}",
        f"       Low:       {low_c}",
        "",
    ]

    if top_cats:
        lines.append("   🏷️   TOP THREAT CATEGORIES")
        for cat, count in list(top_cats.items())[:6]:
            label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"       {label}: {count}")
        lines.append("")

    if threats:
        lines.append(f"   ⚠️   FLAGGED MESSAGES  ({n_threat} threats)")
        lines.append("")
        for i, t in enumerate(threats, 1):
            level   = t.get("threat_level", "?")
            score   = t.get("overall_score", 0)
            icon    = THREAT_ICONS.get(level, "?")
            meta    = t.get("metadata", {})
            subject = meta.get("subject", "<no subject>")[:50]
            from_   = meta.get("from", "")[:45]
            cats    = ", ".join(t.get("categories", []))
            lines += [
                f"   ── {i}. {icon} {level} [{score}/100] ──────────────────────",
                f"       From:       {from_}",
                f"       Subject:    {subject}",
                f"       Categories: {cats}",
                f"       Action:     {t.get('action', '')}",
                "",
            ]
            if i >= 20 and len(threats) > 20:
                lines.append(f"   … and {len(threats) - 20} more threats. Use --output json for full list.")
                lines.append("")
                break
    else:
        lines += [
            "   ✅  No threats detected in this scan.",
            "",
        ]

    lines += [
        f"   {DIVIDER}",
        "   ⚠️   SAFETY NOTE",
        "       Phoenix performs static text analysis only.",
        "       No URLs were fetched. No attachments were opened.",
        "       No network connections were made during this scan.",
        "",
        "   🛠️   Phoenix v1.0.0  ·  MIT License",
        "       https://github.com/aegiswizard/phoenix",
        "",
        f"🐦‍🔥 {DIVIDER}",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON formatters
# ---------------------------------------------------------------------------

def format_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------------
# Smart dispatcher
# ---------------------------------------------------------------------------

def format_report(data: dict, fmt: str = "text") -> str:
    """Auto-detect single vs batch and format accordingly."""
    if fmt == "json":
        return format_json(data)

    if data.get("batch"):
        return format_batch_report(data)
    return format_single_report(data)
