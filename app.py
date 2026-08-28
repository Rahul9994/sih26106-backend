"""
app.py
SIH26106 — AI-Powered Email Threat Detection + Geolocation + Forensic
Intelligence System. Flask backend: parses an email, runs heuristic +
AI (Groq/OpenRouter) analysis, geolocates the sending IP(s), and
returns one combined forensic report + risk percentage.

Now also includes Gmail IMAP live-scan endpoints.
"""
import os
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from analyzer.email_parser import parse_raw_email, parse_quick_fields
from analyzer.heuristics import run_heuristics
from analyzer.geolocation import locate_all
from analyzer.ai_analysis import run_ai_analysis
from analyzer.risk_engine import build_report

load_dotenv()

app = Flask(__name__)

# ⚠️ EDIT THIS: the frontend now lives on a separate host (e.g. ProFreeHost).
# Set ALLOWED_ORIGIN as an env var on your backend host to that exact URL
# (e.g. "https://yoursite.profreehost.com") to lock CORS down. Falls back
# to "*" (any origin) if unset, which is fine for testing but not ideal
# once you have a real domain.
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "*")
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGIN}})


@app.get("/")
def index():
    return jsonify({"status": "backend is running", "note": "frontend is hosted separately"})


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "groq_configured": bool(os.getenv("GROQ_API_KEY", "").strip()),
        "openrouter_configured": bool(os.getenv("OPENROUTER_API_KEY", "").strip()),
        "org": os.getenv("CASE_ORG_NAME", "SIH26106 Email Threat Intelligence Unit"),
    })


@app.post("/api/analyze")
def analyze():
    """
    Accepts JSON body in one of two shapes:

    1) Raw mode  — {"mode": "raw", "raw_email": "<full .eml source text>"}
    2) Quick mode — {"mode": "quick", "from": "...", "subject": "...",
                     "body": "...", "headers_raw": "<optional extra headers>"}
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        mode = payload.get("mode", "quick")

        if mode == "raw":
            raw_email = (payload.get("raw_email") or "").strip()
            if not raw_email:
                return jsonify({"error": "raw_email is required in raw mode"}), 400
            parsed = parse_raw_email(raw_email)
        else:
            from_addr = payload.get("from", "")
            subject = payload.get("subject", "")
            body = payload.get("body", "")
            headers_raw = payload.get("headers_raw", "")
            if not (from_addr or subject or body):
                return jsonify({"error": "provide at least one of from/subject/body"}), 400
            parsed = parse_quick_fields(from_addr, subject, body, headers_raw)

        heuristics = run_heuristics(parsed)
        geolocations = locate_all(parsed.get("hop_ips") or [])
        ai_result = run_ai_analysis(parsed, heuristics)
        report = build_report(parsed, heuristics, ai_result, geolocations)

        return jsonify(report)

    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"analysis failed: {exc}"}), 500


@app.post("/api/geolocate")
def geolocate_only():
    """Standalone lookup for a single IP — used by the UI's quick IP-check widget."""
    payload = request.get_json(force=True, silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    return jsonify(locate_all([ip])[0])


# ══════════════════════════════════════════════════════════════════
#  GMAIL LIVE SCAN ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/api/gmail/fetch")
def gmail_fetch():
    """
    Authenticate with Gmail via IMAP App Password and return inbox previews.

    Body: {
        "email":        "user@gmail.com",
        "app_password": "xxxx xxxx xxxx xxxx",
        "count":        20          (optional, default 20, max 50)
    }

    Returns: { "messages": [ { uid, from, subject, date, snippet, has_attachments }, ... ] }

    SECURITY: credentials are used only for this request and never stored.
    """
    try:
        from gmail_client import fetch_inbox_previews

        payload  = request.get_json(force=True, silent=True) or {}
        gmail    = (payload.get("email") or "").strip()
        app_pwd  = (payload.get("app_password") or "").strip().replace(" ", "")
        count    = int(payload.get("count", 20))
        offset   = int(payload.get("offset", 0))

        if not gmail or not app_pwd:
            return jsonify({"error": "email and app_password are required"}), 400

        result = fetch_inbox_previews(gmail, app_pwd, count, offset)
        return jsonify({
            "messages":    result["messages"],
            "total":       result["total"],
            "has_more":    result["has_more"],
            "page_count":  len(result["messages"]),
            "offset":      offset,
        })

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 401
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"Gmail fetch failed: {exc}"}), 500


@app.post("/api/gmail/scan")
def gmail_scan():
    """
    Fetch a single full Gmail message by UID and run the full forensic pipeline.

    Body: {
        "email":        "user@gmail.com",
        "app_password": "xxxxxxxxxxxxxxxx",
        "uid":          "42"
    }

    Returns the same forensic report JSON as /api/analyze.

    SECURITY: credentials are used only for this request and never stored.
    """
    try:
        from gmail_client import fetch_full_message

        payload  = request.get_json(force=True, silent=True) or {}
        gmail    = (payload.get("email") or "").strip()
        app_pwd  = (payload.get("app_password") or "").strip().replace(" ", "")
        uid      = str(payload.get("uid") or "").strip()

        if not gmail or not app_pwd or not uid:
            return jsonify({"error": "email, app_password, and uid are required"}), 400

        full_msg = fetch_full_message(gmail, app_pwd, uid)

        # Run through the same analysis pipeline as /api/analyze (quick mode)
        parsed = parse_quick_fields(
            from_addr   = full_msg.get("from", ""),
            subject     = full_msg.get("subject", ""),
            body        = full_msg.get("body", ""),
            headers_raw = full_msg.get("headers_raw", ""),
        )

        # Inject attachment list from IMAP parse if heuristics need it
        if full_msg.get("attachments"):
            parsed.setdefault("attachments", full_msg["attachments"])

        heuristics   = run_heuristics(parsed)
        geolocations = locate_all(parsed.get("hop_ips") or [])
        ai_result    = run_ai_analysis(parsed, heuristics)
        report       = build_report(parsed, heuristics, ai_result, geolocations)

        # Attach original Gmail metadata
        report["gmail_meta"] = {
            "uid":     uid,
            "from":    full_msg.get("from", ""),
            "subject": full_msg.get("subject", ""),
            "date":    full_msg.get("date", ""),
        }

        return jsonify(report)

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 401
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"Gmail scan failed: {exc}"}), 500



@app.post("/api/gmail/send_alert")
def gmail_send_alert():
    """
    Send a threat alert email containing the forensic JSON report
    to the logged-in user's Gmail address when risk_score >= 40%.

    Body: {
        "email":        "user@gmail.com",
        "app_password": "xxxxxxxxxxxxxxxx",
        "uid":          "42",
        "score":        73,
        "report":       { ...full forensic report dict... }
    }
    """
    import smtplib
    import json as json_lib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.application import MIMEApplication

    try:
        payload      = request.get_json(force=True, silent=True) or {}
        gmail        = (payload.get("email") or "").strip()
        app_pwd      = (payload.get("app_password") or "").strip().replace(" ", "")
        uid          = str(payload.get("uid") or "").strip()
        score        = int(payload.get("score") or 0)
        report       = payload.get("report") or {}

        if not gmail or not app_pwd:
            return jsonify({"error": "email and app_password are required"}), 400

        subject_email = report.get("gmail_meta", {}).get("subject", f"UID {uid}")
        sender_from   = report.get("sender", {}).get("from", "—")
        verdict       = (report.get("verdict") or "—").upper()
        case_id       = report.get("case_id", f"GMAIL-{uid}")

        # ── Build email ──
        msg = MIMEMultipart("mixed")
        msg["From"]    = gmail
        msg["To"]      = gmail
        msg["Subject"] = f"🚨 THREAT ALERT [{score}%] — {subject_email[:60]}"

        body_text = f"""SIH26106 · Email Threat Intelligence — AUTOMATED ALERT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CASE ID   : {case_id}
MESSAGE UID: {uid}
RISK SCORE : {score}%
VERDICT    : {verdict}
FROM       : {sender_from}
SUBJECT    : {subject_email}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This email was automatically sent because the scanned message
exceeded the 40% threat threshold.

The full forensic JSON report is attached.

AI REASONING:
{report.get('ai_analysis', {}).get('reasoning') or '—'}

RECOMMENDED ACTION:
{report.get('ai_analysis', {}).get('recommended_action') or report.get('ai_analysis', {}).get('action') or '—'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIH26106 · AI-Powered Email Threat Intelligence System
"""
        msg.attach(MIMEText(body_text, "plain", "utf-8"))

        # Attach full JSON report
        json_bytes = json_lib.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
        attachment = MIMEApplication(json_bytes, Name=f"forensic_report_{uid}.json")
        attachment["Content-Disposition"] = f'attachment; filename="forensic_report_{uid}.json"'
        msg.attach(attachment)

        # ── Send via Gmail SMTP ──
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail, app_pwd)
            server.sendmail(gmail, gmail, msg.as_string())

        return jsonify({"status": "sent", "to": gmail})

    except smtplib.SMTPAuthenticationError:
        return jsonify({"error": "SMTP authentication failed — check App Password"}), 401
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"Send alert failed: {exc}"}), 500


if __name__ == "__main__":
    # Render (and most hosts) inject PORT automatically; FLASK_PORT is a local fallback.
    port = int(os.getenv("PORT", os.getenv("FLASK_PORT", "5000")))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    print(f"\n  SIH26106 Threat Detection backend running -> http://0.0.0.0:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
