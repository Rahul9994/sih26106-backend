"""
email_parser.py
Parses a raw email (.eml text, or pasted raw source) into a structured
dict: headers, authentication results, body text, URLs, attachments,
and the list of hop IP addresses pulled from Received headers.
"""
import re
import email
from email import policy
from email.parser import Parser as EmailParser

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)

# Private / reserved ranges we skip when looking for a "real" sender IP
PRIVATE_PREFIXES = ("10.", "127.", "169.254.", "192.168.", "0.")
PRIVATE_172_RANGE = range(16, 32)

SUSPICIOUS_ATTACHMENT_EXT = (
    ".exe", ".scr", ".vbs", ".js", ".jar", ".bat", ".cmd", ".msi",
    ".com", ".pif", ".hta", ".ps1",
)

URGENCY_KEYWORDS = [
    "verify your account", "account suspended", "act now", "urgent action",
    "click here immediately", "confirm your identity", "password expired",
    "unusual sign-in", "wire transfer", "gift card", "bitcoin", "crypto payment",
    "limited time", "your account will be closed", "final notice", "invoice attached",
    "update your payment", "security alert", "unauthorized login", "reset your password",
]


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if second in PRIVATE_172_RANGE:
                return True
        except (IndexError, ValueError):
            pass
    return False


def _extract_hop_ips(received_headers):
    """Pull every public IPv4 found across Received headers, in order
    (oldest hop first — the last Received header is usually the origin)."""
    ips = []
    for header in reversed(received_headers):
        for ip in IPV4_RE.findall(header):
            if not _is_private_ip(ip) and ip not in ips:
                ips.append(ip)
    return ips


def _get_auth_results(msg):
    """Best-effort SPF/DKIM/DMARC verdicts from Authentication-Results
    and Received-SPF headers. Returns PASS/FAIL/NONE/UNKNOWN per check."""
    auth_blobs = " ".join(msg.get_all("Authentication-Results", []) or [])
    auth_blobs += " " + " ".join(msg.get_all("Received-SPF", []) or [])
    auth_blobs = auth_blobs.lower()

    def verdict(tag):
        m = re.search(rf"{tag}\s*=\s*([a-z]+)", auth_blobs)
        if not m:
            return "unknown"
        val = m.group(1)
        if val in ("pass",):
            return "pass"
        if val in ("fail", "softfail", "permerror", "temperror"):
            return "fail"
        if val in ("none", "neutral"):
            return "none"
        return "unknown"

    return {
        "spf": verdict("spf"),
        "dkim": verdict("dkim"),
        "dmarc": verdict("dmarc"),
    }


def _body_text(msg):
    """Walk the MIME tree and grab the best plain-text (or stripped HTML) body."""
    if msg.is_multipart():
        plain, html = None, None
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and plain is None:
                plain = payload
            elif ctype == "text/html" and html is None:
                html = payload
        if plain:
            return plain
        if html:
            return re.sub(r"<[^>]+>", " ", html)
        return ""
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            payload = payload.decode(errors="ignore") if isinstance(payload, bytes) else str(payload)
        if msg.get_content_type() == "text/html":
            return re.sub(r"<[^>]+>", " ", payload)
        return payload


def _attachments(msg):
    found = []
    if not msg.is_multipart():
        return found
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unnamed"
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            found.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "suspicious_extension": ext in SUSPICIOUS_ATTACHMENT_EXT,
            })
    return found


def parse_raw_email(raw_text: str) -> dict:
    """Main entry point. Accepts full raw email source (headers + body,
    as you'd get from 'view source' / a .eml file) and returns a
    structured dict for the heuristic and AI engines to consume."""
    raw_text = raw_text.replace("\r\n", "\n")
    msg = EmailParser(policy=policy.default).parsestr(raw_text)

    from_addr = msg.get("From", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    return_path = msg.get("Return-Path", "") or ""
    subject = msg.get("Subject", "") or ""
    date = msg.get("Date", "") or ""
    message_id = msg.get("Message-ID", "") or ""

    received_headers = msg.get_all("Received", []) or []
    hop_ips = _extract_hop_ips([str(h) for h in received_headers])

    body = _body_text(msg) or ""
    urls = list(dict.fromkeys(URL_RE.findall(body)))  # de-dupe, keep order
    attachments = _attachments(msg)
    auth = _get_auth_results(msg)

    def domain_of(addr):
        m = re.search(r"@([\w.-]+)", addr)
        return m.group(1).lower() if m else ""

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_to)
    return_domain = domain_of(return_path)

    return {
        "from": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_domain,
        "return_path": return_path,
        "return_path_domain": return_domain,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "auth": auth,
        "hop_ips": hop_ips,
        "origin_ip": hop_ips[0] if hop_ips else None,
        "body": body.strip(),
        "urls": urls,
        "attachments": attachments,
        "header_count": len(msg.items()),
    }


def parse_quick_fields(from_addr: str, subject: str, body: str, headers_raw: str = "") -> dict:
    """Lightweight path for the 'quick demo' UI mode where the user
    types From/Subject/Body directly instead of pasting a raw .eml.
    Still runs URL/IP extraction and, if raw headers were pasted too,
    reuses the full parser for auth + hop IPs."""
    base = {
        "from": from_addr,
        "from_domain": re.search(r"@([\w.-]+)", from_addr or "").group(1).lower() if from_addr and "@" in from_addr else "",
        "reply_to": "",
        "reply_to_domain": "",
        "return_path": "",
        "return_path_domain": "",
        "subject": subject,
        "date": "",
        "message_id": "",
        "auth": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        "hop_ips": [],
        "origin_ip": None,
        "body": body or "",
        "urls": list(dict.fromkeys(URL_RE.findall(body or ""))),
        "attachments": [],
        "header_count": 0,
    }
    if headers_raw and headers_raw.strip():
        try:
            fake_msg = f"{headers_raw}\n\n{body or ''}"
            full = parse_raw_email(fake_msg)
            base["auth"] = full["auth"]
            base["hop_ips"] = full["hop_ips"]
            base["origin_ip"] = full["origin_ip"]
            if full["from"]:
                base["from"] = full["from"]
                base["from_domain"] = full["from_domain"]
            base["reply_to_domain"] = full["reply_to_domain"]
            base["return_path_domain"] = full["return_path_domain"]
        except Exception:
            pass
    return base
