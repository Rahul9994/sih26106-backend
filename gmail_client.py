"""
gmail_client.py
SIH26106 — Gmail IMAP integration via App Password.
Uses Python stdlib imaplib + email — no extra dependencies.

SECURITY NOTE: credentials are used only for the duration of this call
and are never stored server-side.
"""

import imaplib
import email as email_lib
import email.header
import email.utils
import ssl
import socket
from typing import Optional

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993


# ─────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────

def _decode_header_field(raw_val: Optional[str]) -> str:
    """Decode RFC-2047-encoded header value to a plain string."""
    if not raw_val:
        return ""
    parts = email.header.decode_header(raw_val)
    decoded = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            try:
                decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(chunk.decode("latin-1", errors="replace"))
        else:
            decoded.append(chunk)
    return "".join(decoded).strip()


def _get_body(msg: email_lib.message.Message) -> str:
    """Extract plain-text body from a Message, falling back to HTML→text."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = part.get("Content-Disposition", "")
            if ct == "text/plain" and "attachment" not in cd:
                try:
                    body = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                    break
                except Exception:
                    pass
        if not body:
            for part in msg.walk():
                ct = part.get_content_type()
                cd = part.get("Content-Disposition", "")
                if ct == "text/html" and "attachment" not in cd:
                    try:
                        import re
                        html = part.get_payload(decode=True).decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        )
                        body = re.sub(r"<[^>]+>", " ", html)
                        break
                    except Exception:
                        pass
    else:
        try:
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", errors="replace"
            )
        except Exception:
            body = ""
    return body.strip()


def _get_attachments(msg: email_lib.message.Message) -> list:
    """Collect attachment filenames from a message."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            cd = part.get("Content-Disposition", "")
            if "attachment" in cd:
                fname = _decode_header_field(part.get_filename())
                if fname:
                    attachments.append(fname)
    return attachments


def _message_to_preview(uid: str, msg: email_lib.message.Message) -> dict:
    """Produce a lightweight preview dict for the inbox list."""
    from_raw = _decode_header_field(msg.get("From", ""))
    subject  = _decode_header_field(msg.get("Subject", "(no subject)"))
    date_raw = msg.get("Date", "")
    body     = _get_body(msg)

    return {
        "uid":      uid,
        "from":     from_raw,
        "subject":  subject,
        "date":     date_raw,
        "snippet":  body[:200].replace("\n", " ").replace("\r", ""),
        "has_attachments": bool(_get_attachments(msg)),
    }


def _message_to_full(uid: str, msg: email_lib.message.Message) -> dict:
    """Produce the full parsed-email dict compatible with analyzer pipeline."""
    from_raw    = _decode_header_field(msg.get("From", ""))
    subject     = _decode_header_field(msg.get("Subject", ""))
    date_raw    = msg.get("Date", "")
    body        = _get_body(msg)
    attachments = _get_attachments(msg)

    # Reconstruct raw headers string for heuristics
    header_lines = []
    for key in msg.keys():
        val = msg.get(key, "")
        header_lines.append(f"{key}: {val}")
    headers_raw = "\n".join(header_lines)

    return {
        "uid":         uid,
        "from":        from_raw,
        "subject":     subject,
        "date":        date_raw,
        "body":        body,
        "headers_raw": headers_raw,
        "attachments": attachments,
    }


# ─────────────────────────────────────────────────────────
# public API
# ─────────────────────────────────────────────────────────

def connect(gmail_address: str, app_password: str) -> imaplib.IMAP4_SSL:
    """
    Open an authenticated IMAP SSL connection to Gmail.
    Raises ValueError with a human-readable message on failure.
    """
    try:
        ctx = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ctx)
    except (socket.gaierror, OSError) as e:
        raise ValueError(f"Cannot reach Gmail IMAP server: {e}")

    try:
        imap.login(gmail_address.strip(), app_password.strip())
    except imaplib.IMAP4.error as e:
        err = str(e).lower()
        if "invalid credentials" in err or "authentication failed" in err:
            raise ValueError(
                "Authentication failed. Make sure you are using a Google App Password "
                "(not your regular Gmail password). Generate one at: "
                "myaccount.google.com/apppasswords"
            )
        raise ValueError(f"IMAP login error: {e}")

    return imap


def fetch_inbox_previews(gmail_address: str, app_password: str, count: int = 20, offset: int = 0) -> dict:
    """
    Fetch `count` messages from INBOX starting at `offset` (newest-first).
    Returns a dict: { "messages": [...], "total": int, "has_more": bool }
    """
    count  = max(1, min(count, 50))   # cap at 50
    offset = max(0, offset)
    imap   = connect(gmail_address, app_password)
    try:
        imap.select("INBOX", readonly=True)
        status, data = imap.search(None, "ALL")
        if status != "OK":
            raise ValueError("Failed to search INBOX")

        all_uids = data[0].split()
        total_inbox = len(all_uids)

        # Reverse so newest is first, then apply offset+count pagination
        reversed_uids = all_uids[::-1]
        page_uids = reversed_uids[offset:offset + count]

        has_more = (offset + count) < total_inbox

        previews = []
        for uid in page_uids:
            uid_str = uid.decode()
            status2, msg_data = imap.fetch(uid, "(RFC822.HEADER BODY.PEEK[TEXT]<0.400>)")
            if status2 != "OK" or not msg_data or msg_data[0] is None:
                continue
            # msg_data structure can be complex; grab first bytes block
            raw = b""
            for part in msg_data:
                if isinstance(part, tuple):
                    raw += part[1]
            msg = email_lib.message_from_bytes(raw)
            previews.append(_message_to_preview(uid_str, msg))

        return {"messages": previews, "total": total_inbox, "has_more": has_more}
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def fetch_full_message(gmail_address: str, app_password: str, uid: str) -> dict:
    """
    Fetch a single full message by sequence number (UID) from INBOX.
    Returns a full parsed dict ready for the analyzer pipeline.
    """
    imap = connect(gmail_address, app_password)
    try:
        imap.select("INBOX", readonly=True)
        status, msg_data = imap.fetch(uid.encode(), "(RFC822)")
        if status != "OK" or not msg_data or msg_data[0] is None:
            raise ValueError(f"Could not fetch message UID {uid}")

        raw = b""
        for part in msg_data:
            if isinstance(part, tuple):
                raw += part[1]

        msg = email_lib.message_from_bytes(raw)
        return _message_to_full(uid, msg)
    finally:
        try:
            imap.logout()
        except Exception:
            pass
