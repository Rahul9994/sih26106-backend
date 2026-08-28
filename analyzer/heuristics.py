"""
heuristics.py
Rule-based scoring layer. Runs independently of any AI model so the
system still produces a real risk assessment even with no API keys
configured. Each triggered rule contributes weighted points (0-100
scale, capped) and is recorded as a named "indicator" with a severity
so the frontend can render a clean forensic checklist.
"""
import re

from .email_parser import URGENCY_KEYWORDS, SUSPICIOUS_ATTACHMENT_EXT

KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix", "facebook",
    "instagram", "bankofamerica", "chase", "wellsfargo", "hdfcbank", "icicibank",
    "sbi", "irctc", "flipkart", "linkedin",
]

SHORTENER_DOMAINS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly")


def _levenshtein(a, b):
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _lookalike_brand(domain: str):
    if not domain:
        return None
    core = domain.split(".")[0]
    for brand in KNOWN_BRANDS:
        if brand == core:
            return None  # exact match to a brand's own root — not a lookalike
        dist = _levenshtein(core, brand)
        if 0 < dist <= 2 and len(core) >= 4:
            return brand
    return None


def _domain_has_ip(url: str) -> bool:
    m = re.search(r"https?://([^/]+)", url)
    if not m:
        return False
    host = m.group(1).split(":")[0]
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))


def _is_punycode(url: str) -> bool:
    return "xn--" in url.lower()


def run_heuristics(parsed: dict) -> dict:
    indicators = []
    score = 0

    auth = parsed.get("auth", {})
    for check, weight in (("spf", 15), ("dkim", 15), ("dmarc", 10)):
        verdict = auth.get(check, "unknown")
        if verdict == "fail":
            score += weight
            indicators.append(_flag(f"{check.upper()} authentication failed", "high",
                                     f"The {check.upper()} check did not pass, meaning the sending "
                                     f"server could not be verified against the claimed domain."))
        elif verdict == "none":
            score += weight // 2
            indicators.append(_flag(f"No {check.upper()} record found", "medium",
                                     f"The message has no {check.upper()} result to evaluate — "
                                     f"treat sender identity as unverified."))

    from_domain = parsed.get("from_domain", "")
    reply_domain = parsed.get("reply_to_domain", "")
    return_domain = parsed.get("return_path_domain", "")
    if reply_domain and from_domain and reply_domain != from_domain:
        score += 10
        indicators.append(_flag("From / Reply-To domain mismatch", "high",
                                 f"Replies are routed to '{reply_domain}' instead of the sending "
                                 f"domain '{from_domain}' — a common redirection trick."))
    if return_domain and from_domain and return_domain != from_domain:
        score += 8
        indicators.append(_flag("From / Return-Path domain mismatch", "medium",
                                 f"Bounce path '{return_domain}' differs from the From domain "
                                 f"'{from_domain}'."))

    lookalike = _lookalike_brand(from_domain)
    if lookalike:
        score += 12
        indicators.append(_flag(f"Sender domain resembles '{lookalike}'", "high",
                                 f"'{from_domain}' is one or two characters off from a well-known "
                                 f"brand domain — a classic typosquat / lookalike pattern."))

    body_lower = (parsed.get("body") or "").lower()
    hit_keywords = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    if hit_keywords:
        pts = min(20, 5 * len(hit_keywords))
        score += pts
        indicators.append(_flag("Social-engineering / urgency language", "medium",
                                 "Phrases detected: " + ", ".join(hit_keywords[:5]) +
                                 ("…" if len(hit_keywords) > 5 else "")))

    urls = parsed.get("urls", [])
    ip_urls = [u for u in urls if _domain_has_ip(u)]
    short_urls = [u for u in urls if any(s in u for s in SHORTENER_DOMAINS)]
    puny_urls = [u for u in urls if _is_punycode(u)]
    if ip_urls:
        score += 15
        indicators.append(_flag("Link points directly to a raw IP address", "high",
                                 f"{len(ip_urls)} link(s) use a bare IP instead of a domain name, "
                                 f"hiding the true destination."))
    if short_urls:
        score += 8
        indicators.append(_flag("Shortened URL detected", "medium",
                                 f"{len(short_urls)} link(s) use a URL shortener, which can mask "
                                 f"the real landing page."))
    if puny_urls:
        score += 12
        indicators.append(_flag("Punycode / homograph domain in link", "high",
                                 f"{len(puny_urls)} link(s) use punycode (xn--) encoding, often used "
                                 f"to spoof lookalike Unicode domains."))

    attachments = parsed.get("attachments", [])
    risky_attachments = [a for a in attachments if a.get("suspicious_extension")]
    if risky_attachments:
        score += 15
        names = ", ".join(a["filename"] for a in risky_attachments)
        indicators.append(_flag("Suspicious attachment type", "high",
                                 f"Executable-style attachment(s) found: {names}"))

    if not indicators:
        indicators.append(_flag("No heuristic red flags found", "info",
                                 "Authentication, links, and language all passed baseline checks. "
                                 "This does not guarantee safety — see the AI verdict below."))

    return {
        "heuristic_score": min(100, score),
        "indicators": indicators,
        "url_count": len(urls),
        "suspicious_url_count": len(set(ip_urls) | set(short_urls) | set(puny_urls)),
        "attachment_count": len(attachments),
        "suspicious_attachment_count": len(risky_attachments),
    }


def _flag(title, severity, detail):
    return {"title": title, "severity": severity, "detail": detail}
