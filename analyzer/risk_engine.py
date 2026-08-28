"""
risk_engine.py
Combines the heuristic score and the AI score into one final risk
percentage + verdict band, and assembles the complete forensic report
returned to the frontend.
"""
import uuid
import datetime

VERDICT_BANDS = (
    (85, "critical"),
    (60, "high"),
    (30, "medium"),
    (0, "low"),
)


def _verdict_for(score: int) -> str:
    for floor, label in VERDICT_BANDS:
        if score >= floor:
            return label
    return "low"


def compute_final_score(heuristic_score: int, ai_score) -> dict:
    if ai_score is None:
        final = heuristic_score
        blend = "heuristic-only (AI unavailable)"
    else:
        final = round(0.5 * heuristic_score + 0.5 * ai_score)
        blend = "50% heuristic / 50% AI"
    final = max(0, min(100, final))
    return {
        "final_score": final,
        "verdict": _verdict_for(final),
        "blend_method": blend,
    }


def build_report(parsed: dict, heuristics: dict, ai_result: dict, geolocations: list) -> dict:
    scoring = compute_final_score(heuristics["heuristic_score"], ai_result.get("phishing_score"))

    return {
        "case_id": f"CASE-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}",
        "analyzed_at": datetime.datetime.utcnow().isoformat() + "Z",
        "sender": {
            "from": parsed.get("from"),
            "from_domain": parsed.get("from_domain"),
            "reply_to_domain": parsed.get("reply_to_domain"),
            "return_path_domain": parsed.get("return_path_domain"),
            "subject": parsed.get("subject"),
            "date": parsed.get("date"),
        },
        "authentication": parsed.get("auth"),
        "network": {
            "hop_ips": parsed.get("hop_ips"),
            "origin_ip": parsed.get("origin_ip"),
            "geolocations": geolocations,
        },
        "content": {
            "url_count": heuristics.get("url_count"),
            "suspicious_url_count": heuristics.get("suspicious_url_count"),
            "urls": parsed.get("urls"),
            "attachments": parsed.get("attachments"),
        },
        "heuristics": {
            "score": heuristics["heuristic_score"],
            "indicators": heuristics["indicators"],
        },
        "ai_analysis": ai_result,
        "risk": scoring,
    }
