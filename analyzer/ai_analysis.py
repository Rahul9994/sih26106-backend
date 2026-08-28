"""
ai_analysis.py
Sends the parsed email + heuristic findings to an LLM for a second,
semantic opinion — phishing score, classification, plain-English
reasoning, and a recommended action. Tries Groq first (fast + has a
generous free tier), falls back to OpenRouter, and if neither key is
configured (or both calls fail) returns a clearly-labeled
heuristic-only result instead of crashing the request.
"""
import os
import json
import re
import requests

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
TIMEOUT_SECONDS = 25

SYSTEM_PROMPT = """You are a cybersecurity forensic analyst specializing in email-based \
threats (phishing, business email compromise, malware delivery, spoofing). \
You will be given structured facts extracted from one email plus a list of \
heuristic findings already computed by a rules engine. Provide your own \
independent semantic judgement of intent and social-engineering technique — \
do not simply restate the heuristic findings.

Respond with ONLY a JSON object, no markdown fences, no commentary, in \
exactly this shape:
{
  "phishing_score": <integer 0-100, your independent estimate of malicious intent>,
  "classification": "<one of: benign, suspicious, phishing, business_email_compromise, malware_delivery, spam>",
  "key_indicators": ["short phrase", "short phrase", ...],
  "reasoning": "<2-4 sentences of plain-English forensic reasoning>",
  "recommended_action": "<one short actionable sentence for the recipient/SOC analyst>"
}"""


def _build_user_prompt(parsed: dict, heuristics: dict) -> str:
    facts = {
        "from": parsed.get("from"),
        "from_domain": parsed.get("from_domain"),
        "reply_to_domain": parsed.get("reply_to_domain"),
        "return_path_domain": parsed.get("return_path_domain"),
        "subject": parsed.get("subject"),
        "auth_results": parsed.get("auth"),
        "origin_ip": parsed.get("origin_ip"),
        "url_count": heuristics.get("url_count"),
        "urls_sample": (parsed.get("urls") or [])[:8],
        "attachments": parsed.get("attachments"),
        "heuristic_score_0_100": heuristics.get("heuristic_score"),
        "heuristic_indicators": [i["title"] for i in heuristics.get("indicators", [])],
        "body_excerpt": (parsed.get("body") or "")[:2500],
    }
    return "Analyze this email:\n" + json.dumps(facts, indent=2, default=str)


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)
    return json.loads(text)


def _call_chat_api(url: str, api_key: str, model: str, user_prompt: str, extra_headers=None) -> dict:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 700,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT_SECONDS)
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    return _extract_json(content)


def run_ai_analysis(parsed: dict, heuristics: dict) -> dict:
    user_prompt = _build_user_prompt(parsed, heuristics)

    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip()
    openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    openrouter_model = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free").strip()

    errors = []

    if groq_key:
        try:
            result = _call_chat_api(GROQ_URL, groq_key, groq_model, user_prompt)
            return _finalize(result, provider="groq", model=groq_model)
        except Exception as exc:
            errors.append(f"groq: {exc}")

    if openrouter_key:
        try:
            result = _call_chat_api(
                OPENROUTER_URL, openrouter_key, openrouter_model, user_prompt,
                extra_headers={
                    "HTTP-Referer": "http://localhost",
                    "X-Title": "SIH26106 Email Threat Detection",
                },
            )
            return _finalize(result, provider="openrouter", model=openrouter_model)
        except Exception as exc:
            errors.append(f"openrouter: {exc}")

    return {
        "available": False,
        "provider": None,
        "model": None,
        "phishing_score": None,
        "classification": "unavailable",
        "key_indicators": [],
        "reasoning": (
            "No AI provider is configured or reachable, so this verdict is heuristic-only. "
            "Add GROQ_API_KEY and/or OPENROUTER_API_KEY to backend/.env to enable AI analysis."
            + (" (" + "; ".join(errors) + ")" if errors else "")
        ),
        "recommended_action": "Rely on the rule-based indicators above until an AI key is configured.",
    }


def _finalize(result: dict, provider: str, model: str) -> dict:
    score = result.get("phishing_score")
    try:
        score = max(0, min(100, int(score)))
    except (TypeError, ValueError):
        score = None
    return {
        "available": True,
        "provider": provider,
        "model": model,
        "phishing_score": score,
        "classification": result.get("classification", "unknown"),
        "key_indicators": result.get("key_indicators", []) or [],
        "reasoning": result.get("reasoning", "").strip(),
        "recommended_action": result.get("recommended_action", "").strip(),
    }
