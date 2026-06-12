"""Gemini-powered triage narrative for top-scored events."""

from __future__ import annotations

import os
from typing import Any

try:
    import google.generativeai as genai
except ImportError:
    genai = None  # type: ignore[assignment]


FALLBACK = {
    "EVIL": (
        "**Analyst brief:** Field strength exceeded EVIL threshold (F_threat ≥ 2.5). "
        "Prioritize: validate source IP, check auth logs for lateral movement, "
        "contain host if exploit signature matches."
    ),
    "SUSPICIOUS": (
        "**Analyst brief:** Elevated F_threat — correlate with firewall and EDR timelines. "
        "May be reconnaissance or misconfigured service."
    ),
    "NOISE": (
        "**Analyst brief:** Moderate field — likely operational noise unless paired "
        "with failure bursts."
    ),
    "BENIGN": (
        "**Analyst brief:** Low threat field — deprioritize unless part of a chain."
    ),
}


def triage_top_events(
    events: list[dict[str, Any]],
    *,
    api_key: str | None = None,
    max_events: int = 5,
) -> str:
    if not events:
        return "No events to triage."

    key = api_key or os.getenv("GEMINI_API_KEY")
    top = events[:max_events]
    bullet_lines = []
    for e in top:
        bullet_lines.append(
            f"- [{e.get('state', '?')}] F={e.get('f_threat', 0):.2f} "
            f"{e.get('raw', {}).get('message', e.get('message', ''))[:120]}"
        )
    context = "\n".join(bullet_lines)
    dominant = top[0].get("state", "SUSPICIOUS") if top else "SUSPICIOUS"

    if not key or genai is None:
        return FALLBACK.get(str(dominant), FALLBACK["SUSPICIOUS"]) + "\n\n" + context

    genai.configure(api_key=key)
    model = genai.GenerativeModel("gemini-2.0-flash")
    prompt = f"""You are a SOC analyst assistant. CogShield scored logs using MFA threat field F=S/r².
Summarize the top anomalies in 3-5 sentences for a junior analyst. Be concrete. No fluff.

Top events:
{context}
"""
    try:
        resp = model.generate_content(prompt)
        return resp.text.strip()
    except Exception:
        return FALLBACK.get(str(dominant), FALLBACK["SUSPICIOUS"]) + "\n\n" + context
