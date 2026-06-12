"""MFA-inspired log anomaly scoring for CogShield.

Maps security log events to threat field strength F_threat = S / r².
No hardcoded IOC tables — severity, rarity, and context drive S and r.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


SEVERITY_WEIGHT = {
    "critical": 3.0,
    "high": 2.2,
    "medium": 1.4,
    "low": 0.8,
    "info": 0.4,
}


@dataclass
class ScoredEvent:
    index: int
    raw: dict[str, Any]
    f_threat: float
    r: float
    s: float
    state: str
    reasons: list[str]


def _norm_severity(event: dict[str, Any]) -> float:
    sev = str(event.get("severity", event.get("level", "info"))).lower()
    return SEVERITY_WEIGHT.get(sev, 1.0)


def _baseline_r(event: dict[str, Any], avg_interval_ms: float) -> float:
    """r = contextual distance from 'normal' analyst focus."""
    reasons: list[str] = []
    r = 1.0

    action = str(event.get("action", "")).lower()
    if any(k in action for k in ("deny", "block", "fail", "alert", "exploit")):
        r *= 0.6
        reasons.append("hostile action verb")
    if event.get("success") is False:
        r *= 0.7
        reasons.append("explicit failure")

    # Burst timing — very fast repeats = lower r (harder to ignore)
    interval = float(event.get("interval_ms", avg_interval_ms) or avg_interval_ms)
    if interval < avg_interval_ms * 0.3:
        r *= 0.75
        reasons.append("burst timing")

    src = str(event.get("src_ip", ""))
    if src.count(".") == 3 and src.startswith(("10.", "192.168.", "172.")):
        r *= 1.15
        reasons.append("internal source (higher r)")

    return max(r, 0.15), reasons


def _field_strength(event: dict[str, Any], rarity: float) -> tuple[float, list[str]]:
    reasons: list[str] = []
    s = _norm_severity(event)
    reasons.append(f"severity base {s:.2f}")

    # Rarity from inverse document frequency proxy
    s *= 0.5 + min(rarity, 2.0)
    if rarity > 1.2:
        reasons.append("rare signature")

    if event.get("mitre_id"):
        s *= 1.25
        reasons.append("MITRE tagged")

    if event.get("user") in ("admin", "root", "SYSTEM"):
        s *= 1.15
        reasons.append("privileged user")

    return s, reasons


def classify_state(f_threat: float) -> str:
    if f_threat >= 2.5:
        return "EVIL"
    if f_threat >= 1.2:
        return "SUSPICIOUS"
    if f_threat >= 0.5:
        return "NOISE"
    return "BENIGN"


def score_events(events: list[dict[str, Any]]) -> list[ScoredEvent]:
    if not events:
        return []

    # Simple rarity: count normalized message hashes
    from collections import Counter

    keys = [str(e.get("signature", e.get("message", "")))[:80] for e in events]
    counts = Counter(keys)
    n = len(events)

    intervals = []
    prev_ts = None
    for e in events:
        ts = e.get("timestamp")
        if prev_ts is not None and ts is not None:
            try:
                intervals.append(abs(float(ts) - float(prev_ts)) * 1000)
            except (TypeError, ValueError):
                pass
        prev_ts = ts
    avg_interval = sum(intervals) / len(intervals) if intervals else 5000.0

    scored: list[ScoredEvent] = []
    for i, event in enumerate(events):
        key = keys[i]
        rarity = math.log(n / max(counts[key], 1)) + 0.5
        s, s_reasons = _field_strength(event, rarity)
        r, r_reasons = _baseline_r(event, avg_interval)
        f_threat = s / (r ** 2)
        state = classify_state(f_threat)
        scored.append(
            ScoredEvent(
                index=i,
                raw=event,
                f_threat=f_threat,
                r=r,
                s=s,
                state=state,
                reasons=s_reasons + r_reasons,
            )
        )

    scored.sort(key=lambda x: x.f_threat, reverse=True)
    return scored
