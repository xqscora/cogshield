"""CogShield — Streamlit log triage dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from gemini_triage import triage_top_events
from mfa_log_scorer import ScoredEvent, score_events

SAMPLE_DIR = Path(__file__).parent / "sample_logs"

st.set_page_config(page_title="CogShield", page_icon="🛡️", layout="wide")

st.markdown(
    """
<style>
[data-testid="stAppViewContainer"] { background: #0a0f14; }
</style>
""",
    unsafe_allow_html=True,
)

st.title("🛡️ CogShield")
st.caption("MFA threat-field triage for security logs · FIND EVIL! SANS 2026")


def _serialize(scored: list[ScoredEvent]) -> list[dict]:
    return [
        {
            "index": s.index,
            "state": s.state,
            "f_threat": s.f_threat,
            "r": s.r,
            "s": s.s,
            "reasons": s.reasons,
            "raw": s.raw,
        }
        for s in scored
    ]


col_a, col_b = st.columns([1, 2])
with col_a:
    sample = st.selectbox(
        "Sample dataset",
        ["custom upload"] + sorted(p.name for p in SAMPLE_DIR.glob("*.json")),
    )
    api_key = st.text_input("Gemini API key (optional)", type="password")

events: list[dict] = []
if sample == "custom upload":
    up = st.file_uploader("JSON log array", type=["json"])
    if up:
        events = json.loads(up.read().decode("utf-8"))
else:
    events = json.loads((SAMPLE_DIR / sample).read_text(encoding="utf-8"))

with col_b:
    if not events:
        st.info("Select a sample or upload JSON.")
    else:
        scored = score_events(events)
        evil = sum(1 for s in scored if s.state == "EVIL")
        susp = sum(1 for s in scored if s.state == "SUSPICIOUS")
        m1, m2, m3 = st.columns(3)
        m1.metric("Events", len(events))
        m2.metric("EVIL", evil)
        m3.metric("Suspicious", susp)

        st.subheader("Threat field ranking")
        for s in scored[:15]:
            color = {"EVIL": "#ef4444", "SUSPICIOUS": "#f97316", "NOISE": "#eab308"}.get(
                s.state, "#64748b"
            )
            msg = s.raw.get("message", s.raw.get("signature", ""))[:100]
            st.markdown(
                f'<div style="border-left:4px solid {color};padding:8px 12px;margin:6px 0;'
                f'background:#111827;border-radius:6px">'
                f'<strong>{s.state}</strong> F_threat={s.f_threat:.2f} · {msg}</div>',
                unsafe_allow_html=True,
            )

        st.subheader("🤖 Gemini triage brief")
        brief = triage_top_events(
            _serialize(scored),
            api_key=api_key or None,
        )
        st.markdown(brief)

        with st.expander("MFA math (top event)"):
            if scored:
                t = scored[0]
                st.write(f"F_threat = S/r² = {t.s:.3f}/{t.r:.3f}² = {t.f_threat:.3f}")
                st.write("Reasons:", ", ".join(t.reasons))
