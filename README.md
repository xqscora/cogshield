# CogShield — MFA-Inspired Security Log Triage

**FIND EVIL! SANS Hackathon 2026**

CogShield applies the **Magnetic Field Model of Attention (MFA)** to security telemetry: treat analyst focus as a field that collapses when log noise overwhelms signal. It scores events by **threat field strength** `F_threat = S / r²` and uses **Gemini** to triage top anomalies.

## Quick start

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=your-key   # optional — rich fallback without API
streamlit run app.py
```

Upload a JSON log array or use bundled samples in `sample_logs/`.

## Theory (MFA → DFIR)

| MFA (attention) | CogShield (security) |
|-----------------|----------------------|
| r = psychological distance | r = time/context distance from baseline |
| S = motivation × streak | S = severity × confidence × rarity |
| F_att = S/r² | F_threat = S/r² |
| OVERLOADED = collapse | **EVIL** = high field, needs analyst |

Based on Zeng (2026) *Attention as a Magnetic Field* — inverse-square decay models how signal strength drops as events drift from normal behavior.

## Repo layout

- `mfa_log_scorer.py` — zero-preset anomaly scoring
- `gemini_triage.py` — state-aware incident narrative
- `app.py` — Streamlit triage dashboard
- `sample_logs/` — demo datasets

## Author

Cora Zeng — https://github.com/xqscora
