# Vajra Backend (Flask)

## Setup

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\main.py
```

Server runs on http://0.0.0.0:8008

## Endpoints
- POST /sensors: `{ "shield_on": true|false }` → `{ "status": "Shield On|Off" }`
- POST /ai_safety: `{ "x": float, "y": float, "z": float, "timestamp?": str, "shield_on?": bool }` → `{ "status": "ok", "ts": str }`
- POST /heartbeat: `{ "shield_on": bool, "ts": str }` → `{ "status": "ok", "ts": str }`
- POST /heartbeat: `{ "shield_on": bool, "distress?": bool, "ts": str }` → `{ "status": "ok", "ts": str, "distress": bool }`
- POST /location: `{ "lat": float, "lon": float, "ts": str }` → `{ "status": "ok", "lat": float, "lon": float }`
- POST /audio (multipart/form-data): `audio=<file>` → `{ "status": "ok", "bytes": int }`
- POST /sos_alert: `{ "ts": str, "lat?": float, "lon?": float, "distress": bool }` → `{ "status": "accepted", ... }`
