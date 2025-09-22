
import time, hmac, hashlib, base64, json
from typing import Optional, Dict
from datetime import datetime, timedelta
from caio_core.settings import settings

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",",":")).encode())

def sign_jwt(sub: str, minutes: int = None) -> str:
    if minutes is None:
        minutes = settings.JWT_EXPIRE_MINUTES
    header = {"alg":"HS256","typ":"JWT"}
    now = int(time.time())
    payload = {"sub": sub, "iat": now, "exp": now + minutes*60}
    header_b64 = _b64url_json(header)
    payload_b64 = _b64url_json(payload)
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(settings.JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"

def verify_jwt(token: str) -> Optional[Dict]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        msg = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        exp_sig = hmac.new(settings.JWT_SECRET.encode(), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, exp_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

# Prompt kit loader (brains reference external prompt files)
from pathlib import Path

def load_prompt(brain: str, variant: str = "default") -> str:
    # looks for brains/<BRAIN>/<variant>.prompt.txt
    root = Path(__file__).resolve().parents[2]  # project root
    p = root / "brains" / brain.upper() / f"{variant}.prompt.txt"
    if p.exists():
        return p.read_text(encoding="utf-8")
    # fallback
    return f"You are the {brain} brain. Provide concise, actionable insights."
