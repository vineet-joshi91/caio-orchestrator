# caio_core/utils_jwt.py
import time, hmac, hashlib, base64, json
from typing import Optional, Dict
from caio_core.settings import settings

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode())

def sign_jwt(sub: str, minutes: int | None = None) -> str:
    if minutes is None:
        minutes = settings.JWT_EXPIRE_MINUTES
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": sub, "iat": now, "exp": now + minutes * 60}
    h_b64 = _b64url_json(header)
    p_b64 = _b64url_json(payload)
    msg = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(settings.JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"

def verify_jwt(token: str) -> Optional[Dict]:
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        msg = f"{h_b64}.{p_b64}".encode()
        sig = base64.urlsafe_b64decode(s_b64 + "==")
        exp_sig = hmac.new(settings.JWT_SECRET.encode(), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, exp_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(p_b64 + "==").decode())
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None
