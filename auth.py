# auth.py
import os
import time
from datetime import timedelta
from typing import Optional, Set, Dict, Any, Union

# --- JWT backend: PyJWT preferred; fall back to python-jose if available ---
try:
    import jwt as _pyjwt  # PyJWT
    _JWT_BACKEND = "pyjwt"
except Exception:
    try:
        from jose import jwt as _pyjwt  # python-jose
        _JWT_BACKEND = "jose"
    except Exception as e:
        raise ImportError(
            "No JWT library found. Install PyJWT (`pip install PyJWT`) "
            "or python-jose (`pip install python-jose`)."
        ) from e

# --- Password hashing ---
try:
    import bcrypt
except Exception as e:
    raise ImportError(
        "bcrypt is not installed. Add `bcrypt` to requirements.txt."
    ) from e

from fastapi import Depends, Header, Cookie, HTTPException, Response
from sqlalchemy.orm import Session
from sqlalchemy import text

from db import get_db, User

# ------------------------------------------------------------------------------
# Settings
# ------------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-in-prod")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "604800"))  # 7 days default

# Comma-separated admin emails (case-insensitive)
_admin_emails_env = os.getenv("ADMIN_EMAILS", "")
ADMIN_EMAILS: Set[str] = {e.strip().lower() for e in _admin_emails_env.split(",") if e.strip()}

# Optional: treat a whole domain as admin (e.g., "yourco.com")
ADMIN_DOMAIN = os.getenv("ADMIN_DOMAIN", "").strip().lower()

# Cookie settings
COOKIE_NAME = os.getenv("AUTH_COOKIE_NAME", "token")
COOKIE_DOMAIN = os.getenv("AUTH_COOKIE_DOMAIN", "") or None  # set if you want to scope the cookie
COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "true").lower() in ("1", "true", "yes")
COOKIE_SAMESITE = os.getenv("AUTH_COOKIE_SAMESITE", "lax").capitalize()  # Lax | Strict | None
COOKIE_MAX_AGE = int(os.getenv("AUTH_COOKIE_MAX_AGE", str(JWT_EXPIRE_SECONDS)))


# ------------------------------------------------------------------------------
# Utilities: password & tokens
# ------------------------------------------------------------------------------
def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Empty password not allowed")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# backward-compat alias
def get_password_hash(password: str) -> str:
    return hash_password(password)

def verify_password(password: str, hashed: Optional[str]) -> bool:
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_access_token(
    sub: Union[str, int],
    *,
    expires_in: Optional[int] = None,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    sub can be a user id (int/str) or an email (str). We'll store it as a string.
    """
    now = int(time.time())
    if expires_delta is not None:
        exp_secs = int(expires_delta.total_seconds())
    else:
        exp_secs = int(expires_in if expires_in is not None else JWT_EXPIRE_SECONDS)
    payload: Dict[str, Any] = {"sub": str(sub).strip().lower(), "iat": now, "exp": now + exp_secs}
    if extra_claims:
        payload.update(extra_claims)
    return _pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def _decode_token(token: str) -> dict:
    try:
        # For PyJWT and jose this returns a dict or raises
        return _pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ------------------------------------------------------------------------------
# Helpers: admin allowlist logic
# ------------------------------------------------------------------------------
def _is_allowlisted_admin(email: str) -> bool:
    e = (email or "").lower().strip()
    if not e:
        return False
    if e in ADMIN_EMAILS:
        return True
    if ADMIN_DOMAIN and e.endswith("@" + ADMIN_DOMAIN):
        return True
    return False

def _ensure_allowlisted_flag(db: Session, user: User) -> None:
    """
    If the user is allowlisted as admin but DB flag is False, flip it to True.
    Keeps DB consistent with env-based allowlist.
    """
    try:
        if not user.is_admin and _is_allowlisted_admin(user.email):
            db.execute(text("UPDATE users SET is_admin = TRUE WHERE id = :uid"), {"uid": user.id})
            db.commit()
            user.is_admin = True
    except Exception:
        db.rollback()


# ------------------------------------------------------------------------------
# Cookie helpers (optional but handy for login/logout)
# ------------------------------------------------------------------------------

def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="token",
        value=token,
        max_age=60*60*24*30,  # 30 days
        expires=60*60*24*30,
        path="/",
        secure=True,          # keep True in prod (https)
        httponly=False,       # readable by JS (your admin UI)
        samesite="Lax",
    )

def clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(key="token", path="/")

# ------------------------------------------------------------------------------
# Token extraction (Bearer header OR cookie)
# ------------------------------------------------------------------------------
def _extract_bearer_token(authorization: Optional[str], cookie_token: Optional[str]) -> str:
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()
    if cookie_token and cookie_token.strip():
        return cookie_token.strip()
    raise HTTPException(status_code=401, detail="Missing token")


# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------
def get_current_user(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None, convert_underscores=False),
    token_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
) -> User:
    """
    Resolve the current user from a JWT presented either as:
      - Authorization: Bearer <token>
      - Cookie: token=<token>    (cookie name can be overridden by AUTH_COOKIE_NAME)
    The token 'sub' may be a user id or an email.
    """
    token = _extract_bearer_token(authorization, token_cookie)
    payload = _decode_token(token)

    sub = str(payload.get("sub", "")).strip().lower()
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user: Optional[User] = None
    if sub.isdigit():
        user = db.query(User).get(int(sub))  # type: ignore[arg-type]
    if not user:
        user = db.query(User).filter(User.email.ilike(sub)).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    _ensure_allowlisted_flag(db, user)
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if bool(user.is_admin) or _is_allowlisted_admin(user.email):
        return user
    raise HTTPException(status_code=403, detail="Admin only")


# ------------------------------------------------------------------------------
# Optional convenience: authenticate via email+password inside endpoints
# ------------------------------------------------------------------------------
def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    e = (email or "").strip().lower()
    if not e or not password:
        return None
    user: Optional[User] = db.query(User).filter(User.email.ilike(e)).first()
    if not user or not user.hashed_password:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user
