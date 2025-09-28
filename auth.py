# auth.py
import os
import time
from typing import Optional, Set

import bcrypt
import jwt  # PyJWT
from fastapi import Depends, Header, Cookie, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

from db import get_db, User

# ------------------------------------------------------------------------------
# Settings
# ------------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-in-prod")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "604800"))  # default 7 days

# Comma-separated admin emails (case-insensitive)
_admin_emails_env = os.getenv("ADMIN_EMAILS", "")
ADMIN_EMAILS: Set[str] = {e.strip().lower() for e in _admin_emails_env.split(",") if e.strip()}

# Optional: treat an entire email domain as admin (e.g., "yourcompany.com")
ADMIN_DOMAIN = os.getenv("ADMIN_DOMAIN", "").strip().lower()

# ------------------------------------------------------------------------------
# Utilities: password & tokens
# ------------------------------------------------------------------------------
def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Empty password not allowed")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: Optional[str]) -> bool:
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_access_token(sub: str, *, expires_in: Optional[int] = None) -> str:
    """Create a signed JWT with subject = user's email (lowercased)."""
    now = int(time.time())
    exp_secs = int(expires_in if expires_in is not None else JWT_EXPIRE_SECONDS)
    payload = {"sub": (sub or "").lower(), "iat": now, "exp": now + exp_secs}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
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
            user.is_admin = True  # reflect change on the in-memory instance
    except Exception:
        db.rollback()

# ------------------------------------------------------------------------------
# Token extraction
# ------------------------------------------------------------------------------
def _extract_bearer_token(authorization: Optional[str], cookie_token: Optional[str]) -> str:
    # Priority 1: Authorization header ("Bearer <token>")
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()

    # Priority 2: Cookie named "token" (best effort; ensure you set it securely if you use it)
    if cookie_token and cookie_token.strip():
        return cookie_token.strip()

    raise HTTPException(status_code=401, detail="Missing token")

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------
def get_current_user(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None, convert_underscores=False),
    token_cookie: Optional[str] = Cookie(default=None, alias="token"),
) -> User:
    """
    Resolve the current user from a JWT Bearer token (or 'token' cookie).
    Returns a fully-loaded ORM User. Raises 401 if missing/invalid, 404 if not found.
    """
    token = _extract_bearer_token(authorization, token_cookie)
    payload = _decode_token(token)
    email = (payload.get("sub") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user: Optional[User] = db.query(User).filter(User.email.ilike(email)).first()
    if not user:
        # Token valid but user missing -> treat as revoked / stale
        raise HTTPException(status_code=401, detail="User not found")

    # If allowlisted via env, ensure DB flag is set
    _ensure_allowlisted_flag(db, user)
    return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    """
    Admin-only guard. Accepts either DB-flagged admin OR allowlisted email/domain.
    Auto-flips DB flag for allowlisted admins.
    """
    if bool(user.is_admin) or _is_allowlisted_admin(user.email):
        return user
    raise HTTPException(status_code=403, detail="Admin only")

# ------------------------------------------------------------------------------
# Optional convenience: authenticate via email+password inside endpoints
# ------------------------------------------------------------------------------
def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """Return user if credentials are valid; otherwise None."""
    e = (email or "").strip().lower()
    if not e or not password:
        return None
    user: Optional[User] = db.query(User).filter(User.email.ilike(e)).first()
    if not user or not user.hashed_password:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user
