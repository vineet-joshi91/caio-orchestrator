# auth.py
import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from db import get_db, User  # User: email, hashed_password, is_admin, is_paid

# -----------------------------------------------------------------------------
# Admin allowlist helper
# -----------------------------------------------------------------------------
def _is_admin_email(email: str) -> bool:
    if not email:
        return False
    email = email.strip().lower()
    admin_one = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    admin_many = [e.strip().lower() for e in (os.getenv("ADMIN_EMAILS") or "").split(",") if e.strip()]
    return (email == admin_one) or (email in admin_many)

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY") or "change-me-in-prod"
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10080"))  # 7 days

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# -----------------------------------------------------------------------------
# Password helpers
# -----------------------------------------------------------------------------
def get_password_hash(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_ctx.verify(plain_password, hashed_password)
    except Exception:
        return False

# -----------------------------------------------------------------------------
# JWT primitives
# -----------------------------------------------------------------------------
def create_access_token(sub: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = {"sub": sub}
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def _decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub: Optional[str] = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        return sub
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# -----------------------------------------------------------------------------
# Dependency
# -----------------------------------------------------------------------------
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """
    Loads the current user from the JWT and DB, and normalizes the admin flag:
    - DB user.is_admin == True  OR
    - Email is in ADMIN_EMAIL / ADMIN_EMAILS allowlist
    """
    email = _decode_token(token)
    user: Optional[User] = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # ✅ ensure admin is true if DB says so OR allowlist contains the email
    try:
        allow_admin = _is_admin_email(user.email)
        db_admin = bool(getattr(user, "is_admin", False))
        user.is_admin = bool(db_admin or allow_admin)
    except Exception:
        # don't block the request over attribute errors
        pass

    return user
