# db.py
import os
from datetime import datetime
from typing import Generator, Optional

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, text
)
from sqlalchemy.orm import (
    sessionmaker, declarative_base, scoped_session, relationship, Session
)

# ------------------------------------------------------------------------------
# Connection (fail-fast in prod; optional SQLite only if you explicitly allow it)
# ------------------------------------------------------------------------------
def _normalize_db_url(url: str) -> str:
    return url.replace("postgres://", "postgresql://", 1) if url.startswith("postgres://") else url

DATABASE_URL = _normalize_db_url((os.getenv("DATABASE_URL") or "").strip())
DB_FALLBACK_TO_SQLITE = (os.getenv("DB_FALLBACK_TO_SQLITE", "0").lower() in ("1", "true", "yes"))
SQLITE_URL = "sqlite:///./caio.dev.sqlite3"

if not DATABASE_URL:
    if DB_FALLBACK_TO_SQLITE:
        DATABASE_URL = SQLITE_URL
    else:
        # Prevent accidental local DBs in production environments.
        raise RuntimeError("DATABASE_URL not set. Set DB_FALLBACK_TO_SQLITE=1 only for local dev.")

def _make_engine(url: str):
    url = _normalize_db_url(url)
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    else:
        # Keep timeouts small so Neon/pool errors surface fast
        connect_args = {"connect_timeout": int(os.getenv("PG_CONNECT_TIMEOUT", "5"))}
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=300,
        future=True,
        connect_args=connect_args,
    )

engine = _make_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()

# ------------------------------------------------------------------------------
# ORM Models
# ------------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)

    # Auth
    hashed_password = Column(String(255), nullable=True)

    # Identity / plan
    username = Column(String(255), nullable=True)
    tier = Column(String(32), nullable=False, default="demo")  # demo | pro | pro_plus | premium | admin
    is_admin = Column(Boolean, nullable=False, default=False)
    is_test = Column(Boolean, nullable=False, default=False)   # internal/testing accounts
    is_paid = Column(Boolean, nullable=False, default=False)

    # Billing (nullable so old rows don't break)
    billing_currency = Column(String(8), nullable=True)        # e.g., "INR" | "USD"
    plan_tier = Column(String(32), nullable=True)              # e.g., "pro" | "pro_plus" | "premium"
    plan_status = Column(String(32), nullable=True)            # e.g., "active" | "cancelled"

    # Timestamps
    created_at = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

class UsageLog(Base):
    __tablename__ = "usage_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    endpoint = Column(String(64), default="analyze", index=True)
    status = Column(String(32), default="ok")                   # "ok" | "429" | "error" ...
    meta = Column(String, default="")

class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    title = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True, nullable=False)
    role = Column(String(16), index=True)  # "user" | "assistant" | "system"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    session = relationship("ChatSession", back_populates="messages")

# ------------------------------------------------------------------------------
# Init & session helpers
# ------------------------------------------------------------------------------
def _ensure_users_columns(engine) -> None:
    """
    Non-destructive, idempotent DDL to make sure new columns exist in prod.
    This protects you until full Alembic migrations are set up.
    """
    ddl = [
        "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS billing_currency VARCHAR(8)",
        "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS plan_tier VARCHAR(32)",
        "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS plan_status VARCHAR(32)",
        "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NULL",
        "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP NULL",
    ]
    with engine.begin() as conn:
        for stmt in ddl:
            conn.execute(text(stmt))

def init_db() -> None:
    """Initialize the DB connection and create tables if missing, then ensure columns exist."""
    # Probe connectivity first; fail early if Neon is unreachable.
    with _make_engine(DATABASE_URL).connect() as conn:
        conn.execute(text("SELECT 1"))

    # Bind the proven engine and create tables (no destructive migrations).
    global engine
    engine = _make_engine(DATABASE_URL)
    SessionLocal.remove()
    SessionLocal.configure(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Ensure newly added columns exist (safe if they already do).
    _ensure_users_columns(engine)

def get_db() -> Generator[Session, None, None]:
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------------------------------------------------------------------
# Small utility helpers used by routes (optional but handy)
# ------------------------------------------------------------------------------
def touch_last_seen(db: Session, user_id: int) -> None:
    """Update last_seen = NOW() for a user; ignore failures to avoid breaking flow."""
    try:
        db.execute(text("UPDATE public.users SET last_seen = NOW() WHERE id = :uid"), {"uid": user_id})
        db.commit()
    except Exception:
        db.rollback()

def log_usage(db: Session, *, user_id: Optional[int], endpoint: str, status: str = "ok", meta: str = "") -> None:
    """Insert a usage log row; safe-and-silent on failure."""
    try:
        db.add(UsageLog(user_id=user_id or 0, endpoint=endpoint[:64], status=status[:32], meta=meta[:1000]))
        db.commit()
    except Exception:
        db.rollback()
