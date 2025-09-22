# -*- coding: utf-8 -*-
"""
CAIO Backend — unified hub wired to Neon (DB) + Auth + Analyze/Brains + Chat + Admin + Payments + Contact
Matches the endpoints your frontend calls.

Build (Render): pip install -r backend/requirements.txt
Start (Render): uvicorn --app-dir backend main:app --host 0.0.0.0 --port $PORT
"""

import os
import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from caio_core.aggregation.brain_aggregator import aggregate_brain_outputs

# ---- core settings / schemas / utils (your files) ----
from caio_core.settings import settings  # APP_NAME, VERSION, CORS_ORIGINS, JWT_EXPIRE_MINUTES
from caio_core.schemas import (
    DocumentIn, BrainRequest, CombinedInsights, Insight, AnalyzeResponse,
    AuthSignup, AuthLogin, AuthToken, Me, Health
)
from caio_core.utils import sign_jwt, verify_jwt

# ---- DB & auth layer (your files) ----
from db import get_db, init_db, User, UsageLog, ChatSession, ChatMessage
from auth import (
    get_current_user,
    create_access_token,
    get_password_hash,
    verify_password,
)

# ---- Feature routers (already exist in your repo) ----
try:
    from health import router as health_router         # /api/health, /api/ready
except Exception:
    health_router = None

try:
    from admin import router as admin_router           # /api/admin/...
except Exception:
    admin_router = None

try:
    from admin_metrics import router as admin_metrics_router  # /api/admin/metrics (timeseries)
except Exception:
    admin_metrics_router = None

try:
    from payment import router as payments_router      # /api/payments/...
except Exception:
    payments_router = None

try:
    from contact import router as contact_router       # /api/contact
except Exception:
    contact_router = None

# ---- Brains (registry + your engine adapter lives behind each brain) ----
from caio_brains.registry import brain_registry

# ------------------------------------------------------------------------------
# App + CORS
# ------------------------------------------------------------------------------
app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)

origins: List[str] = []
if getattr(settings, "CORS_ORIGINS", None):
    origins += [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
extra = (os.getenv("ALLOWED_ORIGINS") or "").strip()
if extra:
    origins += [o.strip() for o in extra.split(",") if o.strip()]
if not origins:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
)

@app.options("/{path:path}")
def options_ok(path: str):
    return PlainTextResponse("ok")

# ------------------------------------------------------------------------------
# Startup: warm DB so /api/ready reflects state
# ------------------------------------------------------------------------------
DB_READY = False
STARTUP_OK = False
STARTUP_ERROR = ""

async def _warmup_db():
    global DB_READY
    tries = int(os.getenv("DB_WARMUP_TRIES", "20"))
    delay = float(os.getenv("DB_WARMUP_DELAY", "1.5"))
    for _ in range(tries):
        try:
            init_db()
            DB_READY = True
            return
        except Exception:
            await asyncio.sleep(delay)

@app.on_event("startup")
async def _startup():
    global STARTUP_OK, STARTUP_ERROR
    try:
        await _warmup_db()
        STARTUP_OK = True
        STARTUP_ERROR = ""
    except Exception as e:
        STARTUP_OK = False
        STARTUP_ERROR = str(e)[:500]

# ------------------------------------------------------------------------------
# Basic health/version (flat)
# ------------------------------------------------------------------------------
@app.get("/health", response_model=Health)
def health():
    return Health(status="ok", version=settings.VERSION)

@app.get("/version")
def version():
    return {"version": settings.VERSION}

# ------------------------------------------------------------------------------
# Helpers: bearer decode, caps, usage log, time helpers
# ------------------------------------------------------------------------------
def bearer_email(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    payload = verify_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload["sub"]

def _today_bounds_utc() -> Tuple[datetime, datetime]:
    now = datetime.utcnow()
    start = datetime(now.year, now.month, now.day)
    end = start + timedelta(days=1)
    return start, end

def _log_usage(db, user_id: int, endpoint: str, status_text="ok", meta: str = ""):
    try:
        db.add(UsageLog(user_id=user_id, endpoint=endpoint, status=status_text,
                        tokens_used=0, timestamp=datetime.utcnow(), meta=meta))
        db.commit()
    except Exception:
        db.rollback()

def _caps_for_tier(tier: str) -> Dict[str, int]:
    t = (tier or "demo").lower()
    def _iget(name, default):
        try: return int(os.getenv(name, str(default)))
        except: return default
    if t == "demo":
        return {"analyze_per_day": _iget("MAX_CALLS_PER_DAY_DEMO", 3),
                "chat_msgs_per_day": _iget("MAX_CALLS_PER_DAY_DEMO", 3),
                "uploads_per_day": _iget("FREE_UPLOADS", 3),
                "max_extract_chars": _iget("MAX_EXTRACT_CHARS_DEMO", 2000),
                "max_file_mb": _iget("MAX_FILE_MB_DEMO", 2)}
    if t in ("pro",):
        return {"analyze_per_day": _iget("PRO_QUERIES_PER_DAY", 50),
                "chat_msgs_per_day": _iget("MAX_CALLS_PER_DAY_PRO", 200),
                "uploads_per_day": _iget("UPLOADS_PER_DAY_PAID", 50),
                "max_extract_chars": _iget("MAX_EXTRACT_CHARS_PRO", 12000),
                "max_file_mb": _iget("MAX_FILE_MB_PRO", 15)}
    if t in ("pro+", "pro_plus"):
        return {"analyze_per_day": _iget("PRO_QUERIES_PER_DAY", 50),
                "chat_msgs_per_day": _iget("PRO_PLUS_MSGS_PER_DAY", 25),
                "uploads_per_day": _iget("UPLOADS_PER_DAY_PAID", 50),
                "max_extract_chars": _iget("MAX_EXTRACT_CHARS_PRO", 12000),
                "max_file_mb": _iget("MAX_FILE_MB_PRO", 15)}
    if t == "premium":
        return {"analyze_per_day": _iget("PRO_QUERIES_PER_DAY", 50),
                "chat_msgs_per_day": _iget("PREMIUM_MSGS_PER_DAY", 50),
                "uploads_per_day": _iget("UPLOADS_PER_DAY_PAID", 50),
                "max_extract_chars": _iget("MAX_EXTRACT_CHARS_PRO", 12000),
                "max_file_mb": _iget("MAX_FILE_MB_PRO", 15)}
    return _caps_for_tier("demo")

def _public_config_from_env() -> Dict[str, Any]:
    import json
    try:
        pricing = json.loads(os.getenv("PRICING_JSON", "")) or {}
    except Exception:
        pricing = {}
    if not pricing:
        pricing = {
            "INR": {"symbol": "₹",
                    "pro": int(os.getenv("PRO_PRICE_INR", 1999)),
                    "pro_plus": int(os.getenv("PRO_PLUS_PRICE_INR", 3999)),
                    "premium": int(os.getenv("PREMIUM_PRICE_INR", 7999))},
            "USD": {"symbol": "$",
                    "pro": int(os.getenv("PRO_PRICE_USD", 25)),
                    "pro_plus": int(os.getenv("PRO_PLUS_PRICE_USD", 49)),
                    "premium": int(os.getenv("PREMIUM_PRICE_USD", 99))}
        }
    limits = {
        "demo":   {"analyze": int(os.getenv("MAX_CALLS_PER_DAY_DEMO", 3)),
                   "chat":    int(os.getenv("MAX_CALLS_PER_DAY_DEMO", 3)),
                   "uploads": int(os.getenv("FREE_UPLOADS", 3))},
        "pro":    {"analyze": int(os.getenv("PRO_QUERIES_PER_DAY", 50)),
                   "chat":    int(os.getenv("MAX_CALLS_PER_DAY_PRO", 200)),
                   "uploads": int(os.getenv("UPLOADS_PER_DAY_PAID", 50))},
        "pro_plus":{"analyze": int(os.getenv("PRO_QUERIES_PER_DAY", 50)),
                    "chat":    int(os.getenv("PRO_PLUS_MSGS_PER_DAY", 25)),
                    "uploads": int(os.getenv("UPLOADS_PER_DAY_PAID", 50))},
        "premium":{"analyze": int(os.getenv("PRO_QUERIES_PER_DAY", 50)),
                   "chat":    int(os.getenv("PREMIUM_MSGS_PER_DAY", 50)),
                   "uploads": int(os.getenv("UPLOADS_PER_DAY_PAID", 50))}
    }
    return {
        "appName": settings.APP_NAME,
        "version": settings.VERSION,
        "positioning": os.getenv("POSITIONING_COPY"),
        "pricing": pricing,
        "limits": limits,
    }

# ------------------------------------------------------------------------------
# API router (prefix=/api) — matches your FE
# ------------------------------------------------------------------------------
api = APIRouter(prefix="/api", tags=["api"])

# ----- public config (pricing/limits for website) -----
@api.get("/public-config")
def api_public_config():
    return _public_config_from_env()

# ----- auth/profile -----
@api.post("/signup")
async def api_signup(request: Request, db=Depends(get_db)):
    # Accept JSON or form
    email = password = None
    try:
        body = await request.json()
        if isinstance(body, dict):
            email = (body.get("email") or "").strip().lower()
            password = body.get("password")
    except Exception:
        pass
    if (not email or not password) and request.headers.get("content-type","").lower().startswith("application/x-www-form-urlencoded"):
        form = await request.form()
        email = (form.get("email") or "").strip().lower()
        password = form.get("password")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    exists = db.query(User).filter(User.email == email).first()
    if exists:
        raise HTTPException(status_code=400, detail="User already exists")

    u = User(email=email, hashed_password=get_password_hash(password),
             is_admin=False, is_paid=False, created_at=datetime.utcnow())
    db.add(u); db.commit()
    return {"ok": True, "message": "Signup successful. Please log in."}

@api.post("/login", response_model=AuthToken)
def api_login(body: AuthLogin, db=Depends(get_db)):
    user = db.query(User).filter(User.email == (body.email or "").lower()).first()
    if not user or not verify_password(body.password or "", user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(sub=user.email, expires_delta=timedelta(minutes=getattr(settings, "JWT_EXPIRE_MINUTES", 120)))
    return AuthToken(access_token=token)

@api.get("/profile", response_model=Me)
def api_profile(current: User = Depends(get_current_user)):
    return Me(
        email=current.email,
        tier=(getattr(current, "plan_tier", None) or ("pro" if current.is_paid else "demo")),
        is_admin=current.is_admin,
        is_paid=current.is_paid,
    )

# ----- analyze (multi-brain) -----
@api.post("/analyze", response_model=AnalyzeResponse)  # If your schema lacks 'aggregate', extend it or drop response_model for now.
def api_analyze(doc: DocumentIn, db=Depends(get_db), current: User = Depends(get_current_user)):
    tier = (doc.tier or getattr(current, "plan_tier", None) or ("pro" if current.is_paid else "demo")).lower()
    caps = _caps_for_tier(tier)

    # daily cap
    start, end = _today_bounds_utc()
    used = db.query(UsageLog).filter(
        UsageLog.user_id == current.id,
        UsageLog.endpoint == "/api/analyze",
        UsageLog.timestamp >= start,
        UsageLog.timestamp < end,
    ).count()
    if used >= caps["analyze_per_day"]:
        raise HTTPException(status_code=429, detail=f"Daily analyze cap reached for tier '{tier}'")

    # trim content by tier
    excerpt = (doc.content or "")[:caps["max_extract_chars"]]

    # run brains
    raw_brain_outputs = []
    insights: List[Insight] = []
    for brain_name in ("CFO","COO","CHRO","CMO","CPO"):
        fn = brain_registry.get(brain_name)
        if not fn:
            continue
        out = fn({"document_excerpt": excerpt, "tier": tier})
        raw_brain_outputs.append(out)
        insights.append(
            Insight(
                role=out["role"],
                summary=out.get("summary",""),
                recommendations=out.get("recommendations", []),
            )
        )

    # aggregate (compact, UI-ready)
    agg = aggregate_brain_outputs(raw_brain_outputs, tier=tier)

    # keep your original CombinedInsights shape for backward-compat
    combined = CombinedInsights(
        document_filename=doc.filename,
        overall_summary="Combined insights across CXO brains (MVP).",
        insights=insights,
    )

    # if your Pydantic model doesn't include 'aggregate', either:
    #  1) extend CombinedInsights/AnalyzeResponse to have an optional 'aggregate: dict | None', OR
    #  2) return a plain dict and remove response_model from the decorator.
    combined_dict = combined.model_dump() if hasattr(combined, "model_dump") else combined.dict()
    combined_dict["aggregate"] = agg

    _log_usage(db, current.id, "/api/analyze", meta=f"tier={tier}")
    job_id = str(uuid.uuid4())

    # return in the same outer shape, but with 'aggregate' included under 'combined'
    return {"job_id": job_id, "combined": combined_dict}

# ----- chat: sessions/history/send (FE premium chat uses these) -----
@api.get("/chat/sessions")
def chat_sessions_list(db=Depends(get_db), current: User = Depends(get_current_user)):
    rows = (db.query(ChatSession)
              .filter(ChatSession.user_id == current.id)
              .order_by(ChatSession.created_at.desc())
              .all())
    return [{"id": r.id, "title": r.title or f"Session {r.id}", "created_at": r.created_at.isoformat()+"Z"} for r in rows]

@api.post("/chat/sessions")
def chat_sessions_create(body: Dict[str, Any] = None, db=Depends(get_db), current: User = Depends(get_current_user)):
    title = None
    if body and isinstance(body, dict):
        title = (body.get("title") or "").strip() or None
    s = ChatSession(user_id=current.id, title=title, created_at=datetime.utcnow())
    db.add(s); db.commit(); db.refresh(s)
    return {"id": s.id, "title": s.title or f"Session {s.id}", "created_at": s.created_at.isoformat()+"Z"}

@api.get("/chat/history")
def chat_history_get(session_id: int = Query(..., ge=1), db=Depends(get_db), current: User = Depends(get_current_user)):
    sess = db.query(ChatSession).filter(ChatSession.id == session_id, ChatSession.user_id == current.id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    msgs = (db.query(ChatMessage).filter(ChatMessage.session_id == sess.id).order_by(ChatMessage.created_at.asc()).all())
    return [{"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at.isoformat()+"Z"} for m in msgs]

@api.post("/chat/history")
def chat_history_append(body: Dict[str, Any], db=Depends(get_db), current: User = Depends(get_current_user)):
    session_id = int(body.get("session_id") or 0)
    role = (body.get("role") or "").strip() or "user"
    content = (body.get("content") or "").strip()
    if not session_id or not content:
        raise HTTPException(status_code=400, detail="session_id and content are required")
    sess = db.query(ChatSession).filter(ChatSession.id == session_id, ChatSession.user_id == current.id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    m = ChatMessage(session_id=sess.id, role=role, content=content, created_at=datetime.utcnow())
    db.add(m); db.commit(); db.refresh(m)
    return {"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at.isoformat()+"Z"}

@api.post("/chat/send")
def chat_send(body: Dict[str, Any], db=Depends(get_db), current: User = Depends(get_current_user)):
    """
    Body: { session_id, message }
    MVP behavior:
      - append user message
      - reply with a short assistant stub (or wire to a brain if you want)
    """
    session_id = int(body.get("session_id") or 0)
    message = (body.get("message") or "").strip()
    if not session_id or not message:
        raise HTTPException(status_code=400, detail="session_id and message are required")

    sess = db.query(ChatSession).filter(ChatSession.id == session_id, ChatSession.user_id == current.id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # user msg
    um = ChatMessage(session_id=sess.id, role="user", content=message, created_at=datetime.utcnow())
    db.add(um); db.commit()

    # assistant stub (you can route to an LLM here, or call one 'brain')
    reply = "Thanks! CAIO is processing this. (MVP stub)"
    am = ChatMessage(session_id=sess.id, role="assistant", content=reply, created_at=datetime.utcnow())
    db.add(am); db.commit(); db.refresh(am)

    _log_usage(db, current.id, "/api/chat/send", meta="stub")
    return {"reply": {"id": am.id, "role": am.role, "content": am.content, "created_at": am.created_at.isoformat()+"Z"}}

# Mount /api
app.include_router(api)

# Mount existing routers (health/admin/admin_metrics/payments/contact)
if health_router:         app.include_router(health_router)
if admin_router:          app.include_router(admin_router)
if admin_metrics_router:  app.include_router(admin_metrics_router)
if payments_router:       app.include_router(payments_router)
if contact_router:        app.include_router(contact_router)
