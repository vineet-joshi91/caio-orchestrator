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
import io

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Header, Request, Query, UploadFile, File, Form, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from caio_core.aggregation.brain_aggregator import aggregate_brain_outputs

try:
    import pandas as pd
except Exception:
    pd = None
try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None
try:
    import docx  # python-docx
except Exception:
    docx = None

import httpx  # used to call our own FastAPI app internally

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
from brains.registry import brain_registry

# ------------------------------------------------------------------------------
# App + CORS
# ------------------------------------------------------------------------------
app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)

allowed = settings.ALLOWED_ORIGINS_LIST  # safe list
# if you want a permissive fallback in DEBUG:
if not allowed and getattr(settings, "DEBUG", False):
    allowed = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
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

def _safe_head(df, n=20):
    try:
        return df.head(n).to_markdown(index=False)
    except Exception:
        return df.head(n).to_string(index=False)

async def _extract_text_from_files(files: Optional[List[UploadFile]]) -> str:
    """
    Best-effort text extraction. Works even if some libs are missing.
    Limits per-file bytes/pages to keep request small.
    """
    if not files:
        return ""
    chunks: List[str] = []
    for f in files:
        name = (f.filename or "file").strip()
        lower = name.lower()
        try:
            raw = await f.read()
        except Exception:
            continue

        # cap size (~3MB) to avoid memory/token blowups
        if len(raw) > 3_000_000:
            raw = raw[:3_000_000]

        # PDF
        if lower.endswith(".pdf") and PdfReader is not None:
            try:
                reader = PdfReader(io.BytesIO(raw))
                pages = min(len(reader.pages), 10)
                text = []
                for i in range(pages):
                    text.append(reader.pages[i].extract_text() or "")
                chunks.append(f"\n\n# [PDF] {name}\n" + "\n".join(text))
                continue
            except Exception:
                pass

        # DOCX
        if lower.endswith(".docx") and docx is not None:
            try:
                d = docx.Document(io.BytesIO(raw))
                text = "\n".join([p.text for p in d.paragraphs if p.text.strip()])[:15000]
                chunks.append(f"\n\n# [DOCX] {name}\n{text}")
                continue
            except Exception:
                pass

        # CSV
        if lower.endswith(".csv") and pd is not None:
            try:
                df = pd.read_csv(io.BytesIO(raw))
                preview = _safe_head(df)
                try:
                    desc = df.describe(include="all").to_markdown()
                except Exception:
                    desc = ""
                chunks.append(f"\n\n# [CSV] {name}\n## preview\n{preview}\n\n## describe\n{desc}")
                continue
            except Exception:
                pass

        # XLS/XLSX
        if (lower.endswith(".xlsx") or lower.endswith(".xls")) and pd is not None:
            try:
                excel = pd.ExcelFile(io.BytesIO(raw))
                sheet_names = excel.sheet_names[:5]
                parts = [f"Sheets: {', '.join(sheet_names)}"]
                for s in sheet_names:
                    df = excel.parse(s)
                    preview = _safe_head(df)
                    parts.append(f"\n### sheet: {s}\n{preview}")
                chunks.append(f"\n\n# [XLSX] {name}\n" + "\n".join(parts))
                continue
            except Exception:
                pass

        # TXT / fallback
        try:
            txt = raw.decode("utf-8", errors="ignore")[:20000]
            chunks.append(f"\n\n# [TEXT] {name}\n{txt}")
        except Exception:
            pass

    return "\n".join(chunks).strip()

def _format_analyze_to_cxo_md(resp: Dict[str, Any]) -> str:
    """
    Convert /api/analyze JSON into the CXO markdown your chat UI expects.
    - Collective Insights (top)
    - Then ## CFO/CHRO/COO/CMO/CPO with ### Recommendations bullets
    """
    lines: List[str] = []

    ci = resp.get("collective_insights") or []
    if ci:
        lines.append("## Collective Insights")
        for i, item in enumerate(ci[:10], 1):
            lines.append(f"{i}. {item}")
        lines.append("")

    recs = (resp.get("cxo_recommendations") or {})
    for role in ["CFO", "CHRO", "COO", "CMO", "CPO"]:
        rlist = recs.get(role) or []
        lines.append(f"## {role}")
        if rlist:
            lines.append("### Recommendations")
            for i, r in enumerate(rlist, 1):
                lines.append(f"{i}. {r}")
        else:
            lines.append("_No recommendations._")
        lines.append("")

    return "\n".join(lines).strip()

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
    tier_val = (getattr(current, "plan_tier", None) or ("pro" if getattr(current, "is_paid", False) else "demo"))
    if getattr(current, "is_admin", False):
        tier_val = "premium"

    return Me(
        email=current.email,
        tier=tier_val,
        is_admin=bool(getattr(current, "is_admin", False)),
        is_paid=bool(getattr(current, "is_paid", False)),
    )

# --- add under the "auth/profile" section in main.py ---

def _is_admin_email(email: str) -> bool:
    """
    Accept both single ADMIN_EMAIL and comma-separated ADMIN_EMAILS.
    True if DB flag is_admin or email is in allowlist.
    """
    if not email:
        return False
    email = email.strip().lower()
    admin_one = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    admin_many = [e.strip().lower() for e in (os.getenv("ADMIN_EMAILS") or "").split(",") if e.strip()]
    return (email == admin_one) or (email in admin_many)

@api.get("/whoami")
def api_whoami(current: User = Depends(get_current_user)):
    """
    Returns who the caller is, with an admin flag that also honors env allowlist.
    Frontend will use this to redirect admins to Premium Chat.
    """
    tier = (getattr(current, "plan_tier", None) or ("pro" if current.is_paid else "demo")).lower()
    is_admin = bool(getattr(current, "is_admin", False) or _is_admin_email(current.email))

    # Optional: represent admins as 'premium' on the UI, but expose is_admin=true
    if is_admin:
        tier = "premium"

    return {
        "email": current.email,
        "tier": tier,
        "is_admin": is_admin
    }

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

from fastapi import UploadFile, File, Form

@api.post("/chat/send")
async def chat_send(
    session_id: Optional[int] = Form(None),
    message: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None),
    db=Depends(get_db),
    current: User = Depends(get_current_user),
):
    """
    - Accepts multipart (message + files)
    - Ensures/creates a chat session
    - Extracts useful text from files
    - Calls our own /api/analyze internally for CXO output
    - Returns assistant message containing CXO-formatted markdown
    """
    # 1) ensure/create session
    if session_id:
        sess = (
            db.query(ChatSession)
            .filter(ChatSession.id == int(session_id), ChatSession.user_id == current.id)
            .first()
        )
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
    else:
        sess = ChatSession(user_id=current.id, title=None, created_at=datetime.utcnow())
        db.add(sess)
        db.commit()
        db.refresh(sess)

    # 2) persist user message (with filenames note if any)
    msg_text = (message or "").strip()
    filenames = [f.filename for f in (files or []) if getattr(f, "filename", None)]

    if not msg_text and not filenames:
        raise HTTPException(status_code=400, detail="Provide a message or at least one file.")

    user_content = msg_text or "(file only)"
    if filenames:
        user_content += f"\n\n[files: {', '.join(filenames)}]"

    um = ChatMessage(session_id=sess.id, role="user", content=user_content, created_at=datetime.utcnow())
    db.add(um)
    db.commit()
    db.refresh(um)

    # 3) build analysis input: message + extracted file text
    appendix = await _extract_text_from_files(files)
    combined_text = (msg_text + "\n\n" + appendix).strip() if appendix else msg_text

    # If truly nothing to analyze (e.g., only a binary we couldn't read), acknowledge
    if not combined_text:
        am = ChatMessage(
            session_id=sess.id,
            role="assistant",
            content="Got your file(s). Please add a brief question/context to start analysis.",
            created_at=datetime.utcnow(),
        )
        db.add(am); db.commit(); db.refresh(am)
        return {
            "session_id": sess.id,
            "assistant": {
                "id": am.id,
                "role": am.role,
                "content": am.content,
                "created_at": am.created_at.isoformat() + "Z",
            },
        }

    # 4) call our own /api/analyze internally (no external HTTP hop)
    #    Treat admins as premium; otherwise use user's plan
    tier_for_analysis = "premium" if getattr(current, "is_admin", False) else ("pro" if getattr(current, "is_paid", False) else "demo")
    payload = {"text": combined_text, "tier": tier_for_analysis, "want_deep_dive": True}

    try:
        async with httpx.AsyncClient(app=app, base_url="http://internal") as client:
            r = await client.post("/api/analyze", json=payload, timeout=120.0)
        if not r.is_success:
            body = r.text
            raise RuntimeError(f"/api/analyze {r.status_code}: {body[:500]}")
        analysis = r.json()
        reply_md = _format_analyze_to_cxo_md(analysis)
        reply = reply_md if reply_md.strip() else "No recommendations were generated."
    except Exception as e:
        # graceful fallback; still reply something
        reply = f"Received {len(filenames)} file(s). Could not run full analysis.\n\nError: {e}"

    # 5) store assistant message & respond
    am = ChatMessage(session_id=sess.id, role="assistant", content=reply, created_at=datetime.utcnow())
    db.add(am); db.commit(); db.refresh(am)

    _log_usage(db, current.id, "/api/chat/send", meta=f"files={len(filenames)}")

    return {
        "session_id": sess.id,
        "assistant": {
            "id": am.id,
            "role": am.role,
            "content": am.content,
            "created_at": am.created_at.isoformat() + "Z",
        },
    }

# Mount /api
app.include_router(api)

# Mount existing routers (health/admin/admin_metrics/payments/contact)
if health_router:         app.include_router(health_router)
if admin_router:          app.include_router(admin_router)
if admin_metrics_router:  app.include_router(admin_metrics_router)
if payments_router:       app.include_router(payments_router)
if contact_router:        app.include_router(contact_router)
