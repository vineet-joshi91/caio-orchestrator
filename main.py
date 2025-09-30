# -*- coding: utf-8 -*-
"""
CAIO Orchestrator Backend
 - Auth, Profile, Public Config
 - Analyze (brains + aggregator) with safe fallbacks
 - Premium Chat (sessioned) returning Markdown (no FE change needed)
 - Admin users roster & summary (added)
 - Health/Ready
"""

import os
import io
import csv
import json
import uuid
import asyncio
import traceback
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

from fastapi import (
    FastAPI, APIRouter, Depends, HTTPException, Request, Query,
    UploadFile, File, Form, Response
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel  # (added) for small admin response models
from sqlalchemy import text      # (added) for tiny updates/queries

# Optional parsers (used if available; code is resilient if missing)
try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None
try:
    import docx  # python-docx
except Exception:
    docx = None
try:
    import openpyxl  # Excel without pandas
except Exception:
    openpyxl = None

# --- Core settings/schemas/utils (your modules) ---
from caio_core.settings import settings
from caio_core.schemas import (
    DocumentIn, AnalyzeResponse, Insight, CombinedInsights,  # keep imports for compatibility
    AuthLogin, AuthToken, Me, Health
)
from caio_core.aggregation.brain_aggregator import aggregate_brain_outputs

# --- DB & auth (your modules) ---
from db import get_db, init_db, User, UsageLog, ChatSession, ChatMessage, log_usage
from auth import get_current_user, create_access_token, get_password_hash, verify_password
# NOTE: We deliberately do NOT import require_admin to avoid coupling;
# we gate admin endpoints by checking current.is_admin inline to preserve compatibility.

# --- Feature routers (optional) ---
try:
    from health import router as health_router
except Exception:
    health_router = None
try:
    from admin import router as admin_router
except Exception:
    admin_router = None
try:
    from payment import router as payments_router
except Exception:
    payments_router = None
try:
    from contact import router as contact_router
except Exception:
    contact_router = None

# --- Brains registry (your module) ---
from brains.registry import brain_registry


# ==============================================================================
# App & CORS  (stable)
# ==============================================================================
import re
app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)

# explicit allowlist for your frontend origins
ALLOWED_ORIGINS = [
    "https://caio-frontend.vercel.app",
    "http://localhost:3000",
    # add any real FE domains you use:
    # "https://caioinsights.com",
    # "https://www.caioinsights.com",
]

# also allow Vercel preview URLs by regex
ALLOW_ORIGIN_REGEX = r"^https://([a-z0-9-]+\.)?vercel\.app$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,     # explicit list
    allow_origin_regex=ALLOW_ORIGIN_REGEX,  # plus previews
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

def _set_cors_headers(resp: JSONResponse, origin: str | None):
    if not origin:
        return
    if origin in ALLOWED_ORIGINS or re.match(ALLOW_ORIGIN_REGEX, origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        vary = resp.headers.get("Vary", "")
        resp.headers["Vary"] = "Origin" if not vary else f"{vary}, Origin"

@app.middleware("http")
async def _cors_on_all(request, call_next):
    try:
        resp = await call_next(request)
    except Exception as e:
        # convert crashes to JSON so the browser shows details instead of CORS block
        resp = JSONResponse(
            status_code=500,
            content={"detail": "internal_server_error", "error": str(e)},
        )
    _set_cors_headers(resp, request.headers.get("origin"))
    return resp

@app.options("/{path:path}")
def options_ok(path: str):
    resp = JSONResponse({"ok": True})
    # make preflight succeed
    _set_cors_headers(resp, None)  # browser ignores on OPTIONS without Origin
    return resp
# ==============================================================================
# Startup warmup (DB)
# ==============================================================================
DB_READY = False
STARTUP_OK = False
STARTUP_ERR = ""

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
    global STARTUP_OK, STARTUP_ERR
    try:
        await _warmup_db()
        STARTUP_OK = True
        STARTUP_ERR = ""
    except Exception as e:
        STARTUP_OK = False
        STARTUP_ERR = str(e)[:400]


# ==============================================================================
# Small helpers
# ==============================================================================
def _log_usage(db, user_id: int, endpoint: str, status_text="ok", meta: str = ""):
    try:
        db.add(UsageLog(
            user_id=user_id,
            endpoint=endpoint,
            status=status_text,
            timestamp=datetime.utcnow(),
            meta=meta,
        ))
        db.commit()
    except Exception:
        db.rollback()

def _touch_user_last_seen(db, user_id: int):
    """Light-touch bump of last_seen, non-fatal on errors."""
    try:
        db.execute(text("UPDATE users SET last_seen = NOW() WHERE id = :uid"), {"uid": user_id})
        db.commit()
    except Exception:
        db.rollback()

def _public_config_from_env() -> Dict[str, Any]:
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
                    "premium": int(os.getenv("PREMIUM_PRICE_USD", 99))},
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
        "premium":{"analyze": int(os.getenv("PRO_QUERIES_PER_DAY", None)),
                   "chat":    int(os.getenv("PREMIUM_MSGS_PER_DAY", None)),
                   "uploads": int(os.getenv("UPLOADS_PER_DAY_PAID", None))}
    }
    return {
        "appName": settings.APP_NAME,
        "version": settings.VERSION,
        "positioning": os.getenv("POSITIONING_COPY"),
        "pricing": pricing,
        "limits": limits,
    }


# ==============================================================================
# Health/Ready
# ==============================================================================
@app.get("/health", response_model=Health)
def health():
    return Health(status="ok", version=settings.VERSION)

@app.get("/api/ready")
def api_ready():
    return {"ok": True, "db": DB_READY, "startup": STARTUP_OK}

@app.get("/api/profile")
def profile(current_user=Depends(get_current_user)):
    return {
        "email": current_user.email,
        "tier": getattr(current_user, "tier", "demo"),
        "is_admin": bool(getattr(current_user, "is_admin", False)),
        "is_paid": bool(getattr(current_user, "is_paid", False)),
        "created_at": getattr(current_user, "created_at", None),
    }
# ==============================================================================
# Public Config + Auth/Profile
# ==============================================================================
api = APIRouter(prefix="/api", tags=["api"])

@api.get("/public-config")
def api_public_config():
    return _public_config_from_env()

from fastapi.responses import JSONResponse

@api.post("/signup")
def api_signup(body: AuthLogin, request: Request, db=Depends(get_db)):
    try:
        email = (body.email or "").strip().lower()
        password = body.password or ""
        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password are required")

        # Is this user already present?
        user = db.query(User).filter(User.email.ilike(email)).first()
        if user and user.hashed_password:
            # Existing normal user
            raise HTTPException(status_code=400, detail="User already exists")

        # Create or update (idempotent)
        if not user:
            user = User(
                email=email,
                tier="demo",
                is_admin=False,
                is_paid=False,
                created_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
            db.add(user)

        # set/replace password
        user.hashed_password = get_password_hash(password)
        db.commit()
        db.refresh(user)

        # ✅ record signup success in Neon
        ip, ua = _client_meta(request)
        db.execute(
            text("SELECT public.log_auth_event(:email, 'signup', TRUE, :ip, :ua)"),
            {"email": user.email, "ip": ip, "ua": ua},
        )
        db.commit()

        # optional usage log (ignore failures)
        try:
            _log_usage(db, user_id=int(user.id), endpoint="/api/signup", status_text="ok")
        except Exception:
            db.rollback()

        return {"ok": True, "message": "Signup successful. Please log in."}

    except HTTPException as e:
        # record failed signup attempt (by email) and re-raise
        try:
            ip, ua = _client_meta(request)
            db.execute(
                text("SELECT public.log_auth_event(:email, 'signup', FALSE, :ip, :ua)"),
                {"email": (body.email or "").strip().lower(), "ip": ip, "ua": ua},
            )
            db.commit()
        except Exception:
            db.rollback()
        raise
    except Exception as e:
        # record failure but keep returning 500 like before
        try:
            ip, ua = _client_meta(request)
            db.execute(
                text("SELECT public.log_auth_event(:email, 'signup', FALSE, :ip, :ua)"),
                {"email": (body.email or "").strip().lower(), "ip": ip, "ua": ua},
            )
            db.commit()
        except Exception:
            db.rollback()
        return JSONResponse(status_code=500, content={"detail": "internal_error", "error": str(e)})

@api.post("/login", response_model=AuthToken)
def api_login(body: AuthLogin, request: Request, db=Depends(get_db)):
    email = (body.email or "").strip().lower()
    password = body.password or ""

    # --- 1) find user & verify password ---
    user = db.query(User).filter(User.email.ilike(email)).first()
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        # record FAILED login (do not let failures here mask the 401)
        try:
            ip, ua = _client_meta(request)
            db.execute(
                text("SELECT public.log_auth_event(:email, 'login', FALSE, :ip, :ua)"),
                {"email": email, "ip": ip, "ua": ua},
            )
            db.commit()
        except Exception:
            db.rollback()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # --- 2) touch activity (never fail login if this errors) ---
    try:
        _touch_user_last_seen(db, user.id)
    except Exception:
        db.rollback()

    # --- 3) create JWT ---
    # Use user.id to be unambiguous; our auth.py accepts id or email in sub.
    token = create_access_token(sub=user.id)

    # --- 4) record SUCCESS login (never fail the response on logging errors) ---
    try:
        ip, ua = _client_meta(request)
        db.execute(
            text("SELECT public.log_auth_event(:email, 'login', TRUE, :ip, :ua)"),
            {"email": user.email, "ip": ip, "ua": ua},
        )
        db.commit()
    except Exception:
        db.rollback()

    # --- 5) optional usage log (don't break flow on failures) ---
    try:
        _log_usage(db, user_id=int(user.id), endpoint="/api/login", status_text="ok")
    except Exception:
        db.rollback()

    # --- 6) return token AND set cookie so browser sends it automatically ---
    resp = JSONResponse({"access_token": token})
    try:
        from auth import set_auth_cookie
        set_auth_cookie(resp, token)
    except Exception:
        pass
    return resp

@api.get("/profile", response_model=Me)
def api_profile(current: User = Depends(get_current_user), db=Depends(get_db)):
    # bump last_seen whenever profile is fetched
    _touch_user_last_seen(db, current.id)
    tier_val = (getattr(current, "plan_tier", None) or ("pro" if getattr(current, "is_paid", False) else "demo"))
    if getattr(current, "is_admin", False):
        tier_val = "premium"
    return Me(
        email=current.email,
        tier=tier_val,
        is_admin=bool(getattr(current, "is_admin", False)),
        is_paid=bool(getattr(current, "is_paid", False)),
    )

@app.get("/debug/db")
def db_debug(db=Depends(get_db)):
    row = db.execute(text("""
        SELECT current_database()   AS db,
               current_setting('neon.project_id', true)  AS neon_project,
               current_setting('neon.branch_name', true) AS neon_branch,
               current_schema()      AS schema,
               now()                 AS server_time
    """)).mappings().one()
    users = db.execute(text("SELECT count(*) FROM public.users")).scalar()
    latest = db.execute(text("SELECT max(timestamp) FROM public.usage_logs")).scalar()
    return {"info": dict(row), "counts": {"users": users, "usage_logs_latest": str(latest)}}

#from auth import clear_auth_cookie

@api.post("/logout")
def api_logout(response: Response):
    # import lazily so app boot never crashes if auth helpers change
    try:
        from auth import clear_auth_cookie
        clear_auth_cookie(response)
    except Exception:
        # swallow: logout should never take the app down
        pass
    return JSONResponse({"ok": True})

# ==============================================================================
# Extraction helpers + formatter
# ==============================================================================
def _client_meta(request: Request):
    """Return (ip, user_agent) respecting proxy headers."""
    ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    if ip and "," in ip:  # if multiple proxies, take first hop
        ip = ip.split(",", 1)[0].strip()
    ua = request.headers.get("user-agent")
    return ip, ua

async def _extract_text_from_files(files: List[UploadFile]) -> str:
    """
    Extract text from uploaded files. Never raises. Best-effort only.
    Supports: txt, csv, pdf, docx, xlsx (if libs present). Falls back to filenames.
    """
    chunks: List[str] = []
    for f in files or []:
        try:
            name = (f.filename or "").lower()
            data = await f.read()
            await f.seek(0)
            if not data:
                continue

            if name.endswith(".txt"):
                chunks.append(data.decode("utf-8", errors="ignore"))

            elif name.endswith(".csv"):
                try:
                    text_csv = data.decode("utf-8", errors="ignore")
                    reader = csv.reader(io.StringIO(text_csv))
                    rows = []
                    for i, row in enumerate(reader):
                        if i > 200: break
                        rows.append(", ".join(row))
                    chunks.append("\n".join(rows))
                except Exception:
                    chunks.append(name)

            elif name.endswith(".pdf") and PdfReader:
                try:
                    reader = PdfReader(io.BytesIO(data))
                    pages = []
                    for i, p in enumerate(reader.pages):
                        if i >= 10: break
                        pages.append(p.extract_text() or "")
                    chunks.append("\n".join(pages))
                except Exception:
                    chunks.append(name)

            elif name.endswith(".docx") and docx:
                try:
                    d = docx.Document(io.BytesIO(data))
                    chunks.append("\n".join([p.text for p in d.paragraphs if p.text]))
                except Exception:
                    chunks.append(name)

            elif name.endswith(".xlsx") and openpyxl:
                try:
                    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
                    ws = wb.active
                    take = []
                    for r_i, row in enumerate(ws.iter_rows(values_only=True)):
                        if r_i > 200: break
                        take.append(", ".join("" if v is None else str(v) for v in row))
                    chunks.append("\n".join(take))
                except Exception:
                    chunks.append(name)

            else:
                chunks.append(name)
        except Exception:
            continue

    text = "\n\n".join([c for c in chunks if c]).strip()
    if len(text) > 16000:
        text = text[:16000]
    return text

def _fallback_recs(role: str, text: str) -> List[str]:
    t = (text or "").lower()
    recs: List[str] = []
    if role == "CFO":
        if any(k in t for k in ["p&l", "profit", "loss", "revenue", "margin"]):
            recs += [
                "Create a 13-week cash-flow with weekly variance tracking.",
                "Shift 10–15% budget to highest ROI channels; freeze low-ROAS lines.",
            ]
        else:
            recs += [
                "Upload P&L, balance sheet, and cash ledger for last 12 months.",
                "Define target runway and cost guardrails; propose a 90-day budget.",
            ]
    elif role == "COO":
        recs += [
            "Map top 5 bottlenecks with owners, SLAs, and weekly review.",
            "Stand up an ops dashboard: throughput, defects, backlog, SLA.",
        ]
    elif role == "CHRO":
        recs += [
            "Run a 9-box talent review; publish 2-role deep succession slates.",
            "Quarterly calibration; simplify ratings to 3 bands tied to pay.",
        ]
    elif role == "CMO":
        recs += [
            "Audit CAC/LTV by channel; reallocate 15% from bottom quartile to top.",
            "Spin up win/loss + ICP refresh from 5 recent customer calls.",
        ]
    elif role == "CPO":
        recs += [
            "Define 3 outcomes; align people roles with job metrics.",
            "Weekly discovery cadence; 5 user interviews per cycle.",
        ]
    return recs

def _format_analyze_to_cxo_md(resp: Dict[str, Any]) -> str:
    """
    Turn analyze JSON into markdown for chat:
      ## CFO
      ### Insights
      1. ...
      ### Recommendations
      1. ...
    """
    combined = resp.get("combined") or {}
    agg = combined.get("aggregate") or {}
    collective = (
        resp.get("collective_insights")
        or agg.get("collective")
        or agg.get("collective_insights")
        or []
    )
    recs_by_role = (
        resp.get("recommendations_by_role")
        or resp.get("cxo_recommendations")
        or agg.get("recommendations_by_role")
        or agg.get("cxo_recommendations")
        or {}
    )

    # Build role-insights from CombinedInsights.insights[]
    role_insights: Dict[str, List[str]] = {r: [] for r in ["CFO", "CHRO", "COO", "CMO", "CPO"]}
    try:
        for it in (combined.get("insights") or []):
            r = (it.get("role") or "").upper()
            if r in role_insights:
                s = (it.get("summary") or "").strip()
                if s:
                    role_insights[r].append(s)
    except Exception:
        pass

    # Fallback: if a role has no insights, seed from collective (first 2)
    for r in role_insights:
        if not role_insights[r] and collective:
            role_insights[r] = list(collective[:2])

    for r in ["CFO", "CHRO", "COO", "CMO", "CPO"]:
        recs_by_role.setdefault(r, [])

    lines: List[str] = []
    for role in ["CFO", "CHRO", "COO", "CMO", "CPO"]:
        lines.append(f"## {role}")
        lines.append("### Insights")
        ins = [x for x in role_insights.get(role, []) if x]
        if ins:
            for i, item in enumerate(ins[:6], 1):
                lines.append(f"{i}. {item}")
        else:
            lines.append("- No material evidence in the provided context.")
        lines.append("")
        lines.append("### Recommendations")
        recs = [x for x in (recs_by_role.get(role) or []) if x]
        if recs:
            for i, item in enumerate(recs[:6], 1):
                lines.append(f"{i}. {item}")
        else:
            lines.append("- No actionable data found.")
        lines.append("")
    return "\n".join(lines).strip()


# ==============================================================================
# Analyze core (shared by API + chat)
# ==============================================================================
DEBUG_VERBOSE = bool(os.getenv("DEBUG_VERBOSE", "0") == "1")

async def _run_analyze_from_content(content: str, filename: str, tier: str) -> Dict[str, Any]:
    """
    Core analyze logic. Returns dict: {"job_id": str, "combined": {...}}
    Never raises. Ensures at least 1 recommendation per role and mirrors into details.
    """
    job_id = str(uuid.uuid4())
    dbg: Dict[str, Any] = {"phase": "start", "tier": tier, "filename": filename}

    try:
        if not content:
            raise ValueError("No content provided for analysis.")
        excerpt = content[:16000]
        dbg["phase"] = "brains"

        # Run brains
        raw: List[Dict[str, Any]] = []
        for role in ("CFO", "CHRO", "COO", "CMO", "CPO"):
            fn = brain_registry.get(role)
            if not fn:
                continue
            try:
                out = fn({"document_excerpt": excerpt, "tier": tier}) or {}
                if isinstance(out, dict) and not out.get("role"):
                    out["role"] = role
                raw.append(out)
            except Exception as e:
                raw.append({"role": role, "summary": "", "recommendations": [], "error": str(e)})

        dbg["phase"] = "aggregate"

        # Aggregate
        try:
            combined: Dict[str, Any] = aggregate_brain_outputs(raw, document_filename=filename) or {}
        except Exception as e:
            combined = {
                "overall_summary": "",
                "insights": [],
                "aggregate": {},
                "details_by_role": {},
                "error": str(e),
            }
            if DEBUG_VERBOSE:
                combined["debug"] = {"aggregate_error": str(e), "trace": traceback.format_exc()}

        # Guarantees: recommendations & mirroring
        agg = combined.get("aggregate") or {}
        recs_by_role: Dict[str, List[str]] = dict(
            (agg.get("recommendations_by_role") or agg.get("cxo_recommendations") or {})
        )
        for role in ("CFO", "CHRO", "COO", "CMO", "CPO"):
            lst = list(recs_by_role.get(role) or [])
            if not lst:
                first = None
                src = next((r for r in raw if (r.get("role") or "").upper() == role), None)
                if src:
                    arr = list(src.get("recommendations") or [])
                    if arr:
                        first = arr[0]
                if not first:
                    try:
                        fb = _fallback_recs(role, excerpt)
                        if fb:
                            first = fb[0]
                    except Exception:
                        pass
                if first:
                    recs_by_role[role] = [first]
        agg["recommendations_by_role"] = recs_by_role
        agg.setdefault("cxo_recommendations", recs_by_role)
        combined["aggregate"] = agg

        details = combined.setdefault("details_by_role", {})
        for role in ("CFO", "CHRO", "COO", "CMO", "CPO"):
            block = details.get(role) or {}
            if not (block.get("recommendations") or []):
                first = (recs_by_role.get(role) or [None])[0]
                if first:
                    block["recommendations"] = [first]
                    details[role] = block
        combined["details_by_role"] = details

        # --- Ensure Collective Insights (2–3 items) --------------------------
        agg = combined.get("aggregate") or {}
        collective = list(
            agg.get("collective")
            or agg.get("collective_insights")
            or combined.get("collective_insights")
            or []
        )
        if not collective:
            # Try to harvest from CombinedInsights.insights[] (role summaries)
            try:
                pool = []
                for it in (combined.get("insights") or []):
                    s = (it.get("summary") or "").strip()
                    if s:
                        pool.append(s)
                collective = pool[:3]
            except Exception:
                pass
        if not collective:
            # Split overall_summary into sentences
            try:
                txt = (combined.get("overall_summary") or "").strip()
                if txt:
                    parts = [p.strip() for p in txt.replace("\n", " ").split(".") if p.strip()]
                    collective = parts[:3]
            except Exception:
                pass
        if not collective:
            # Fall back to first recs across roles, labeled
            try:
                tmp = []
                recs_by_role = (
                    agg.get("recommendations_by_role")
                    or agg.get("cxo_recommendations")
                    or {}
                )
                for role in ("CFO", "CHRO", "COO", "CMO", "CPO"):
                    first = (recs_by_role.get(role) or [None])[0]
                    if first:
                        tmp.append(f"{role}: {first}")
                    if len(tmp) >= 3:
                        break
                collective = tmp
            except Exception:
                pass

        # Final write-back in both canonical spots the FE may read
        agg["collective"] = collective
        agg["collective_insights"] = collective
        combined["aggregate"] = agg
        combined["collective_insights"] = collective

        if DEBUG_VERBOSE:
            combined.setdefault("debug", {})["dbg"] = dbg

        return {"job_id": job_id, "combined": combined}

    except Exception as e:
        safe_combined: Dict[str, Any] = {
            "overall_summary": "",
            "insights": [],
            "aggregate": {},
            "details_by_role": {},
            "error": str(e),
        }
        if DEBUG_VERBOSE:
            safe_combined["debug"] = {"fatal": str(e), "trace": traceback.format_exc(), "dbg": dbg}
        return {"job_id": job_id, "combined": safe_combined}


# ==============================================================================
# Analyze API
# ==============================================================================
@api.post("/analyze")  # <- no response_model to avoid 500s from schema mismatches
async def api_analyze(
    request: Request,
    doc: Optional[DocumentIn] = None,          # JSON path
    text: Optional[str] = Form(None),          # multipart path
    file: Optional[UploadFile] = File(None),
    files: Optional[List[UploadFile]] = File(None),
    db=Depends(get_db),
    current: User = Depends(get_current_user),
):
    # Normalize input -> content, filename, tier
    ct = (request.headers.get("content-type") or "").lower()
    is_multipart = "multipart/form-data" in ct or (text is not None) or (file is not None) or (files is not None)

    tier = ("premium" if getattr(current, "is_admin", False)
            else ("pro" if getattr(current, "is_paid", False) else "demo"))

    if is_multipart:
        flist: List[UploadFile] = []
        if file is not None: flist.append(file)
        if files: flist.extend(files)
        appendix = await _extract_text_from_files(flist)
        content = ((text or "") + (("\n\n" + appendix) if appendix else "")).strip()
        filename = "input.txt"
        for f in flist:
            if getattr(f, "filename", None):
                filename = f.filename
                break
    else:
        if doc is None:
            try:
                body = await request.json()
            except Exception:
                raise HTTPException(status_code=415, detail="Unsupported content-type. Send JSON or multipart/form-data.")
            try:
                doc = DocumentIn(**(body or {}))
            except Exception:
                raise HTTPException(status_code=422, detail="Invalid payload for DocumentIn.")
        content = (doc.content or "").strip()
        filename = doc.filename or "input.txt"
        tier = (doc.tier or tier).lower()

    if not content:
        raise HTTPException(status_code=400, detail="No content provided for analysis.")

    result = await _run_analyze_from_content(content, filename, tier)
    _touch_user_last_seen(db, current.id)  # bump activity
    _log_usage(db, current.id, "/api/analyze", "ok")
    return JSONResponse(result, status_code=200)


# ==============================================================================
# Chat (sessions/history/send)
# ==============================================================================
@api.get("/chat/sessions")
def chat_sessions_list(db=Depends(get_db), current: User = Depends(get_current_user)):
    _touch_user_last_seen(db, current.id)
    rows = (
        db.query(ChatSession)
        .filter(ChatSession.user_id == current.id)
        .order_by(ChatSession.created_at.desc())
        .all()
    )
    return [{"id": r.id, "title": r.title or f"Session {r.id}", "created_at": r.created_at.isoformat() + "Z"} for r in rows]

@api.post("/chat/sessions")
def chat_sessions_create(body: Dict[str, Any] = None, db=Depends(get_db), current: User = Depends(get_current_user)):
    _touch_user_last_seen(db, current.id)
    title = None
    if body and isinstance(body, dict):
        title = (body.get("title") or "").strip() or None
    s = ChatSession(user_id=current.id, title=title, created_at=datetime.utcnow())
    db.add(s); db.commit(); db.refresh(s)
    return {"id": s.id, "title": s.title or f"Session {s.id}", "created_at": s.created_at.isoformat() + "Z"}

@api.get("/chat/history")
def chat_history_get(session_id: int = Query(..., ge=1), db=Depends(get_db), current: User = Depends(get_current_user)):
    _touch_user_last_seen(db, current.id)
    sess = db.query(ChatSession).filter(ChatSession.id == session_id, ChatSession.user_id == current.id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    msgs = db.query(ChatMessage).filter(ChatMessage.session_id == sess.id).order_by(ChatMessage.created_at.asc()).all()
    return [{"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at.isoformat() + "Z"} for m in msgs]

@api.post("/chat/history")
def chat_history_append(body: Dict[str, Any], db=Depends(get_db), current: User = Depends(get_current_user)):
    _touch_user_last_seen(db, current.id)
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
    return {"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at.isoformat() + "Z"}

@api.post("/chat/send")
async def chat_send(
    session_id: Optional[int] = Form(None),
    message: Optional[str] = Form(None),
    files: Optional[List[UploadFile]] = File(None),
    db=Depends(get_db),
    current: User = Depends(get_current_user),
):
    """
    Accepts multipart (message + files), extracts text, runs analyze core directly,
    stores user + assistant messages, and returns **Markdown** (and raw JSON) for FE.
    """
    _touch_user_last_seen(db, current.id)

    # 1) ensure/create session
    if session_id:
        sess = (
            db.query(ChatSession)
            .filter(ChatSession.id == int(session_id), ChatSession.user_id == current.id)
            .first()
        )
        if not sess:
            raise HTTPException(status_code=404, detail="Session not found")
        sess_id = int(sess.id)
    else:
        sess = ChatSession(user_id=current.id, title=None, created_at=datetime.utcnow())
        db.add(sess); db.commit(); db.refresh(sess)
        sess_id = int(sess.id)

    # 2) persist user message
    msg_text = (message or "").strip()
    filenames = [f.filename for f in (files or []) if getattr(f, "filename", None)]

    if not msg_text and not filenames:
        raise HTTPException(status_code=400, detail="Provide a message or at least one file.")

    user_content = msg_text or "(file only)"
    if filenames:
        user_content += f"\n\n[files: {', '.join(filenames)}]"

    um = ChatMessage(session_id=sess_id, role="user", content=user_content, created_at=datetime.utcnow())
    db.add(um); db.commit(); db.refresh(um)

    # 3) analysis input
    appendix = await _extract_text_from_files(files or [])
    combined_text = (msg_text + "\n\n" + appendix).strip() if appendix else msg_text

    if not combined_text:
        fallback = ChatMessage(
            session_id=sess_id,
            role="assistant",
            content="Got your file(s). Please add a brief question/context to start analysis.",
            created_at=datetime.utcnow(),
        )
        db.add(fallback); db.commit(); db.refresh(fallback)
        _log_usage(db, current.id, "/api/chat/send", meta=f"files={len(filenames)}")
        return {
            "session_id": sess_id,
            "assistant": {
                "id": int(fallback.id),
                "role": "assistant",
                "content": fallback.content,
                "created_at": fallback.created_at.isoformat() + "Z",
            },
        }

    # 4) Run analyze core (no internal HTTP)
    tier_for_analysis = "premium" if getattr(current, "is_admin", False) else ("pro" if getattr(current, "is_paid", False) else "demo")
    analysis_dict = await _run_analyze_from_content(
        combined_text,
        filenames[0] if filenames else "input.txt",
        tier_for_analysis,
    )

    # 5) Build Markdown for chat bubble
    reply_md = _format_analyze_to_cxo_md(analysis_dict).strip()
    if not reply_md:
        # Minimal fallback
        combined = analysis_dict.get("combined", {}) or {}
        agg = (combined.get("aggregate") or {})
        collective = (
            analysis_dict.get("collective_insights")
            or agg.get("collective")
            or agg.get("collective_insights")
            or []
        )
        by_role = (
            analysis_dict.get("recommendations_by_role")
            or analysis_dict.get("cxo_recommendations")
            or agg.get("recommendations_by_role")
            or agg.get("cxo_recommendations")
            or {}
        )
        lines = []
        if collective:
            lines.append("## Collective Insights")
            for i, c in enumerate(collective[:10], 1):
                lines.append(f"{i}. {c}")
            lines.append("")
        for role in ["CFO", "CHRO", "COO", "CMO", "CPO"]:
            recs = list(by_role.get(role) or [])
            lines.append(f"## {role}")
            if recs:
                for i, r in enumerate(recs[:6], 1):
                    lines.append(f"{i}. {r}")
            else:
                lines.append("_No actionable data found._")
            lines.append("")
        reply_md = "\n".join(lines).strip()

    reply_content = reply_md if reply_md else "No actionable data found."

    # 6) assistant message
    am = ChatMessage(session_id=sess_id, role="assistant", content=reply_content, created_at=datetime.utcnow())
    db.add(am); db.commit(); db.refresh(am)

    _log_usage(db, current.id, "/api/chat/send", meta=f"files={len(filenames)};md=true")

    return {
        "session_id": sess_id,
        "assistant": {
            "id": int(am.id),
            "role": am.role,
            "content": am.content,      # markdown
            "content_json": analysis_dict,  # raw JSON for FE if needed
            "created_at": am.created_at.isoformat() + "Z",
        },
    }


# ==============================================================================
# Admin: Users roster & summary (added; gated by current.is_admin)
# ==============================================================================
class AdminUserOut(BaseModel):
    id: int
    email: str
    username: Optional[str] = None
    tier: str
    is_admin: bool
    is_test: bool
    is_paid: bool
    created_on: Optional[str] = None
    last_seen: Optional[str] = None
    total_sessions: int

class AdminUsersOut(BaseModel):
    items: List[AdminUserOut]
    page: int
    page_size: int
    total: int
    counters: Dict[str, int]

@api.get("/admin/users", response_model=AdminUsersOut)
def admin_users(
    q: str = Query("", description="search by email/username"),
    page: int = 1,
    page_size: int = 25,
    include_test: bool = False,
    include_admins: bool = True,
    db=Depends(get_db),
    current: User = Depends(get_current_user),
):
    if not bool(getattr(current, "is_admin", False)):
        raise HTTPException(status_code=403, detail="Admin only")

    q = (q or "").strip().lower()
    offset = max(0, (page - 1) * page_size)

    filters = ["1=1"]
    params = {"limit": page_size, "offset": offset}
    if q:
        filters.append("(lower(u.email) LIKE :qq OR lower(u.username) LIKE :qq)")
        params["qq"] = f"%{q}%"
    if not include_test:
        filters.append("COALESCE(u.is_test,false) = FALSE")
    if not include_admins:
        filters.append("COALESCE(u.is_admin,false) = FALSE")

    where = " AND ".join(filters)
    profile_select = """
      SELECT u.id, u.email, u.username, COALESCE(u.tier,'demo') AS tier,
             COALESCE(u.is_admin,false) AS is_admin,
             COALESCE(u.is_test,false)  AS is_test,
             COALESCE(u.is_paid,false)  AS is_paid,
             u.created_at, u.last_seen,
             COALESCE(s.sessions,0) AS total_sessions
      FROM users u
      LEFT JOIN (
        SELECT user_id, COUNT(*)::int AS sessions
        FROM chat_sessions
        GROUP BY user_id
      ) s ON s.user_id = u.id
    """

    rows = db.execute(text(f"""
      {profile_select}
      WHERE {where}
      ORDER BY u.last_seen DESC NULLS LAST, u.created_at DESC
      LIMIT :limit OFFSET :offset
    """), params).mappings().all()

    count_row = db.execute(text(f"""
      SELECT COUNT(*) AS c FROM users u
      WHERE {where}
    """), params).mappings().first()

    counts = db.execute(text("""
      SELECT
        COUNT(*) FILTER (WHERE is_test = FALSE AND COALESCE(is_admin,false)=FALSE) AS real_users,
        COUNT(*) FILTER (WHERE is_test = TRUE)  AS test_users,
        COUNT(*) FILTER (WHERE is_admin = TRUE) AS admins,
        COUNT(*) FILTER (WHERE tier='demo')     AS demo,
        COUNT(*) FILTER (WHERE tier='pro')      AS pro,
        COUNT(*) FILTER (WHERE tier IN ('pro+','pro_plus')) AS pro_plus,
        COUNT(*) FILTER (WHERE tier='premium')  AS premium
      FROM users
    """)).mappings().one()

    def map_row(r):
        return {
            "id": r["id"],
            "email": r["email"],
            "username": r.get("username"),
            "tier": r.get("tier"),
            "is_admin": bool(r.get("is_admin")),
            "is_test": bool(r.get("is_test")),
            "is_paid": bool(r.get("is_paid")),
            "created_on": r["created_at"].isoformat() + "Z" if r.get("created_at") else None,
            "last_seen":  r["last_seen"].isoformat() + "Z" if r.get("last_seen") else None,
            "total_sessions": int(r.get("total_sessions") or 0),
        }

    return {
        "items": [map_row(r) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": int(count_row["c"] if count_row else 0),
        "counters": {k: int(v) for k, v in dict(counts).items()} if counts else {},
    }

@api.get("/admin/users/summary")
def admin_users_summary(db=Depends(get_db), current: User = Depends(get_current_user)):
    if not bool(getattr(current, "is_admin", False)):
        raise HTTPException(status_code=403, detail="Admin only")
    row = db.execute(text("""
      SELECT
        COUNT(*) FILTER (WHERE is_test = FALSE AND COALESCE(is_admin,false)=FALSE) AS real_users,
        COUNT(*) FILTER (WHERE is_test = TRUE)  AS test_users,
        COUNT(*) FILTER (WHERE is_admin = TRUE) AS admins,
        COUNT(*) FILTER (WHERE tier='demo')     AS demo,
        COUNT(*) FILTER (WHERE tier='pro')      AS pro,
        COUNT(*) FILTER (WHERE tier IN ('pro+','pro_plus')) AS pro_plus,
        COUNT(*) FILTER (WHERE tier='premium')  AS premium
      FROM users
    """)).mappings().one()
    return {k: int(v) for k, v in dict(row).items()}

# --- Feature routers (optional) ---
try:
    from admin_metrics import router as admin_metrics_router
except Exception as e:
    admin_metrics_router = None
    print("WARNING: admin_metrics NOT loaded:", repr(e))

# ==============================================================================
# Mount routers
# ==============================================================================
app.include_router(api)
if health_router:         app.include_router(health_router)
if admin_router:          app.include_router(admin_router)
if admin_metrics_router:  app.include_router(admin_metrics_router)
if payments_router:       app.include_router(payments_router)
if contact_router:        app.include_router(contact_router)
