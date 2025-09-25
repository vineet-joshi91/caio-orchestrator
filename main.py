# -*- coding: utf-8 -*-
"""
CAIO Orchestrator Backend
 - Auth, Profile, Public Config
 - Analyze (brains + aggregator) with safe fallbacks
 - Premium Chat (sessioned) returning Markdown (no FE change needed)
 - Health/Ready
"""

import os
import io
import csv
import json
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

from fastapi import (
    FastAPI, APIRouter, Depends, HTTPException, Request, Query,
    UploadFile, File, Form
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

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
    DocumentIn, AnalyzeResponse, Insight, CombinedInsights,
    AuthLogin, AuthToken, Me, Health
)
from caio_core.aggregation.brain_aggregator import aggregate_brain_outputs

# --- DB & auth (your modules) ---
from db import get_db, init_db, User, UsageLog, ChatSession, ChatMessage
from auth import get_current_user, create_access_token, get_password_hash, verify_password

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
    from admin_metrics import router as admin_metrics_router
except Exception:
    admin_metrics_router = None
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
# App & CORS  (ironclad)
# ==============================================================================
# App & CORS
app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)

def _parse_origins(val):
    if isinstance(val, (list, tuple, set)):
        return [str(x).strip() for x in val if str(x).strip()]
    if isinstance(val, str):
        return [p.strip() for p in val.split(",") if p.strip()]
    return []

allowed = _parse_origins(getattr(settings, "ALLOWED_ORIGINS_LIST", None))
if not allowed:
    allowed = _parse_origins(os.getenv("ALLOWED_ORIGINS", ""))

allow_origin_regex = (
    r"^(https://caio-frontend\.vercel\.app"
    r"|http://localhost:3000"
    r"|https://caioai\.netlify\.app)$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed,
    allow_origin_regex=allow_origin_regex,  # belt & suspenders
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.options("/{path:path}")
def options_ok(path: str):
    return PlainTextResponse("ok")

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
        try:
            return int(os.getenv(name, str(default)))
        except Exception:
            return default
    if t == "demo":
        return {"analyze_per_day": _iget("MAX_CALLS_PER_DAY_DEMO", 3),
                "chat_msgs_per_day": _iget("MAX_CALLS_PER_DAY_DEMO", 3),
                "uploads_per_day": _iget("FREE_UPLOADS", 3),
                "max_extract_chars": _iget("MAX_EXTRACT_CHARS_DEMO", 2000),
                "max_file_mb": _iget("MAX_FILE_MB_DEMO", 2)}
    if t == "pro":
        return {"analyze_per_day": _iget("PRO_QUERIES_PER_DAY", 50),
                "chat_msgs_per_day": _iget("MAX_CALLS_PER_DAY_PRO", 200),
                "uploads_per_day": _iget("UPLOADS_PER_DAY_PAID", 50),
                "max_extract_chars": _iget("MAX_EXTRACT_CHARS_PRO", 12000),
                "max_file_mb": _iget("MAX_FILE_MB_PRO", 15)}
    if t in ("pro_plus", "pro+"):
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


# ==============================================================================
# Health/Ready
# ==============================================================================
@app.get("/health", response_model=Health)
def health():
    return Health(status="ok", version=settings.VERSION)

@app.get("/version")
def version():
    return {"version": settings.VERSION}

@app.get("/api/ready")
def api_ready():
    return {"ok": True, "db": DB_READY, "startup": STARTUP_OK}


# ==============================================================================
# Public Config + Auth/Profile
# ==============================================================================
api = APIRouter(prefix="/api", tags=["api"])

@api.get("/public-config")
def api_public_config():
    return _public_config_from_env()

@api.post("/signup")
async def api_signup(request: Request, db=Depends(get_db)):
    email = password = None
    try:
        body = await request.json()
        if isinstance(body, dict):
            email = (body.get("email") or "").strip().lower()
            password = body.get("password")
    except Exception:
        pass
    if (not email or not password) and request.headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
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
    token = create_access_token(
        sub=user.email, expires_delta=timedelta(minutes=getattr(settings, "JWT_EXPIRE_MINUTES", 120))
    )
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

def _is_admin_email(email: str) -> bool:
    if not email:
        return False
    email = email.strip().lower()
    admin_one = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    admin_many = [e.strip().lower() for e in (os.getenv("ADMIN_EMAILS") or "").split(",") if e.strip()]
    return (email == admin_one) or (email in admin_many)

@api.get("/whoami")
def api_whoami(current: User = Depends(get_current_user)):
    tier = (getattr(current, "plan_tier", None) or ("pro" if current.is_paid else "demo")).lower()
    is_admin = bool(getattr(current, "is_admin", False) or _is_admin_email(current.email))
    if is_admin:
        tier = "premium"
    return {"email": current.email, "tier": tier, "is_admin": is_admin}

@api.get("/_echo/ready")
def echo_ready(request: Request):
    return {"ok": True, "origin": request.headers.get("origin")}

@api.post("/analyze/echo")
async def analyze_echo(request: Request):
    return {
        "ok": True,
        "content_type": request.headers.get("content-type"),
        "has_auth": bool(request.headers.get("authorization")),
    }

# ==============================================================================
# Brains + Analyze
# ==============================================================================
def _safe_head_rows(rows: List[List[Any]], n: int = 25) -> str:
    out = []
    for i, row in enumerate(rows):
        if i >= n:
            break
        out.append(" | ".join((("" if v is None else str(v))[:80] for v in row)))
    return "\n".join(out)

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
                    text = data.decode("utf-8", errors="ignore")
                    reader = csv.reader(io.StringIO(text))
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
                # unknown or missing libs: fallback to file name only
                chunks.append(name)
        except Exception:
            # never bubble
            continue

    # clean and cap
    text = "\n\n".join([c for c in chunks if c]).strip()
    if len(text) > 16000:
        text = text[:16000]
    return text

def _format_analyze_to_cxo_md(resp: Dict[str, Any]) -> str:
    """
    Turn analyze JSON into the exact markdown the FE expects:
      ## CFO
      ### Insights
      - ...
      ### Recommendations
      - ...
    The FE flattens all per-role "Insights" bullets into the top Insights box.
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
    # Build role -> insights from CombinedInsights.insights[]
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

    # Fallback for recs: ensure dict keys exist
    for r in ["CFO", "CHRO", "COO", "CMO", "CPO"]:
        recs_by_role.setdefault(r, [])

    # Compose markdown exactly as the FE parser expects
    lines: List[str] = []
    for role in ["CFO", "CHRO", "COO", "CMO", "CPO"]:
        lines.append(f"## {role}")
        # Insights block (the FE aggregates these across roles to the top box)
        lines.append("### Insights")
        ins = [x for x in role_insights.get(role, []) if x]
        if ins:
            for i, item in enumerate(ins[:6], 1):
                lines.append(f"{i}. {item}")
        else:
            lines.append("- No material evidence in the provided context.")
        lines.append("")  # spacing

        # Recommendations block
        lines.append("### Recommendations")
        recs = [x for x in (recs_by_role.get(role) or []) if x]
        if recs:
            for i, item in enumerate(recs[:6], 1):
                lines.append(f"{i}. {item}")
        else:
            lines.append("- No actionable data found.")
        lines.append("")  # spacing between roles

    return "\n".join(lines).strip()

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
            "Define 3 outcomes; align product bets with owners and metrics.",
            "Weekly discovery cadence; 5 user interviews per cycle.",
        ]
    return recs

from typing import Optional, List, Dict, Any
from fastapi import Request, Form, File, UploadFile, HTTPException, Depends

# --- /api/analyze that accepts multipart + JSON, and guarantees data completeness ---
import traceback

DEBUG_VERBOSE = bool(os.getenv("DEBUG_VERBOSE", "0") == "1")

@api.post("/analyze", response_model=AnalyzeResponse)
async def api_analyze(
    request: Request,
    # JSON path
    doc: Optional[DocumentIn] = None,
    # multipart path
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    files: Optional[List[UploadFile]] = File(None),
    db=Depends(get_db),
    current: User = Depends(get_current_user),
):
    dbg: Dict[str, Any] = {"phase": "start"}

    try:
        # --- Normalize input ---
        ct = (request.headers.get("content-type") or "").lower()
        is_multipart = "multipart/form-data" in ct or (text is not None) or (file is not None) or (files is not None)

        tier = ("premium" if getattr(current, "is_admin", False)
                else ("pro" if getattr(current, "is_paid", False) else "demo"))

        content = ""
        filename = "input.txt"

        if is_multipart:
            flist: List[UploadFile] = []
            if file is not None: flist.append(file)
            if files: flist.extend(files)
            dbg["files"] = [getattr(f, "filename", None) for f in flist]

            # best-effort extraction; never raises
            appendix = await _extract_text_from_files(flist)
            content = ((text or "") + (("\n\n" + appendix) if appendix else "")).strip()
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

        excerpt = content[:16000]
        dbg.update({"phase": "brains", "tier": tier, "filename": filename})

        # --- Run brains (do not fail request) ---
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

        # --- Aggregate (do not fail request) ---
        try:
            combined: Dict[str, Any] = aggregate_brain_outputs(raw, document_filename=filename) or {}
        except Exception as e:
            combined = {"overall_summary": "", "insights": [], "aggregate": {}, "details_by_role": {}, "error": str(e)}
            if DEBUG_VERBOSE:
                combined["debug"] = {"aggregate_error": str(e), "trace": traceback.format_exc()}

        # --- Guarantees: one rec per role + mirror into details ---
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
                        if fb: first = fb[0]
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

        if DEBUG_VERBOSE:
            combined.setdefault("debug", {})["dbg"] = dbg

        # --- Respond ---
        job_id = str(uuid.uuid4())
        _log_usage(db, current.id, "/api/analyze", "ok")
        return AnalyzeResponse(job_id=job_id, combined=CombinedInsights(**combined))

    except HTTPException:
        raise
    except Exception as e:
        job_id = str(uuid.uuid4())
        payload = {"overall_summary": "", "insights": [], "aggregate": {}, "details_by_role": {}}
        if DEBUG_VERBOSE:
            payload["debug"] = {"fatal": str(e), "trace": traceback.format_exc(), "dbg": dbg}
        _log_usage(db, current.id, "/api/analyze", "error", meta=str(e)[:200])
        return AnalyzeResponse(job_id=job_id, combined=CombinedInsights(**payload))

# (Optional) Admin-only debug endpoint
@api.post("/debug/brains")
def debug_brains(doc: DocumentIn, db=Depends(get_db), current: User = Depends(get_current_user)):
    """Returns each brain's raw dict for quick troubleshooting (admin only)."""
    if not getattr(current, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admins only")
    excerpt = (doc.content or "")[:4000]
    out = {}
    for name in ("CFO","CHRO","COO","CMO","CPO"):
        fn = brain_registry.get(name)
        if not fn:
            continue
        try:
            out[name] = fn({"document_excerpt": excerpt, "tier": "premium"})
        except Exception as e:
            out[name] = {"error": str(e)}
    return out

@api.post("/analyze", response_model=AnalyzeResponse)
async def api_analyze(
    request: Request,
    doc: Optional[DocumentIn] = None,
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    files: Optional[List[UploadFile]] = File(None),
    db=Depends(get_db),
    current: User = Depends(get_current_user),
):
    """
    Accepts multipart (Dashboard) or JSON. Never throws uncaught errors.
    Ensures at least 1 recommendation per CXO and mirrors into details_by_role.
    """
    try:
        # -------- Normalize input --------
        content = ""
        filename = None
        tier = ("premium" if getattr(current, "is_admin", False)
                else ("pro" if getattr(current, "is_paid", False) else "demo"))

        ct = (request.headers.get("content-type") or "").lower()
        is_multipart = "multipart/form-data" in ct or (text is not None) or (file is not None) or (files is not None)

        if is_multipart:
            file_list: List[UploadFile] = []
            if file is not None:
                file_list.append(file)
            if files:
                file_list.extend(files)
            appendix = await _extract_text_from_files(file_list)
            content = ((text or "") + (("\n\n" + appendix) if appendix else "")).strip()

            for f in file_list:
                if getattr(f, "filename", None):
                    filename = f.filename
                    break
            if not filename:
                filename = "input.txt"
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

        excerpt = content[:16000]

        # -------- Run brains (never fail the request) --------
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

        # -------- Aggregate (never fail the request) --------
        combined: Dict[str, Any] = {}
        try:
            combined = aggregate_brain_outputs(raw, document_filename=filename) or {}
        except Exception as e:
            combined = {"overall_summary": "", "insights": [], "aggregate": {}, "details_by_role": {}, "error": str(e)}

        # -------- Guarantees: at least one rec per role + mirror to details --------
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
                        first = None
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

        # -------- Respond --------
        job_id = str(uuid.uuid4())
        _log_usage(db, current.id, "/api/analyze", "ok")
        return AnalyzeResponse(job_id=job_id, combined=CombinedInsights(**combined))

    except HTTPException:
        raise
    except Exception as e:
        # Last-resort safety: still return a valid shape
        job_id = str(uuid.uuid4())
        combined = {"overall_summary": "", "insights": [], "aggregate": {}, "details_by_role": {}, "error": str(e)}
        _log_usage(db, current.id, "/api/analyze", "error", meta=str(e)[:200])
        return AnalyzeResponse(job_id=job_id, combined=CombinedInsights(**combined))

# ==============================================================================
# Chat (sessions/history/send)
# ==============================================================================
@api.get("/chat/sessions")
def chat_sessions_list(db=Depends(get_db), current: User = Depends(get_current_user)):
    rows = (
        db.query(ChatSession)
        .filter(ChatSession.user_id == current.id)
        .order_by(ChatSession.created_at.desc())
        .all()
    )
    return [{"id": r.id, "title": r.title or f"Session {r.id}", "created_at": r.created_at.isoformat() + "Z"} for r in rows]

@api.post("/chat/sessions")
def chat_sessions_create(body: Dict[str, Any] = None, db=Depends(get_db), current: User = Depends(get_current_user)):
    title = None
    if body and isinstance(body, dict):
        title = (body.get("title") or "").strip() or None
    s = ChatSession(user_id=current.id, title=title, created_at=datetime.utcnow())
    db.add(s); db.commit(); db.refresh(s)
    return {"id": s.id, "title": s.title or f"Session {s.id}", "created_at": s.created_at.isoformat() + "Z"}

@api.get("/chat/history")
def chat_history_get(session_id: int = Query(..., ge=1), db=Depends(get_db), current: User = Depends(get_current_user)):
    sess = db.query(ChatSession).filter(ChatSession.id == session_id, ChatSession.user_id == current.id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    msgs = db.query(ChatMessage).filter(ChatMessage.session_id == sess.id).order_by(ChatMessage.created_at.asc()).all()
    return [{"id": m.id, "role": m.role, "content": m.content, "created_at": m.created_at.isoformat() + "Z"} for m in msgs]

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
    Accepts multipart (message + files), extracts text, calls analyze directly,
    stores user + assistant messages, and returns **Markdown** for instant FE rendering.
    Uses only primitive IDs post-commit to avoid DetachedInstanceError.
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
    appendix = await _extract_text_from_files(files)
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

    # 4) DIRECT analyze call (no internal HTTP)
    tier_for_analysis = "premium" if getattr(current, "is_admin", False) else ("pro" if getattr(current, "is_paid", False) else "demo")
    try:
        doc = DocumentIn(content=combined_text, filename=(filenames[0] if filenames else None), tier=tier_for_analysis)
        analysis = api_analyze(doc=doc, db=db, current=current)
        analysis_dict = analysis if isinstance(analysis, dict) else analysis.model_dump()

        # Build Markdown for chat bubble
        reply_md = _format_analyze_to_cxo_md(analysis_dict).strip()

        # Robust fallback if formatter returns empty
        if not reply_md:
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
            
            # belt & suspenders: if somehow empty, derive from combined.insights
            if not by_role and isinstance(combined.get("insights"), list):
                tmp = {}
                for it in combined["insights"]:
                    r = (it.get("role") or "").upper()
                    recs = list(it.get("recommendations") or [])
                    if r and recs:
                        tmp[r] = recs
                by_role = tmp

            if collective or any(by_role.values()):
                lines = []
                if collective:
                    lines.append("## Collective Insights")
                    for i, c in enumerate(collective[:10], 1):
                        lines.append(f"{i}. {c}")
                    lines.append("")
                for role in ["CFO","CHRO","COO","CMO","CPO"]:
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

    except Exception as e:
        reply_content = f"Received {len(filenames)} file(s). Could not run full analysis.\n\nError: {e}"

    # 5) assistant message
    am = ChatMessage(session_id=sess_id, role="assistant", content=reply_content, created_at=datetime.utcnow())
    db.add(am); db.commit(); db.refresh(am)

    _log_usage(db, current.id, "/api/chat/send", meta=f"files={len(filenames)};md=true")

    return {
        "session_id": sess_id,
        "assistant": {
            "id": int(am.id),
            "role": am.role,
            "content": am.content,  # markdown chat can display
            "content_json": analysis_dict,
            "created_at": am.created_at.isoformat() + "Z",
        },
    }


# ==============================================================================
# Mount routers
# ==============================================================================
app.include_router(api)
if health_router:         app.include_router(health_router)
if admin_router:          app.include_router(admin_router)
if admin_metrics_router:  app.include_router(admin_metrics_router)
if payments_router:       app.include_router(payments_router)
if contact_router:        app.include_router(contact_router)
