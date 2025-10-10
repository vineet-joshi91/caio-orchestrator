from __future__ import annotations
import os, json, hmac, hashlib, logging
from typing import Dict, Any, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

# Your project imports (present in main.py)
from db import get_db, User
from auth import get_current_user

# Razorpay SDK (optional guard so local dev without the lib doesn't crash)
try:
    import razorpay
    from razorpay.errors import BadRequestError, ServerError, SignatureVerificationError
except Exception:  # pragma: no cover
    razorpay = None
    BadRequestError = ServerError = SignatureVerificationError = Exception  # type: ignore

log = logging.getLogger("payments")
router = APIRouter(prefix="/api/payments", tags=["payments"])

# ------------------------- Environment / Config ------------------------------

MODE = "razorpay"

RZP_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RZP_SECRET = os.getenv("RAZORPAY_SECRET", "").strip()
RZP_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()

DEFAULT_CURRENCY = os.getenv("PAY_DEFAULT_CURRENCY", "INR").upper()

# Interval copy (display only)
PAY_PERIOD = os.getenv("PAY_PERIOD", "monthly")      # plan.period
PAY_INTERVAL = int(os.getenv("PAY_INTERVAL", "1"))   # plan.interval
PAY_INTERVAL_TEXT = os.getenv("PAY_INTERVAL_TEXT", "every 1 monthly")

# Supported tiers
SUPPORTED_PLANS = ("pro", "pro_plus", "premium")
TIER_KEYS = {"pro", "pro_plus", "premium"}

# Pricing via env JSON
# Old shape (still supported, maps to 'pro'): {"INR":{"amount_major":1999,"symbol":"₹"},"USD":{"amount_major":25,"symbol":"$"}}
# New shape (preferred): {
#   "INR":{"symbol":"₹","pro":1999,"pro_plus":3999,"premium":7999},
#   "USD":{"symbol":"$","pro":25,"pro_plus":49,"premium":99}
# }
def _load_pricing() -> Dict[str, Dict[str, Any]]:
    raw = os.getenv("PRICING_JSON", "").strip()
    if raw:
        try:
            data = json.loads(raw)
            return {k.upper(): v for k, v in data.items()}
        except Exception as e:
            log.warning("Invalid PRICING_JSON, using defaults. %s", e)
    return {
        "INR": {"amount_major": 1999, "symbol": "₹"},  # legacy single-price -> pro
        "USD": {"amount_major": 25,   "symbol": "$"},
    }

PRICING = _load_pricing()
ALLOWED_CURRENCIES = set(PRICING.keys())
HAS_SECRET = bool(RZP_SECRET)

# Optional (Subscriptions only) – map plan_id -> feature tier
PLAN_TO_TIER = {
    # INR
    os.getenv("RAZORPAY_PLAN_PRO_INR", ""): "pro",
    os.getenv("RAZORPAY_PLAN_PRO_PLUS_INR", ""): "pro_plus",
    os.getenv("RAZORPAY_PLAN_PREMIUM_INR", ""): "premium",
    # USD
    os.getenv("RAZORPAY_PLAN_PRO_USD", ""): "pro",
    os.getenv("RAZORPAY_PLAN_PRO_PLUS_USD", ""): "pro_plus",
    os.getenv("RAZORPAY_PLAN_PREMIUM_USD", ""): "premium",
}

# Payment Pages: hidden field notes.plan_id values we’ll set on each page
NOTES_PLAN_MAP = {"pro": "pro", "pro_plus": "pro_plus", "premium": "premium"}

_rzp: Optional["razorpay.Client"] = None
if razorpay and RZP_KEY_ID and RZP_SECRET:
    _rzp = razorpay.Client(auth=(RZP_KEY_ID, RZP_SECRET))
else:
    log.warning("Razorpay client not initialized (missing keys or library).")

# In-memory cache: (plan, currency, amount, period, interval) -> plan_id
PLAN_CACHE: Dict[Tuple[str, str, int, str, int], str] = {}

# ------------------------- Helpers ------------------------------------------

def _pick_currency(request: Request, explicit: Optional[str]) -> str:
    """
    Priority:
      1) explicit query/body
      2) geo hints (IN => INR else USD if available)
      3) DEFAULT_CURRENCY
      4) first available
    """
    if explicit:
        c = explicit.upper()
        if c in ALLOWED_CURRENCIES:
            return c
        raise HTTPException(400, f"Unsupported currency: {explicit}")

    cc = (
        request.headers.get("x-vercel-ip-country")
        or request.headers.get("cf-ipcountry")
        or request.headers.get("x-country-code")
        or ""
    ).upper()
    if cc == "IN" and "INR" in ALLOWED_CURRENCIES:
        return "INR"
    if "USD" in ALLOWED_CURRENCIES:
        return "USD"
    if DEFAULT_CURRENCY in ALLOWED_CURRENCIES:
        return DEFAULT_CURRENCY
    return next(iter(ALLOWED_CURRENCIES))

def _pricing_for(currency: str, plan: str) -> Tuple[int, str]:
    """
    Returns (amount_major, symbol) for given currency and plan.
    Back-compat: if only amount_major is provided, treat it as the 'pro' amount.
    """
    c = currency.upper()
    cfg = PRICING.get(c)
    if not cfg:
        raise HTTPException(500, f"Pricing missing for {currency}")

    symbol = cfg.get("symbol") or ("₹" if c == "INR" else "$")

    # New shape: per-plan ints present
    if any(k in cfg for k in SUPPORTED_PLANS):
        if plan not in SUPPORTED_PLANS:
            raise HTTPException(400, f"Unsupported plan: {plan}")
        amount = cfg.get(plan)
        if not isinstance(amount, int):
            raise HTTPException(500, f"Pricing missing for {currency}/{plan}")
        return int(amount), symbol

    # Old shape: single amount_major -> treat as 'pro'
    amt = cfg.get("amount_major")
    if isinstance(amt, int):
        if plan != "pro":
            log.warning("Per-plan pricing not configured; mapping plan=%s -> pro for currency=%s", plan, c)
        return int(amt), symbol

    raise HTTPException(500, f"Pricing invalid for {currency}")

def _ensure_plan(currency: str, amount_major: int, plan: str) -> str:
    key = (plan, currency, amount_major, PAY_PERIOD, PAY_INTERVAL)
    if key in PLAN_CACHE:
        return PLAN_CACHE[key]
    if not _rzp:
        raise HTTPException(503, "Razorpay not initialized on server.")
    try:
        plan_obj = _rzp.plan.create(
            {
                "period": PAY_PERIOD,
                "interval": PAY_INTERVAL,
                "item": {
                    "name": f"CAIO {plan.replace('_','+').title()} ({currency})",
                    "amount": amount_major * 100,  # subunits
                    "currency": currency,
                },
            }
        )
        PLAN_CACHE[key] = plan_obj["id"]
        return plan_obj["id"]
    except BadRequestError as e:
        msg = getattr(e, "args", [str(e)])[0]
        raise HTTPException(400, f"Plan create failed: {msg}") from e
    except ServerError as e:
        msg = getattr(e, "args", [str(e)])[0]
        raise HTTPException(502, f"Razorpay server error: {msg}") from e

# ------------------------- DB helpers (idempotency & columns) ----------------

def _ensure_event_table(db: Session) -> None:
    """Create the idempotency/audit table and user columns if missing."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS payments_webhooks (
          id TEXT PRIMARY KEY,
          provider TEXT NOT NULL,
          event_type TEXT NOT NULL,
          email TEXT,
          plan_key TEXT,
          currency TEXT,
          raw JSONB,
          created_at TIMESTAMPTZ DEFAULT now()
        );
    """)
    # Add user metadata columns if not present (best replaced with Alembic later)
    try:
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS feature_tier TEXT;")
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS billing_currency TEXT;")
    except Exception:
        pass
    db.commit()

def _already_processed(event_id: str, db: Session) -> bool:
    if not event_id:
        return False
    row = db.execute("SELECT 1 FROM payments_webhooks WHERE id=:i", {"i": event_id}).fetchone()
    return bool(row)

def _record_event(event_id: str, provider: str, evtype: str, email: Optional[str],
                  plan_key: Optional[str], currency: Optional[str], raw: dict, db: Session) -> None:
    db.execute(
        """
        INSERT INTO payments_webhooks (id, provider, event_type, email, plan_key, currency, raw)
        VALUES (:id, :prov, :ev, :em, :pk, :cur, CAST(:raw AS JSON))
        ON CONFLICT (id) DO NOTHING
        """,
        {"id": event_id or "no-id", "prov": "razorpay", "ev": evtype, "em": email,
         "pk": plan_key, "cur": currency, "raw": json.dumps(raw)}
    )
    db.commit()

# ------------------------- Extractors for webhook ----------------------------

def _extract_email(event: dict) -> Optional[str]:
    pay = (event.get("payload", {}).get("payment", {}) or {}).get("entity", {}) or {}
    email = (pay.get("email") or "").strip().lower()
    if email:
        return email
    sub = (event.get("payload", {}).get("subscription", {}) or {}).get("entity", {}) or {}
    email = ((sub.get("notes") or {}).get("email") or "").strip().lower()
    if email:
        return email
    inv = (event.get("payload", {}).get("invoice", {}) or {}).get("entity", {}) or {}
    email = ((inv.get("customer_details") or {}).get("email") or "").strip().lower()
    return email or None

def _extract_currency(event: dict) -> str:
    pay = (event.get("payload", {}).get("payment", {}) or {}).get("entity", {}) or {}
    cur = (pay.get("currency") or "").upper()
    if cur:
        return cur
    title = ((event.get("payload", {}).get("payment_page", {}) or {}).get("entity", {}) or {}).get("title", "").lower()
    if "international" in title or "usd" in title:
        return "USD"
    if "india" in title or "inr" in title:
        return "INR"
    return ""

def _extract_plan_key(event: dict) -> Optional[str]:
    # 1) Payment Pages: notes.plan_id
    pay = (event.get("payload", {}).get("payment", {}) or {}).get("entity", {}) or {}
    notes = pay.get("notes") or {}
    n = (notes.get("plan_id") or "").strip().lower()
    if n in NOTES_PLAN_MAP:
        return NOTES_PLAN_MAP[n]

    # 2) Subscriptions: map plan_id via env
    sub = (event.get("payload", {}).get("subscription", {}) or {}).get("entity", {}) or {}
    plan_id = (sub.get("plan_id") or "").strip()
    if plan_id in PLAN_TO_TIER:
        return PLAN_TO_TIER[plan_id]

    # 3) Payment Page title fallback
    title = ((event.get("payload", {}).get("payment_page", {}) or {}).get("entity", {}) or {}).get("title", "").lower()
    if "pro+" in title or "pro plus" in title:
        return "pro_plus"
    if "premium" in title:
        return "premium"
    if "pro" in title:
        return "pro"
    return None

# ------------------------- Routes -------------------------------------------

@router.get("/ping")
def ping():
    return {"ok": True, "mode": MODE, "currencies": sorted(ALLOWED_CURRENCIES)}

@router.get("/subscription-config")
def subscription_config(request: Request, currency: Optional[str] = None):
    """
    Boot payload for the frontend.
    Returns the raw PRICING table (old or new shape) and a defaultCurrency,
    plus a `pay` wrapper for older TS that expects config.pay.pricing.
    """
    display_currency = _pick_currency(request, currency)
    payload = {
        "mode": MODE,
        "key_id": RZP_KEY_ID or None,
        "has_secret": HAS_SECRET,
        "interval": PAY_INTERVAL_TEXT,
        "defaultCurrency": display_currency,
        "pricing": PRICING,
    }
    return {**payload, "pay": payload}

class CreateBody(BaseModel):
    plan: Optional[str] = "pro"           # "pro" | "pro_plus" | "premium"
    currency: Optional[str] = None
    notes: Optional[Dict[str, Any]] = None

@router.post("/subscription/create", status_code=201)
def create_subscription(
    request: Request,
    body: CreateBody,
    current_user: User = Depends(get_current_user),   # ensure auth
):
    if MODE != "razorpay":
        raise HTTPException(400, "Only Razorpay mode is implemented.")

    # 1) Resolve currency and plan
    plan = (body.plan or "pro").lower()
    if plan not in SUPPORTED_PLANS:
        raise HTTPException(400, f"Unsupported plan: {plan}")
    currency = _pick_currency(request, body.currency)

    # 2) Resolve amount & symbol for this plan
    amount_major, symbol = _pricing_for(currency, plan)

    # 3) Ensure (or create) a Razorpay plan for this (plan,currency,amount)
    plan_id = _ensure_plan(currency, amount_major, plan)

    # 4) Propagate email to notes to ease webhook mapping
    notes = dict(body.notes or {})
    notes.setdefault("email", getattr(current_user, "email", ""))

    try:
        sub = _rzp.subscription.create(
            {
                "plan_id": plan_id,
                "total_count": 12,           # 1 year; adjust as desired
                "customer_notify": 1,
                "notes": notes,
            }
        )
        return {
            "key_id": RZP_KEY_ID or None,
            "currency": currency,
            "symbol": symbol,
            "amount_major": amount_major,
            "plan": plan,
            "plan_id": plan_id,
            "subscription_id": sub.get("id"),
            "status": sub.get("status"),
            "short_url": sub.get("short_url"),
            "raw": sub,
        }
    except BadRequestError as e:
        msg = getattr(e, "args", [str(e)])[0]
        raise HTTPException(400, f"Subscription create failed: {msg}") from e
    except ServerError as e:
        msg = getattr(e, "args", [str(e)])[0]
        raise HTTPException(502, f"Razorpay server error: {msg}") from e

# ----- Optional verify endpoint (UI can call after handler; webhook is source of truth)

class VerifyBody(BaseModel):
    payload: Optional[Dict[str, Any]] = None

@router.post("/verify")
def verify_payment(_: VerifyBody, current_user: User = Depends(get_current_user)):
    return {"ok": True, "note": "Verification deferred to webhook"}

# ---------------------------- Cancel endpoint --------------------------------

class CancelBody(BaseModel):
    subscription_id: str

@router.post("/cancel")
def cancel_subscription(
    body: CancelBody,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not _rzp:
        raise HTTPException(503, "Razorpay not initialized on server.")
    try:
        sub = _rzp.subscription.cancel(body.subscription_id, {"cancel_at_cycle_end": 0})
    except BadRequestError as e:
        msg = getattr(e, "args", [str(e)])[0]
        raise HTTPException(400, f"Cancel failed: {msg}") from e
    except ServerError as e:
        msg = getattr(e, "args", [str(e)])[0]
        raise HTTPException(502, f"Razorpay server error: {msg}") from e

    # mark user as free
    try:
        current_user.is_paid = False
        db.add(current_user); db.commit()
    except Exception as e:
        log.warning("Cancel OK at gateway but DB flag update failed: %s", e)

    return {"ok": True, "status": sub.get("status"), "raw": sub}

# -------------------------- Webhook (authoritative) --------------------------

@router.post("/razorpay/webhook")
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handles:
      - Payment Pages: payment.captured -> set is_paid True, feature_tier, billing_currency
      - Subscriptions: subscription.activated / invoice.paid -> True
                       subscription.cancelled -> False
    Logs every event for idempotency/audit in payments_webhooks.
    """
    if not RZP_WEBHOOK_SECRET:
        raise HTTPException(503, "Webhook secret not configured")

    # Verify HMAC signature
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "") or ""
    expected = hmac.new(RZP_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Invalid signature")

    event = json.loads(body.decode("utf-8"))
    etype = event.get("event", "")
    event_id = event.get("id", "")
    payload = event.get("payload", {}) or {}

    _ensure_event_table(db)
    if _already_processed(event_id, db):
        return {"ok": True, "duplicate": True}

    # Extract attributes used across flows
    email = _extract_email(event)
    plan_key = _extract_plan_key(event)   # "pro" | "pro_plus" | "premium" if resolvable
    currency = _extract_currency(event)   # "INR" | "USD" etc.

    # Always record event (idempotency + audit)
    _record_event(event_id, "razorpay", etype, email, plan_key, currency, event, db)

    actionable = {
        # Payment Pages:
        "payment.captured",
        "order.paid",
        "payment.authorized",
        # Subscriptions:
        "subscription.activated",
        "invoice.paid",
        "subscription.cancelled",
    }

    if etype not in actionable:
        return {"ok": True, "note": f"ignored:{etype}"}

    if not email:
        log.warning("Webhook %s without resolvable email; payload keys=%s", etype, list(payload.keys()))
        return {"ok": True, "note": "no-email-in-payload"}

    # Load user
    user: Optional[User] = db.query(User).filter(User.email == email).first()
    if not user:
        log.warning("Webhook %s: user not found for email=%s", etype, email)
        return {"ok": True, "note": "user-not-found"}

    try:
        if etype in ("payment.captured", "order.paid", "payment.authorized", "subscription.activated", "invoice.paid"):
            user.is_paid = True
            if plan_key in TIER_KEYS:
                user.feature_tier = plan_key
            if currency:
                user.billing_currency = currency
        elif etype in ("subscription.cancelled",):
            user.is_paid = False

        db.add(user); db.commit()
    except Exception as e:
        log.error("Webhook DB update failed: %s", e)
        raise HTTPException(500, "DB update failed")

    return {
        "ok": True,
        "email": email,
        "event": etype,
        "feature_tier": getattr(user, "feature_tier", None),
        "billing_currency": getattr(user, "billing_currency", None),
    }

# -------------------------- Legacy shim for old frontend ---------------------

@router.post("/create-checkout-session")
def legacy_create_checkout_session(request: Request, current_user: User = Depends(get_current_user)):
    """
    Backward-compat: older frontend called /api/payments/create-checkout-session without a plan.
    We map it to 'pro' so nothing breaks, and return the shape with 'url'.
    """
    data = create_subscription(request, CreateBody(plan="pro"), current_user)
    return {"url": data.get("short_url"), **{k: v for k, v in data.items() if k != "short_url"}}
