# -*- coding: utf-8 -*-
"""
Admin metrics API for CAIO
- No HTTP self-calls (prices come from ENV)
- Stable timeseries: UTC day x endpoint x tier
- Back/forward compatible with optional columns on User
"""
from datetime import datetime, timedelta, timezone, date as _date
from typing import Dict, Any, Optional, List

import os
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, Date, text

from db import get_db, User, UsageLog
from auth import get_current_user

# Router lives under /api/admin to match your API style elsewhere
router = APIRouter(prefix="/api/admin", tags=["admin-metrics"])

# ---- Env-driven pricing (adjust in Render env) --------------------------------
PRO_PRICE_INR      = int(os.getenv("PRO_PRICE_INR", "1999"))
PRO_PRICE_USD      = int(os.getenv("PRO_PRICE_USD", "25"))
PRO_PLUS_PRICE_INR = int(os.getenv("PRO_PLUS_PRICE_INR", "3999"))
PRO_PLUS_PRICE_USD = int(os.getenv("PRO_PLUS_PRICE_USD", "49"))
PREMIUM_PRICE_INR  = int(os.getenv("PREMIUM_PRICE_INR", "7999"))
PREMIUM_PRICE_USD  = int(os.getenv("PREMIUM_PRICE_USD", "99"))

DEFAULT_ADMIN_CURRENCY = os.getenv("DEFAULT_ADMIN_CURRENCY", "INR").upper()


# ---- Helpers ------------------------------------------------------------------
def _ensure_admin(u: User) -> None:
    if not u or not bool(getattr(u, "is_admin", False)):
        raise HTTPException(status_code=403, detail="admin_only")

def _tier_expr():
    """
    SQLAlchemy CASE expression for a normalized tier label.
    Priority: admin > plan_tier (if present and not null) > is_paid->"pro" > "demo"
    """
    # we avoid calling .isnot(None) on a non-column; gate with hasattr
    if hasattr(User, "plan_tier"):
        return func.coalesce(
            func.nullif(func.case(
                (User.is_admin == True, "admin"),
            ), ""),  # ensure admin wins
            func.nullif(User.plan_tier, ""),         # prefer explicit plan_tier if set
            func.case((User.is_paid == True, "pro"), else_="demo"),
        )
    else:
        return func.case(
            (User.is_admin == True, "admin"),
            (User.is_paid  == True, "pro"),
            else_="demo",
        )

def _today_utc() -> _date:
    return datetime.now(timezone.utc).date()


# ---- Core snapshot endpoint ----------------------------------------------------
@router.get("/metrics")
def metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    _ensure_admin(current_user)

    # -------- Account totals --------
    total_users = db.query(func.count(User.id)).scalar() or 0
    active_paid = db.query(func.count(User.id)).filter(User.is_paid.is_(True)).scalar() or 0

    active_inr: Optional[int] = None
    active_usd: Optional[int] = None
    if hasattr(User, "billing_currency"):
        active_inr = db.query(func.count(User.id)).filter(User.is_paid.is_(True), User.billing_currency == "INR").scalar() or 0
        active_usd = db.query(func.count(User.id)).filter(User.is_paid.is_(True), User.billing_currency == "USD").scalar() or 0

    cancelled_7d = 0
    if hasattr(User, "plan_status"):
        # prefer updated_at when present
        ts_col = getattr(User, "updated_at", None) or getattr(User, "created_at")
        if ts_col is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            cancelled_7d = db.query(func.count(User.id)).filter(User.plan_status == "cancelled", ts_col >= cutoff).scalar() or 0

    # -------- Usage timeseries: UTC day x endpoint x tier --------
    day_col = cast(UsageLog.timestamp, Date)
    series_rows = (
        db.query(
            day_col.label("date"),
            UsageLog.endpoint.label("endpoint"),
            _tier_expr().label("tier"),
            func.count(UsageLog.id).label("count"),
        )
        .join(User, User.id == UsageLog.user_id)
        .group_by("date", "endpoint", "tier")
        .order_by("date")
        .all()
    )
    series = [
        {"date": str(r.date), "endpoint": r.endpoint or "", "tier": r.tier, "count": int(r.count or 0)}
        for r in series_rows
    ]

    # Totals from logs
    today = _today_utc()
    totals_today = (
        db.query(func.count(UsageLog.id))
          .filter(cast(UsageLog.timestamp, Date) == today)
          .scalar()
        or 0
    )
    totals_all = int(db.query(func.count(UsageLog.id)).scalar() or 0)

    # Optional: free-cap hits (status 429/rate_limited)
    cap_hits_today = 0
    if hasattr(UsageLog, "status"):
        cap_hits_today = (
            db.query(func.count(UsageLog.id))
              .filter(
                  cast(UsageLog.timestamp, Date) == today,
                  UsageLog.status.in_(["429", "rate_limited"])
              )
              .scalar()
            or 0
        )

    # -------- MRR (basic estimate) --------
    mrr: Dict[str, int] = {}

    def _add(d: Dict[str, int], k: str, v: int) -> None:
        d[k] = d.get(k, 0) + v

    if active_inr is not None and active_usd is not None:
        # Baseline uses Pro prices; refine when you fully track plan_tier
        _add(mrr, "INR", int(active_inr) * PRO_PRICE_INR)
        _add(mrr, "USD", int(active_usd) * PRO_PRICE_USD)
    else:
        cur = DEFAULT_ADMIN_CURRENCY if DEFAULT_ADMIN_CURRENCY in ("INR", "USD") else "INR"
        base = PRO_PRICE_INR if cur == "INR" else PRO_PRICE_USD
        _add(mrr, cur, int(active_paid) * base)

    return {
        "totals": {
            "today": totals_today,
            "all_time": totals_all,
            "total_users": total_users,
            "active_paid": active_paid,
            "active_inr": active_inr,
            "active_usd": active_usd,
            "cancelled_7d": cancelled_7d,
            "free_cap_hits_today": cap_hits_today,
        },
        # Core chartable data: never guess on the frontend
        "series": series,  # [{date, endpoint, tier, count}]
        "mrr": mrr,
        "notes": "UTC grouping by day/endpoint/tier; prices from ENV; no HTTP self-call.",
    }


# ---- Extra endpoints for the Admin UI -----------------------------------------
@router.get("/kpis")
def admin_kpis(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    # Use the DB view if you created it; otherwise compute inline
    row = db.execute(text("SELECT * FROM public.v_admin_kpis")).mappings().first()
    if row:
        return dict(row)

    # Fallback computation if the view isn't present
    today = _today_utc()
    dau_today = db.query(func.count(func.distinct(UsageLog.user_id))).filter(cast(UsageLog.timestamp, Date) == today).scalar() or 0
    wau_7d = db.query(func.count(func.distinct(UsageLog.user_id))).filter(UsageLog.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)).scalar() or 0
    mau_30d = db.query(func.count(func.distinct(UsageLog.user_id))).filter(UsageLog.timestamp >= datetime.now(timezone.utc) - timedelta(days=30)).scalar() or 0
    new_users_7d = db.query(func.count(User.id)).filter(getattr(User, "created_at", None) >= datetime.now(timezone.utc) - timedelta(days=7)).scalar() if hasattr(User, "created_at") else 0
    latest_usage_log_ts = db.query(func.max(UsageLog.timestamp)).scalar()

    total_users = db.query(func.count(User.id)).scalar() or 0
    return {
        "total_users": total_users,
        "new_users_7d": int(new_users_7d or 0),
        "dau_today": int(dau_today or 0),
        "wau_7d": int(wau_7d or 0),
        "mau_30d": int(mau_30d or 0),
        "latest_usage_log_ts": latest_usage_log_ts.isoformat() if latest_usage_log_ts else None,
    }


@router.get("/users")
def admin_users(
    q: Optional[str] = Query(None, description="search by email contains"),
    sort: str = Query("last_active_at_desc", pattern="^(last_active_at_desc|created_at_desc)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)

    # Prefer the view if present
    try:
        base = "SELECT user_id, email, tier, is_admin, is_test, is_paid, billing_currency, plan_tier, plan_status, created_at, last_active_at, events_30d FROM public.v_user_activity"
        where = ""
        params: Dict[str, Any] = {}
        if q:
            where = " WHERE lower(email) LIKE :q "
            params["q"] = f"%{q.lower()}%"

        order = " ORDER BY last_active_at DESC NULLS LAST, created_at DESC "
        if sort == "created_at_desc":
            order = " ORDER BY created_at DESC NULLS LAST, last_active_at DESC "

        sql = base + where + order + " LIMIT :limit OFFSET :offset"
        params.update({"limit": limit, "offset": offset})
        rows = db.execute(text(sql), params).mappings().all()
        total = db.execute(text("SELECT count(*) FROM public.v_user_activity")).scalar()
        return {"total": int(total or 0), "items": [dict(r) for r in rows]}
    except Exception:
        # Inline fallback if the view doesn't exist
        day_col = cast(UsageLog.timestamp, Date)
        latest_log_subq = (
            db.query(
                UsageLog.user_id.label("uid"),
                func.max(UsageLog.timestamp).label("last_log")
            )
            .group_by(UsageLog.user_id)
            .subquery()
        )
        q_users = db.query(
            User.id.label("user_id"),
            User.email,
            _tier_expr().label("tier"),
            User.is_admin,
            User.is_test,
            User.is_paid,
            getattr(User, "billing_currency", text("NULL")).label("billing_currency"),
            getattr(User, "plan_tier", text("'pro'")).label("plan_tier"),
            getattr(User, "plan_status", text("NULL")).label("plan_status"),
            getattr(User, "created_at", text("NULL")).label("created_at"),
            func.greatest(
                getattr(User, "last_seen", text("'1900-01-01'::timestamp")),
                func.coalesce(latest_log_subq.c.last_log, text("'1900-01-01'::timestamp"))
            ).label("last_active_at"),
            # simple 30d events count
            db.query(func.count(UsageLog.id)).filter(
                UsageLog.user_id == User.id,
                UsageLog.timestamp >= datetime.now(timezone.utc) - timedelta(days=30)
            ).correlate(User).as_scalar().label("events_30d"),
        ).outerjoin(latest_log_subq, latest_log_subq.c.uid == User.id)

        if q:
            q_users = q_users.filter(func.lower(User.email).like(f"%{q.lower()}%"))

        if sort == "created_at_desc":
            q_users = q_users.order_by(getattr(User, "created_at", text("NULL")) .desc().nullslast())
        else:
            q_users = q_users.order_by(text("last_active_at DESC NULLS LAST"))

        items = q_users.limit(limit).offset(offset).all()
        total = db.query(func.count(User.id)).scalar()
        return {"total": int(total or 0), "items": [dict(r._mapping) for r in items]}


@router.get("/usage-daily")
def usage_daily(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    try:
        rows = db.execute(
            text("""
                SELECT day, endpoint, events, dau
                FROM public.v_usage_daily
                WHERE day >= CURRENT_DATE - INTERVAL :days || ' days'
                ORDER BY day DESC, endpoint
            """),
            {"days": days},
        ).mappings().all()
        return {"items": [dict(r) for r in rows]}
    except Exception:
        # Inline fallback
        day_col = cast(UsageLog.timestamp, Date)
        sub = (
            db.query(
                day_col.label("day"),
                UsageLog.endpoint.label("endpoint"),
                func.count(UsageLog.id).label("events"),
                func.count(func.distinct(UsageLog.user_id)).label("dau"),
            )
            .filter(day_col >= _today_utc() - timedelta(days=days))
            .group_by("day", "endpoint")
            .order_by("day DESC", "endpoint")
            .all()
        )
        return {"items": [dict(day=str(r.day), endpoint=r.endpoint or "", events=int(r.events or 0), dau=int(r.dau or 0)) for r in sub]}


@router.get("/signups-30d")
def signups_30d(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    try:
        rows = db.execute(
            text("SELECT * FROM public.v_signups_last_30d ORDER BY day DESC")
        ).mappings().all()
        return {"items": [dict(r) for r in rows]}
    except Exception:
        if not hasattr(User, "created_at"):
            return {"items": []}
        rows = (
            db.query(
                cast(getattr(User, "created_at"), Date).label("day"),
                func.count(User.id).label("signups"),
            )
            .filter(getattr(User, "created_at") >= datetime.now(timezone.utc) - timedelta(days=30))
            .group_by("day")
            .order_by(text("day DESC"))
            .all()
        )
        return {"items": [dict(day=str(r.day), signups=int(r.signups or 0)) for r in rows]}


@router.get("/last-logins")
def last_logins(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_admin(current_user)
    # View-based if available
    try:
        rows = db.execute(
            text("""
                SELECT u.id AS user_id, u.email, v.last_login_at
                FROM public.users u
                LEFT JOIN public.v_user_last_login v ON v.user_id = u.id
                ORDER BY v.last_login_at DESC NULLS LAST, u.created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"limit": limit, "offset": offset},
        ).mappings().all()
        return {"items": [dict(r) for r in rows]}
    except Exception:
        # Fallback using auth_events if the view is missing
        if not db.execute(text("SELECT to_regclass('public.auth_events')")).scalar():
            return {"items": []}
        rows = db.execute(
            text("""
                WITH last_login AS (
                    SELECT user_id, MAX(created_at) AS last_login_at
                    FROM public.auth_events
                    WHERE event_type='login' AND success
                    GROUP BY user_id
                )
                SELECT u.id AS user_id, u.email, l.last_login_at
                FROM public.users u
                LEFT JOIN last_login l ON l.user_id = u.id
                ORDER BY l.last_login_at DESC NULLS LAST, u.created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"limit": limit, "offset": offset},
        ).mappings().all()
        return {"items": [dict(r) for r in rows]}
