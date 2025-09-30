# admin_metrics.py  (DROP-IN)
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Any, Dict, List

from db import get_db
from auth import require_admin

router = APIRouter(prefix="/api/admin", tags=["admin-metrics"])

def _ok(data: Dict[str, Any] | List[Dict[str, Any]]):
    # tiny helper to keep shape consistent
    return data

@router.get("/kpis")
def kpis(db: Session = Depends(get_db), _=Depends(require_admin)):
    try:
        total_users = db.execute(text("SELECT COUNT(*) FROM public.users")).scalar() or 0

        new_users_7d = db.execute(text("""
            SELECT COUNT(*) FROM public.users
            WHERE created_at >= NOW() - INTERVAL '7 days'
        """)).scalar() or 0

        dau_today = db.execute(text("""
            SELECT COUNT(DISTINCT user_id) FROM public.usage_logs
            WHERE timestamp::date = CURRENT_DATE
        """)).scalar() or 0

        wau_7d = db.execute(text("""
            SELECT COUNT(DISTINCT user_id) FROM public.usage_logs
            WHERE timestamp >= NOW() - INTERVAL '7 days'
        """)).scalar() or 0

        mau_30d = db.execute(text("""
            SELECT COUNT(DISTINCT user_id) FROM public.usage_logs
            WHERE timestamp >= NOW() - INTERVAL '30 days'
        """)).scalar() or 0

        latest_usage = db.execute(text("""
            SELECT MAX(timestamp) FROM public.usage_logs
        """)).scalar()

        return _ok({
            "total_users": int(total_users),
            "new_users_7d": int(new_users_7d),
            "dau_today": int(dau_today),
            "wau_7d": int(wau_7d),
            "mau_30d": int(mau_30d),
            "latest_usage_log_ts": str(latest_usage) if latest_usage else None,
        })
    except Exception as e:
        # don’t crash – surface the DB error so we can see it in DevTools
        return {"detail": "query_error", "error": str(e)}

@router.get("/users")
def users(q: str = "", sort: str = "last_active_at_desc",
          limit: int = 25, offset: int = 0,
          db: Session = Depends(get_db), _=Depends(require_admin)):
    try:
        # safely build order by
        order_sql = "v.last_active_at DESC NULLS LAST"
        if sort == "created_at_desc":
            order_sql = "u.created_at DESC NULLS LAST"

        # make sure v_user_last_login view exists; if not, use a subquery fallback
        sql = text(f"""
            WITH last AS (
                SELECT user_id, MAX(timestamp) AS last_active_at
                FROM public.usage_logs
                GROUP BY user_id
            )
            SELECT
              u.id        AS user_id,
              u.email     AS email,
              COALESCE(u.plan_tier, u.tier, 'demo') AS tier,
              u.is_admin  AS is_admin,
              u.is_paid   AS is_paid,
              u.created_at,
              l.last_active_at,
              COALESCE((
                SELECT COUNT(*) FROM public.usage_logs ul
                WHERE ul.user_id = u.id AND ul.timestamp >= NOW() - INTERVAL '30 days'
              ), 0) AS events_30d
            FROM public.users u
            LEFT JOIN last l ON l.user_id = u.id
            WHERE (:q = '' OR u.email ILIKE '%' || :q || '%')
            ORDER BY {order_sql}
            LIMIT :limit OFFSET :offset
        """)

        rows = db.execute(sql, {"q": q.strip().lower(), "limit": limit, "offset": offset}).mappings().all()
        total = db.execute(text("""
            SELECT COUNT(*) FROM public.users
            WHERE (:q = '' OR email ILIKE '%' || :q || '%')
        """), {"q": q.strip().lower()}).scalar() or 0

        items = []
        for r in rows:
            items.append({
                "user_id": r["user_id"],
                "email": r["email"],
                "tier": (r["tier"] or "demo"),
                "is_admin": bool(r["is_admin"]),
                "is_paid": bool(r["is_paid"]) if r["is_paid"] is not None else False,
                "created_at": str(r["created_at"]) if r["created_at"] else None,
                "last_active_at": str(r["last_active_at"]) if r["last_active_at"] else None,
                "events_30d": int(r["events_30d"] or 0),
            })
        return {"total": int(total), "items": items}
    except Exception as e:
        return {"detail": "query_error", "error": str(e), "items": [], "total": 0}

@router.get("/usage-daily")
def usage_daily(days: int = 30, db: Session = Depends(get_db), _=Depends(require_admin)):
    try:
        rows = db.execute(text("""
            SELECT
              DATE_TRUNC('day', timestamp)::date AS day,
              endpoint,
              COUNT(*) AS events,
              COUNT(DISTINCT user_id) FILTER (WHERE endpoint = 'chat' OR endpoint = 'analyze') AS dau
            FROM public.usage_logs
            WHERE timestamp >= NOW() - (:days || ' days')::interval
            GROUP BY 1, 2
            ORDER BY 1 DESC, 2 ASC
        """), {"days": days}).mappings().all()

        items = [{
            "day": str(r["day"]),
            "endpoint": r["endpoint"],
            "events": int(r["events"] or 0),
            "dau": int(r["dau"] or 0),
        } for r in rows]
        return {"items": items}
    except Exception as e:
        return {"detail": "query_error", "error": str(e), "items": []}

@router.get("/signups-30d")
def signups_30d(db: Session = Depends(get_db), _=Depends(require_admin)):
    try:
        rows = db.execute(text("""
            SELECT DATE_TRUNC('day', created_at)::date AS day, COUNT(*) AS signups
            FROM public.users
            WHERE created_at >= NOW() - INTERVAL '30 days'
            GROUP BY 1
            ORDER BY 1 DESC
        """)).mappings().all()
        items = [{"day": str(r["day"]), "signups": int(r["signups"] or 0)} for r in rows]
        return {"items": items}
    except Exception as e:
        return {"detail": "query_error", "error": str(e), "items": []}

@router.get("/ping")
def ping_admin(_=Depends(require_admin)):
    return {"ok": True}
