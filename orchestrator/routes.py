# -*- coding: utf-8 -*-
"""
Created on Mon Sep 22 13:36:20 2025

@author: Vineet
"""

# backend/orchestrator/routes.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from sqlalchemy import func, cast, Date

from db import get_db, UsageLog
from auth import get_current_user  # returns User from JWT {"sub": email}
from orchestrator.tier import caps_for_tier
from brains.registry import brain_registry

router = APIRouter(prefix="/api", tags=["orchestrator"])

def _today_utc():
    return datetime.now(timezone.utc).date()

@router.post("/analyze")
def analyze(doc: dict, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """
    Body: { filename: str, content: str, tier?: "demo"|"pro"|"pro_plus"|"premium" }
    """
    tier = (doc.get("tier") or getattr(user, "plan_tier", None) or ("pro" if getattr(user,"is_paid",False) else "demo")).lower()
    caps = caps_for_tier(tier)

    # enforce per-day cap for analyze
    count = db.query(func.count(UsageLog.id)).filter(
        cast(UsageLog.timestamp, Date) == _today_utc(),
        UsageLog.user_id == user.id,
        UsageLog.endpoint == "/api/analyze",
    ).scalar() or 0
    if count >= caps.analyze_per_day:
        raise HTTPException(status_code=429, detail=f"Daily analyze cap reached for tier '{tier}'")

    excerpt = (doc.get("content") or "")[:caps.max_extract_chars]
    insights = []
    for name in ("CFO","COO","CHRO","CMO","CPO"):
        fn = brain_registry.get(name)
        if not fn: continue
        out = fn({"document_excerpt": excerpt, "tier": tier})
        insights.append({
            "role": out["role"],
            "summary": out["summary"],
            "recommendations": out["recommendations"],
        })

    # log usage
    db.add(UsageLog(user_id=user.id, endpoint="/api/analyze", status="200", timestamp=datetime.utcnow()))
    db.commit()

    return {
        "job_id": "mvp-local",
        "combined": {
            "document_filename": doc.get("filename"),
            "overall_summary": "Combined insights (MVP)",
            "insights": insights
        }
    }

@router.post("/brains/{brain}/run")
def run_brain(brain: str, body: dict, db: Session = Depends(get_db), user=Depends(get_current_user)):
    fn = brain_registry.get(brain.upper())
    if not fn:
        raise HTTPException(status_code=404, detail="Brain not found")
    out = fn(body or {})
    db.add(UsageLog(user_id=user.id, endpoint=f"/api/brains/{brain}/run", status="200", timestamp=datetime.utcnow()))
    db.commit()
    return out

@router.post("/export")
def export(body: dict, db: Session = Depends(get_db), user=Depends(get_current_user)):
    # Stub: FE doesn’t need export now; keep contract/no-op
    return {"status":"ok","format": body.get("format","json"), "data": body.get("data")}
