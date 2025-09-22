# -*- coding: utf-8 -*-
"""
Created on Mon Sep 22 17:11:13 2025

@author: Vineet
"""

# core/aggregation/brain_aggregator.py
from __future__ import annotations
from typing import List, Dict, Any, Tuple
from collections import OrderedDict

# Preferred CXO ordering for a stable UI
ROLES_ORDER = ["CFO", "CHRO", "COO", "CMO", "CPO"]

# Default caps by tier (aligns with your env; tweak if you like different UI caps)
DEFAULT_CAPS = {
    "demo":     {"collective_min": 3, "collective_max": 5, "recs_per_role": 3, "include_deep_dive": False},
    "pro":      {"collective_min": 3, "collective_max": 5, "recs_per_role": 3, "include_deep_dive": False},
    "pro_plus": {"collective_min": 3, "collective_max": 6, "recs_per_role": 3, "include_deep_dive": True},
    "pro+":     {"collective_min": 3, "collective_max": 6, "recs_per_role": 3, "include_deep_dive": True},
    "premium":  {"collective_min": 4, "collective_max": 7, "recs_per_role": 4, "include_deep_dive": True},
}

def _norm_tier(t: str | None) -> str:
    t = (t or "demo").strip().lower()
    return "pro_plus" if t in ("pro_plus", "pro+") else t

def _dedupe_preserve_order(lines: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in lines:
        s = (x or "").strip()
        key = s.lower()
        if s and key not in seen:
            seen.add(key)
            out.append(s)
    return out

def _first_sentence(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    # split on common sentence breaks; keep it short
    for sep in [". ", "• ", "\n", " - ", " — "]:
        if sep in t:
            return t.split(sep, 1)[0].strip().rstrip(".")
    return t[:160].strip().rstrip(".")

def _order_roles(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key_fn(b: Dict[str, Any]) -> Tuple[int, str]:
        role = (b.get("role") or "").upper()
        idx = ROLES_ORDER.index(role) if role in ROLES_ORDER else 999
        return (idx, role)
    return sorted([b for b in items if b and b.get("role")], key=key_fn)

def _ensure_topline(b: Dict[str, Any]) -> str:
    """Use provided topline_insight; else synthesize from summary."""
    if b.get("topline_insight"):
        return str(b["topline_insight"]).strip()
    return _first_sentence(b.get("summary") or b.get("raw") or "")

def aggregate_brain_outputs(
    brain_outputs: List[Dict[str, Any]],
    *,
    tier: str = "demo",
    caps_override: Dict[str, int | bool] | None = None
) -> Dict[str, Any]:
    """
    Inputs: list of per-brain dicts like:
      {"role":"CFO","summary":"...","recommendations":[...],"raw":"...", "deep_dive": {...}?}
    Output (compact, UI-ready):
    {
      "collective_insights": ["..", "..", ".."],            # 3–7 bullets (tier dependent)
      "cxo_recommendations": {"CFO":[...], "CHRO":[...], ...},  # 2–4 per role (tier dependent)
      # Pro+/Premium (if available):
      "deep_dive": {"CFO": {...}, "CHRO": {...}, ...}
    }
    """
    t = _norm_tier(tier)
    caps = dict(DEFAULT_CAPS.get(t, DEFAULT_CAPS["demo"]))
    if caps_override:
        caps.update(caps_override)

    ordered = _order_roles(brain_outputs)

    # Build toplines
    toplines = _dedupe_preserve_order([_ensure_topline(b) for b in ordered if _ensure_topline(b)])
    # Enforce caps; if fewer than min, keep what's available (don't pad)
    toplines = toplines[: caps["collective_max"]]

    # Build recommendations per role
    cxo_recs: Dict[str, List[str]] = OrderedDict()
    deep_dive: Dict[str, Any] = OrderedDict()
    per_role_cap = int(caps["recs_per_role"])
    for b in ordered:
        role = (b.get("role") or "").upper()
        recs = _dedupe_preserve_order(b.get("recommendations", []) or [])[:per_role_cap]
        if recs:
            cxo_recs[role] = recs
        if caps.get("include_deep_dive") and b.get("deep_dive"):
            deep_dive[role] = b["deep_dive"]

    out: Dict[str, Any] = {
        "collective_insights": toplines,
        "cxo_recommendations": cxo_recs
    }
    if caps.get("include_deep_dive") and deep_dive:
        out["deep_dive"] = deep_dive
    return out
