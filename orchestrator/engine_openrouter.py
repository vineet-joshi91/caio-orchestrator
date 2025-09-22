# -*- coding: utf-8 -*-
"""
Created on Mon Sep 22 11:46:40 2025

@author: Vineet
"""

# backend/orchestrator/engine_openrouter.py
import json, urllib.request
from typing import Optional, Dict, Any
import os

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def _http_post(payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(OPENROUTER_URL, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())

def _sanitize_demo_model(model_id: Optional[str], env_default: Optional[str]) -> str:
    m = (model_id or env_default or "openrouter/auto").strip()
    return "openrouter/auto" if m.startswith("openai/") else m

def pick_model(tier: str, model_hint: Optional[str] = None) -> str:
    t = (tier or "demo").lower()
    if t == "demo":
        return _sanitize_demo_model(model_hint, os.getenv("LLM_MODEL_OPENROUTER"))
    return (model_hint or "openai/gpt-4o").strip()

def generate(*, system: str, prompt: str, tier: str, model_hint: Optional[str]=None,
             max_tokens: int = 800, extra: Optional[Dict[str, Any]]=None) -> str:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return "[OPENROUTER] Missing OPENROUTER_API_KEY"
    payload: Dict[str, Any] = {
        "model": pick_model(tier, model_hint),
        "messages": [{"role":"system","content":system},{"role":"user","content":prompt}],
        "max_tokens": max_tokens,
    }
    if extra: payload.update(extra)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://caio.app",
        "X-Title": "CAIO",
    }
    try:
        out = _http_post(payload, headers)
        return ((out.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    except Exception as e:
        return f"[OPENROUTER ERROR] {e}"
