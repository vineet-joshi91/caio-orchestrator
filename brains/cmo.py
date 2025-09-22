# -*- coding: utf-8 -*-
"""
Created on Mon Sep 22 11:50:54 2025

@author: Vineet
"""

from orchestrator.utils import load_prompt
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

def run(inputs: dict) -> dict:
    tier = (inputs.get("tier") or "demo").lower()
    caps = caps_for_tier(tier)
    base = load_prompt("CMO", "default")
    excerpt = (inputs.get("document_excerpt") or "")[:caps.max_extract_chars]
    prompt = f"""{base}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END ===

Return JSON-like content: summary + 3-5 bullet recommendations.
"""
    out = generate(system="You are the CMO.", prompt=prompt, tier=tier)
    return {
        "role": "CMO",
        "summary": "Stub summary (parse model output next pass).",
        "recommendations": ["Add weekly variance deck","Tighten working capital","Validate unit economics"],
        "raw": out[:2000],
    }
