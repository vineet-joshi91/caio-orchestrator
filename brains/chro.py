# -*- coding: utf-8 -*-
from orchestrator.utils_prompt import load_prompt, parse_llm_output
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

ROLE = "CHRO"
SYSTEM = "You are the Chief Human Resources Officer. Focus on org health, workforce planning, skills, engagement, and compliance. Be precise and actionable."

def _desired_recs_for_tier(tier: str) -> int:
    t = (tier or "demo").lower()
    if t in ("admin", "premium"):
        return 8
    if t == "pro_plus":
        return 5
    return 3

def run(inputs: dict) -> dict:
    tier = (inputs.get("tier") or "demo").lower()
    want = _desired_recs_for_tier(tier)
    caps = caps_for_tier(tier)

    base = load_prompt(ROLE, "default")
    excerpt = (inputs.get("document_excerpt") or inputs.get("content") or "")[:caps.max_extract_chars]

    prompt = f"""{base}

Return STRICT JSON with this schema (no extra keys, no commentary):
{{
  "summary": "1–2 sentences",
  "recommendations": [
    // {want} concrete, non-duplicative CHRO actions (6–20 words), tied to risks/opportunities in the excerpt.
  ]
}}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END EXCERPT ===
"""

    raw = generate(system=SYSTEM, prompt=prompt, tier=tier)
    summary, recs = parse_llm_output(raw, max_recs=max(10, want))

    fallback = [
        "Align workforce plan to revenue forecast; freeze or backfill selectively",
        "Tighten hiring bar; prioritize roles tied to near-term growth",
        "Launch skills inventory; map gaps to strategic initiatives",
        "Roll out quarterly performance calibration to curb rating inflation",
        "Reduce regrettable attrition with manager check-ins and flight risk flags",
        "Standardize compensation bands; close out-of-band offers and inequities",
        "Improve onboarding time-to-productivity with role-specific checklists",
        "Audit compliance training; remediate overdue and high-risk audiences",
    ]
    if not recs:
        recs = fallback[:want]
    elif len(recs) < want:
        recs = (recs + fallback)[:want]
    if not summary:
        summary = "Model-generated summary unavailable; showing consolidated recommendations."

    return {
        "role": ROLE,
        "summary": summary,
        "recommendations": recs,
        "raw": (raw or "")[:2000],
    }
