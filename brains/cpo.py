# -*- coding: utf-8 -*-
# CPO = Chief People Officer (People / Employee Experience)

from orchestrator.utils_prompt import load_prompt, parse_llm_output
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

ROLE = "CPO"
SYSTEM = (
    "You are the Chief People Officer. Focus on culture, engagement, leadership, "
    "manager effectiveness, internal mobility, learning, DEI, and employee experience. "
    "Be precise and action-oriented."
)

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
    // {want} concrete, non-duplicative CPO actions (6–20 words), tied to people strategy and employee experience.
  ]
}}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END EXCERPT ===
"""

    raw = generate(system=SYSTEM, prompt=prompt, tier=tier)
    summary, recs = parse_llm_output(raw, max_recs=max(10, want))

    # People/EX-focused fallback actions
    fallback = [
        "Launch quarterly engagement pulse; action-plan top three drivers with owners",
        "Stand up manager excellence program with coaching and peer practice",
        "Map internal mobility paths; publish role ladders and criteria transparently",
        "Prioritize leadership pipeline; fill top succession gaps with targeted development",
        "Close critical skill gaps via academies aligned to business outcomes",
        "Standardize career conversations; require semiannual growth plans for all employees",
        "Tighten DEI metrics; set hiring and promotion guardrails with dashboards",
        "Reduce time-to-resolution on people tickets with clear SLAs and self-serve",
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
        "recommendations": recs,   # keep full list; Premium UI shows all in Details
        "raw": (raw or "")[:2000],
    }
