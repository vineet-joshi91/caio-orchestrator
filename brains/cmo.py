# -*- coding: utf-8 -*-
from orchestrator.utils_prompt import load_prompt, parse_llm_output
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

ROLE = "CMO"
SYSTEM = "You are the Chief Marketing Officer. Be ROI-driven; focus on pipeline, CAC/LTV, channels, and experimentation."

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
    // {want} concrete, non-duplicative CMO actions (6–20 words), tied to pipeline, CAC/LTV, mix, and tests.
  ]
}}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END EXCERPT ===
"""

    raw = generate(system=SYSTEM, prompt=prompt, tier=tier)
    summary, recs = parse_llm_output(raw, max_recs=max(10, want))

    fallback = [
        "Shift spend to channels with CAC below target and stable volume",
        "Stand up weekly pipeline council with Sales for stage conversion",
        "Launch 3 controlled A/B tests per month across paid and web",
        "Tighten MQL→SQL criteria; prune low-intent sources from mix",
        "Spin up lifecycle emails for activation and second-order revenue",
        "Refresh positioning; update top-of-funnel assets and landing pages",
        "Add multi-touch attribution; re-weight budgets by marginal CPA",
        "Expand partner co-marketing to tap adjacent audiences",
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
