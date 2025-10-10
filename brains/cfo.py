from orchestrator.utils_prompt import load_prompt, parse_llm_output
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

ROLE = "CFO"
SYSTEM = "You are the Chief Financial Officer. Be precise and actionable."

def _desired_recs_for_tier(tier: str) -> int:
    t = (tier or "demo").lower()
    if t in ("admin", "premium"):  # full experience
        return 8
    if t == "pro_plus":
        return 5
    return 3  # pro/demo

def run(inputs: dict) -> dict:
    tier = (inputs.get("tier") or "demo").lower()
    caps = caps_for_tier(tier)
    want = _desired_recs_for_tier(tier)

    base = load_prompt(ROLE, "default")
    excerpt = (inputs.get("document_excerpt") or inputs.get("content") or "")[:caps.max_extract_chars]

    prompt = f"""{base}

Return STRICT JSON with this schema (no extra keys, no commentary):
{{
  "summary": "1–2 sentences",
  "recommendations": [
    // {want} concrete, non-duplicative actions written as imperative bullets,
    // each 6–20 words, scoped to the {ROLE}'s domain, no fluff.
  ]
}}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END EXCERPT ===
"""

    raw = generate(system=SYSTEM, prompt=prompt, tier=tier)
    # allow a couple extra if the model sends more; we’ll still cap in UI where needed
    summary, recs = parse_llm_output(raw, max_recs= max(10, want))

    # robust fallback: give at least `want` items
    fallback = [
        "Tighten working capital and reduce DSO via stricter collections cadence",
        "Add weekly variance deck with risks/mitigations to steer exec decisions",
        "Reprice low-margin SKUs; negotiate supplier discounts or volume rebates",
        "Freeze non-critical spend; reallocate to ROI-positive growth channels",
        "Validate unit economics by cohort; cut under-performing segments",
        "Scenario test FX/interest-rate shocks; pre-hedge where material",
        "Automate month-end close steps to shorten reporting cycle",
        "Raise gross margin with bundling/cross-sell offers and ops efficiency",
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
        "recommendations": recs,   # keep full list here (details panel will use it)
        "raw": (raw or "")[:2000],
    }
