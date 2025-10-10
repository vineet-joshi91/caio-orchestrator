# -*- coding: utf-8 -*-
from orchestrator.utils_prompt import load_prompt, parse_llm_output
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

ROLE = "COO"
SYSTEM = "You are the Chief Operating Officer. Focus on delivery, SLAs, quality, throughput, cost-to-serve, and risk. Be precise and operational."

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
    // {want} concrete, non-duplicative COO actions (6–20 words), focused on throughput, cost, quality, and risk.
  ]
}}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END EXCERPT ===
"""

    raw = generate(system=SYSTEM, prompt=prompt, tier=tier)
    summary, recs = parse_llm_output(raw, max_recs=max(10, want))

    fallback = [
        "Map end-to-end process; remove bottlenecks to raise throughput",
        "Standardize work instructions; tighten QC gates to reduce defects",
        "Rationalize vendor list; renegotiate top-10 contracts on volume",
        "Shift volume to lower-cost lanes while protecting cycle times",
        "Introduce daily ops huddles with KPI boards and owner actions",
        "Automate repetitive steps; redeploy labor to constraint steps",
        "Implement tiered incident response; drive MTTR down by 30%",
        "Create rolling 13-week capacity plan; align hiring and scheduling",
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
