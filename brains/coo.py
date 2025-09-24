# brains/coo.py
from orchestrator.utils_prompt import load_prompt, parse_llm_output
from orchestrator.engine_openrouter import generate
from orchestrator.tier import caps_for_tier

ROLE = "COO"
SYSTEM = "You are the Chief Operating Officer. Focus on delivery, efficiency, and risk."

def run(inputs: dict) -> dict:
    tier = (inputs.get("tier") or "demo").lower()
    caps = caps_for_tier(tier)
    base = load_prompt(ROLE, "default")
    excerpt = (inputs.get("document_excerpt") or inputs.get("content") or "")[:caps.max_extract_chars]

    prompt = f"""{base}

Return STRICT JSON with this schema:
{{
  "summary": "1–2 sentences",
  "recommendations": ["bullet", "bullet", "bullet"]
}}

=== EXCERPT (trimmed to {caps.max_extract_chars} chars) ===
{excerpt}
=== END EXCERPT ===
"""

    raw = generate(system=SYSTEM, prompt=prompt, tier=tier)
    summary, recs = parse_llm_output(raw, max_recs=6)

    if not recs:
        recs = ["Add weekly variance deck", "Tighten working capital", "Validate unit economics"]
    if not summary:
        summary = "Auto-summary unavailable; showing extracted recommendations."

    return {"role": ROLE, "summary": summary, "recommendations": recs, "raw": (raw or "")[:2000]}
