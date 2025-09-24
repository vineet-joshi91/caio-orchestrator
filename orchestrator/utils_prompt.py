# orchestrator/utils_prompt.py
from pathlib import Path
import json, re
from typing import Tuple, List

def load_prompt(brain: str, variant: str = "default") -> str:
    """
    Search order:
      1) brains/prompts/<brain>.<variant>.md   (new shared prompts)
      2) brains/<BRAIN>/<variant>.prompt.txt   (legacy)
    """
    root = Path(__file__).resolve().parents[2]
    p1 = root / "brains" / "prompts" / f"{brain.lower()}.{variant}.md"
    if p1.exists():
        return p1.read_text(encoding="utf-8")
    p2 = root / "brains" / brain.upper() / f"{variant}.prompt.txt"
    if p2.exists():
        return p2.read_text(encoding="utf-8")
    return f"You are the {brain} brain. Provide concise, actionable insights."

_JSON_BLOCK_RE = re.compile(r"\{[\s\S]*\}", re.M)

def parse_llm_output(text: str, max_recs: int = 6) -> Tuple[str, List[str]]:
    """Return (summary, recommendations[]) with JSON-first parsing and graceful fallback."""
    if not text:
        return "", []
    m = _JSON_BLOCK_RE.search(text)
    if m:
        try:
            data = json.loads(m.group(0))
            summary = (data.get("summary") or "").strip()
            recs = [str(r).strip("-•* ").strip() for r in (data.get("recommendations") or []) if str(r).strip()]
            return summary, recs[:max_recs]
        except Exception:
            pass
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    summary = next((ln for ln in lines if len(ln) > 20 and not ln.startswith(("#","##"))), "")
    bullets = []
    for ln in lines:
        if re.match(r"^(\*|-|•|\d+[.)])\s+", ln):
            bullets.append(re.sub(r"^(\*|-|•|\d+[.)])\s+", "", ln).strip())
    return summary, bullets[:max_recs]
