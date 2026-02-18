import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from llm_client import llm_client

app = FastAPI(title="Security Event Analyst")

SYSTEM_PROMPT = """
You are an elite Tier-3 SOC analyst. Analyze the provided security events using MITRE ATT&CK
and the Cyber Kill Chain. Think step-by-step before concluding.

Respond ONLY with a valid JSON object — no markdown, no preamble — matching this schema:
{
  "overall_risk_level": "low|medium|high|critical",
  "executive_summary": "2-3 sentence CISO-level summary",
  "attack_patterns": ["pattern1", ...],
  "threat_indicators": [{"indicator": "...", "confidence": "low|medium|high", "reasoning": "..."}],
  "recommendations": [{"priority": "immediate|short-term|long-term", "action": "...", "rationale": "..."}],
  "affected_assets": ["..."],
  "confidence_score": 0.0,
  "analyst_notes": "TTPs, visibility gaps, false-positive likelihood"
}
Rules: confidence_score is 0.0–1.0. Never invent events not in the input.
""".strip()


# ── Models ────────────────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    event_id:        Optional[str] = None
    timestamp:       Optional[str] = None
    source_ip:       Optional[str] = None
    destination_ip:  Optional[str] = None
    event_type:      str
    description:     str
    severity:        Optional[str] = None
    raw_log:         Optional[str] = None
    metadata:        Optional[dict] = None


class AnalyzeRequest(BaseModel):
    events:  list[SecurityEvent]
    context: Optional[str] = None
    focus:   Optional[str] = None


# ── Endpoint ──────────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    if not req.events:
        raise HTTPException(status_code=422, detail="Provide at least one event")

    parts = [f"Total events: {len(req.events)}"]
    if req.context:
        parts.append(f"Context: {req.context}")
    if req.focus:
        parts.append(f"Focus on: {req.focus}")
    parts.append(json.dumps([e.model_dump(exclude_none=True) for e in req.events], indent=2))
    user_prompt = "\n\n".join(parts)

    try:
        raw = await llm_client.chat(SYSTEM_PROMPT, user_prompt)
        # strip accidental markdown fences
        clean = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return {"events_analyzed": len(req.events), "analysis": json.loads(clean)}
    except json.JSONDecodeError:
        return {"events_analyzed": len(req.events), "raw_response": raw}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
