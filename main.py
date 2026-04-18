import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from llm_client import llm_client
from parser.log_parser import parse_log_line
from detection.rules import run_all_detections

app = FastAPI(title="UPM Integrated Security Analyst")

SYSTEM_PROMPT = """
You are an elite Tier-3 SOC analyst. Analyze the provided security alerts.
Compare the detected patterns with MITRE ATT&CK.
Respond ONLY with a valid JSON object matching the requested schema.
""".strip()

class AnalyzeRequest(BaseModel):
    events: List[dict]

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):

    detected_alerts = run_all_detections(req.events)
    analysis_input = detected_alerts if detected_alerts else req.events
    user_prompt = f"Analyze these security findings: {json.dumps(analysis_input)}"

    try:
        raw = await llm_client.chat(SYSTEM_PROMPT, user_prompt)
        clean = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return {"analysis": json.loads(clean)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))