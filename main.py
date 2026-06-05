import json
import re
import time
from typing import List
from urllib.parse import urlparse, parse_qs, unquote_plus

from fastapi import FastAPI
from pydantic import BaseModel

from detection.rules import run_all_detections, build_alert
from llm_client import llm_client

app = FastAPI(title="UPM Integrated Security Analyst")

incident_history: List[dict] = []
MAX_INCIDENTS = 500
last_attack_time = 0.0  

SYSTEM_PROMPT = """
You are an elite Tier-3 SOC analyst. Analyze the provided security alert context.
Respond ONLY with a valid JSON object.

MANDATORY SCHEMA:
{
  "overall_risk_level": "low/medium/high/critical",
  "confidence_score": 0.95,
  "executive_summary": "string describing the full attack sequence",
  "attack_patterns": ["TXXXX - Pattern Name"],
  "recommendations": [
    {"priority": "high/medium/low", "action": "string"}
  ]
}
""".strip()

class AnalyzeRequest(BaseModel):
    events: List[dict]

def normalize_event(e: dict) -> dict:
    """Hardened normalization to ensure detection logic always receives data."""
    e = dict(e)

    custom_payload = e.get("query_decoded", "")

    for k in ("url", "parameters", "method", "source_ip"):
        if k in e and isinstance(e[k], str):
            e[k] = e[k].lower()

    for k in ("url", "parameters"):
        v = e.get(k)
        if isinstance(v, str):
            e[f"{k}_decoded"] = unquote_plus(v)

    if isinstance(e.get("url_decoded"), str):
        p = urlparse(e["url_decoded"])
        e["path"] = p.path or ""
        e["query"] = p.query or ""
        e["query_params"] = parse_qs(e["query"], keep_blank_values=True)
        
        standard_query = unquote_plus(e["query"])
        e["query_decoded"] = f"{standard_query} {custom_payload}".strip()
    
    if "query_params" not in e and "parameters_decoded" in e:
        e["path"] = e.get("path", "").lower()
        e["query"] = e["parameters_decoded"]
        e["query_params"] = parse_qs(e["parameters_decoded"], keep_blank_values=True)
        e["query_decoded"] = f"{e['parameters_decoded']} {custom_payload}".strip()

    if not e.get("timestamp"):
        e["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")

    return e

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    """Receive candidate events, run detections + correlation, ask LLM, store incident."""
    global incident_history, last_attack_time

    events = [normalize_event(e) for e in req.events]
    detected = run_all_detections(events)

    if not detected:
        return {"status": "no attacks detected"}

    current_time = time.time()
    if current_time - last_attack_time < 15.0:
        return {"status": "ignored duplicate echo log"}
    last_attack_time = current_time

    types = {a["alert_type"] for a in detected}
    if "bruteforce" in types and "webshell" in types:
        detected.append(build_alert(
            "correlated_rce_chain",
            "Brute-force followed by execution from uploads suggests post-auth RCE.",
            "correlation-engine"
        ))
    if "webshell" in types and "dns_c2" in types:
        detected.append(build_alert(
            "correlated_c2_after_webshell",
            "Web shell activity with suspicious DNS indicates possible C2.",
            "correlation-engine"
        ))

    analysis_input = {"rule_engine_alerts": detected, "raw_event_logs": events}
    user_prompt = f"Correlate and output mandatory JSON schema: {json.dumps(analysis_input)}"

    try:
        raw = await llm_client.chat(SYSTEM_PROMPT, user_prompt)
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        clean = match.group(0) if match else raw.strip()
        data = json.loads(clean)
        required = {"overall_risk_level", "confidence_score", "executive_summary", "attack_patterns", "recommendations"}
        if not isinstance(data, dict) or not required.issubset(data.keys()):
            raise ValueError("LLM schema mismatch")
            
    except Exception:
        patterns = [f"{a['technique_id']} - {a['technique_name']}" for a in detected]
        technique_list = ", ".join(sorted({a['technique_name'] for a in detected}))
        source_ip = events[0].get("source_ip", "Unknown IP")
        
        data = {
            "overall_risk_level": "high",
            "confidence_score": 0.85,
            "executive_summary": f"Automated Failsafe: System detected {technique_list} activity from {source_ip}, but AI analysis timed out. Immediate investigation required.",
            "attack_patterns": sorted(set(patterns)),
            "recommendations": [
                {"priority": "high", "action": f"Investigate IP {source_ip} for {technique_list} attempts."},
                {"priority": "medium", "action": "Review application access logs for successful exploitation."}
            ]
        }

    incident_history.insert(0, {
        "timestamp": events[0].get("timestamp", "Just Now"),
        "type": detected[0].get("alert_type", "WEB_ANOMALY").upper(),
        "details": data
    })
    
    if len(incident_history) > MAX_INCIDENTS:
        incident_history.pop()

    return {"status": "incident logged", "current_count": len(incident_history)}

@app.get("/latest")
async def latest():
    """Return recent incidents for the UI."""
    return {"history": incident_history}