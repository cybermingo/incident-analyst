# 🛡️ Security Event Analyst

A modular FastAPI application that analyzes security events using an LLM via the Groq API.

## Architecture

```
security-analyst/
├── .env                          # Environment config (API keys, model settings)
├── requirements.txt
├── main.py                       # App entry point
├── app/
│   ├── core/
│   │   ├── config.py             # Pydantic Settings — loads from .env
│   │   └── exceptions.py        # Custom exception classes + handlers
│   ├── schemas/
│   │   └── security.py          # Pydantic request/response models
│   ├── services/
│   │   ├── llm_client.py        # Async OpenAI-compatible Groq client
│   │   └── security_analyst.py  # Business logic + prompt engineering
│   └── api/
│       └── v1/
│           ├── router.py         # API v1 route aggregator
│           └── endpoints/
│               └── analyze.py   # POST /api/v1/security/analyze
└── tests/
    └── test_analyze.py           # Async pytest tests with mocking
```

## Setup

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

API docs: http://localhost:8000/docs

## Example Request

```bash
curl -X POST http://localhost:8000/api/v1/security/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "context": "Financial services — PCI-DSS environment",
    "focus": "lateral movement and credential theft",
    "events": [
      {
        "event_id": "EVT-001",
        "timestamp": "2024-01-15T02:14:00Z",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.20",
        "event_type": "brute_force",
        "description": "47 failed SSH login attempts over 3 minutes",
        "severity": "high",
        "metadata": {"port": 22, "attempts": 47}
      },
      {
        "event_id": "EVT-002",
        "timestamp": "2024-01-15T02:17:33Z",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.20",
        "event_type": "successful_login",
        "description": "Successful SSH login after brute force sequence",
        "severity": "critical",
        "metadata": {"port": 22, "username": "deploy"}
      }
    ]
  }'
```

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```
