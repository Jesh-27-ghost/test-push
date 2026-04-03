# ShieldProxy — LLM Prompt Injection Firewall

A full-stack cybersecurity application that acts as a firewall for LLM prompts. 
It classifies, scrubs, and blocks malicious prompts in real-time using rule-based 
heuristics — no external AI services required.

## Features

- 🛡️ **6-Category Threat Classification** — Jailbreak, prompt leak, injection, social engineering, harmful content, business logic
- 🔒 **PII Scrubbing** — Automatically redacts emails, phone numbers, Aadhaar, PAN, credit cards, API keys
- ⚡ **Rate Limiting** — 60 requests/minute per API key
- 📊 **Real-time Dashboard** — Live threat feed, analytics charts, client monitoring
- 🧪 **Attack Simulator** — Test prompts with 6 preset attack vectors
- 🌐 **Hinglish Support** — Detects attacks in Hindi-English mixed language

## Quick Start

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
npm install
npm run dev
```

The frontend runs at `http://localhost:5173` and the backend at `http://localhost:8000`.

## Tech Stack

- **Backend**: Python FastAPI, Pydantic, SSE
- **Frontend**: React 19, Vite, Recharts
- **Storage**: In-memory (no external databases)
- **Classification**: Rule-based keyword/regex matching

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/chat` | Full pipeline: rate limit → PII scrub → classify → respond |
| POST | `/v1/simulate` | No-auth simulation for testing |
| GET | `/v1/stats` | Aggregate dashboard statistics |
| GET | `/v1/logs` | Recent audit log entries |
| GET | `/v1/clients` | Per-API-key statistics |
| GET | `/v1/health` | Health check + uptime |
| GET | `/v1/stream` | SSE live event stream |
