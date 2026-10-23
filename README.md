# IITM HTTPS Incident Agent v2 — standalone FastAPI

This is a fresh project; it does not modify an existing incident-agent service.

## Local setup (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL = 'sqlite:///./agent.db'
$env:AI_PIPE_TOKEN = Read-Host 'AI Pipe token'
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` and `http://127.0.0.1:8000/health`.

## Deploy on Render

1. Create a new GitHub repository and push this project's files.
2. Create a **new** Render web service (or Blueprint using `render.yaml`).
3. Set `DATABASE_URL` to your Neon PostgreSQL connection string, including SSL options as provided by Neon.
4. Set `AI_PIPE_TOKEN` in Render's environment settings. Never commit tokens or `.env` files.
5. Use `pip install -r requirements.txt` and `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
6. Submit the new Render HTTPS base URL, without `/docs`, `/v2`, or credentials.

## Contract endpoints

- `POST /v2/incidents`: new run, AI planning, initial diagnostic dispatches.
- `POST /v2/incidents/{runId}/receipts`: authoritative tool and approval receipts.
- `GET /v2/incidents/{runId}`: stored state.
- `GET /health`: readiness.

The `/v2` API is deliberately public, as required by the grader. **It never executes the dispatched tools itself**; the grader executes them and supplies receipts. This service persists action dispatches, receipts and trace metadata. No transcript or sensitive request object is included in the public GET/response or exported trace.

## Important caveats

This is a contract-oriented starter implementation, **not a grader-verified solution**. The hidden incident cases, exact tool schemas, expected root causes, and scoring rules have not been exercised. The model may make incorrect planning decisions; model output is validated for membership and structure, but the current code does not fully validate arguments against each tool's JSON Schema. Run local contract tests and inspect real grader feedback before assuming correctness. It does not yet guarantee all strict OTLP topology expectations for every failure/approval sequence or production-safe concurrent receipt handling. Do not deploy this as a general-purpose incident remediation service.

## Quick validation

```powershell
$base = 'http://127.0.0.1:8000'
Invoke-WebRequest -Uri "$base/v2/incidents" -Method POST -ContentType 'application/json' -Body '{}' -SkipHttpErrorCheck | Select-Object StatusCode
```

Expected: HTTP 400 for unsupported profile, **not 401**.

For a valid request, use the exact `profile`, `runId`, `agentName`, `publicMarker`, `incident`, `toolCatalog`, and `policy` structure in your IITM assignment. A real `AI_PIPE_TOKEN` is needed for planning.

## Privacy and security

Use only synthetic course incidents. Do not submit production credentials, real customer data, or secrets in incident transcripts or tool catalog metadata. The public GET intentionally omits input and model prompts. Access to the database and AI Pipe token must remain private.
