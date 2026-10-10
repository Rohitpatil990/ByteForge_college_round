# AgentBreak — AI-Agent Security Testing Platform

AgentBreak is an AI-agent security testing platform built to evaluate agent boundaries, policy conformance, and prompt injection resistance through adaptive testing, cryptographic evidence tracking, and defense evaluation.

**Current Working Branch:** `feat/platform-integration`

---

## 1. Project Purpose & Honest Limitations

### Purpose
AgentBreak provides an automated testing harness for LLM agents to:
- Test policy constraints against adversarial and edge-case inputs.
- Track canary token leakage across tool execution arguments and final replies.
- Distinguish baseline/recorded fixtures from dynamic adaptive discoveries.
- Offer a minimal, standardized API contract and dark-theme security console dashboard across attacker, target sandbox, analyzer, and defense modules.

### Critical Limitations & Security Assumptions
1. **Canary String Matching Limitations**: Plain string matching only detects exact matching synthetic canary tokens. It does **not** guarantee detection of encoded (e.g., Base64, Hex, URL-encoded), hashed, paraphrased, translated, or transformed secrets.
2. **Tool Policy Enforcement vs. Final Reply Leakage**: Tool-call policy enforcement checks whether an authorized tool was invoked with allowed parameters. Blocking or restricting a tool call does **not** automatically prevent sensitive content or secret leakage from appearing in the final assistant reply (`final_reply`).
3. **Target Scope**: Target configurations are specifically bound to configured synthetic demo agents (e.g., `demo-company-assistant`). The platform does not claim universal compatibility with arbitrary unconfigured agent code.
4. **Guard Failure Mode**: The policy engine and security guards fail closed (`guard_fail_mode: closed`). In the event of ambiguity, parsing failure, or unexpected states, actions are blocked by default.
5. **No Universal Guarantee**: Passing automated test suites or finding zero vulnerabilities in a test run does not prove or guarantee that an agent is immune to jailbreaks or prompt injections.
6. **Development Stubs**: Output reply filtering (D3) is currently a development stub pending P3 defense module integration and is explicitly labeled as such in the dashboard and API.

---

## 2. Project Architecture & Module Responsibilities

```text
ByteForge_college_round/
├── spec/                       # [P4] Shared frozen v2 contract, schemas, and smoke tests
│   ├── __init__.py
│   ├── schema.py               # Frozen v2 contract (Trace, Finding, Feedback, Rules)
│   └── smoke_test.py           # 12-test verification suite (covering all 9 pipeline stages)
├── target/                     # [P1] Agent sandbox runtime & target definitions
│   ├── __init__.py
│   └── configs/
│       └── demo-company-assistant.yaml  # Configured synthetic demo agent
├── attacker/                   # [P2] Attack generators & adaptive mutation strategies
│   └── __init__.py
├── analyzer/                   # [P2] Trace rule checking & canary detection
│   └── __init__.py
├── defense/                    # [P3] Guardrails & active policy mitigations
│   └── __init__.py
├── eval/                       # [P3] Benchmark evaluation & metrics computation
│   └── __init__.py
├── api/                        # [P4] FastAPI backend & integration endpoints
│   ├── __init__.py
│   ├── main.py                 # Application entry point & CORS
│   ├── routes.py               # All frozen P0 API endpoints
│   └── store.py                # Assessment state, attack execution, and hash chain engine
├── dashboard/                  # [P4] React 18 + Vite + TypeScript security console
│   ├── src/                    # UI components, API client, design system CSS
│   ├── package.json
│   └── vite.config.ts
├── data/                       # Data storage
│   ├── generated/              # Saved assessments and run evidence
│   └── recorded/               # Sanitized recorded demo baseline fixtures
├── requirements.txt            # Python dependencies (fastapi, uvicorn, pyyaml, pydantic, httpx, pytest)
├── .env.example                # Example environment configuration
├── .gitignore                  # Git exclusions for secrets, builds, and generated data
├── policy.yaml                 # Master security policy definitions (fail-closed)
├── dev.ps1                     # Windows PowerShell unified development boot script
├── DEMO_SCRIPT.md              # 3-4 minute live demo walkthrough script
├── PITCH.md                    # Pitch outline and evaluator Q&A defense guide
└── README.md                   # This documentation
```

### Module Ownership Matrix
| Module | Lead | Responsibilities | Status |
| :--- | :--- | :--- | :--- |
| **Foundation, API & Web Platform** (`spec/`, `api/`, `dashboard/`) | **P4** | Shared v2 schemas, FastAPI routes, React dashboard, smoke tests, boot script, demo deliverables | **Complete & Verified** |
| **Agent Sandbox** (`target/`) | **P1** | Synthetic agent runtime, execution sandboxing, tool mock execution | Pending P1 integration |
| **Attacker & Analyzer** (`attacker/`, `analyzer/`) | **P2** | Attack generation, adaptive feedback loop (`next_variant`), 4 analyzer rules | Pending P2 integration |
| **Defense & Evaluation** (`defense/`, `eval/`) | **P3** | Interceptor guardrails, policy enforcement, ASR & metrics computation | Pending P3 integration |

---

## 3. Shared v2 Contract Specifications

All modules integrate via `spec/schema.py`:

### Trace Schema
- Required trace fields: `target_id`, `kind`, `variant_source`, `parent_run_id`, `round`
- Recognized step types: `user_input`, `agent_thought`, `tool_call`, `tool_result`, `final_reply`, `error`

### Analyzer Rule IDs (Frozen)
The analyzer evaluates traces against these exact 4 rule IDs:
1. `canary_in_executed_args`: Synthetic canary detected inside tool execution arguments.
2. `canary_in_final_reply`: Synthetic canary detected inside the agent's final text reply.
3. `executed_outside_policy`: Tool executed with parameters or conditions violating `policy.yaml`.
4. `memory_write_untrusted`: Untrusted user input triggered an unauthorized memory write.

### Finding Sources & Adaptive Discoveries
Findings are categorized by `source`:
- `seed`: Baseline benchmark test cases.
- `generated`: Dynamically mutated test cases generated during adaptive runs.
- `recorded`: Pre-recorded test fixtures stored in `data/recorded/`.

> **Note**: Recorded findings and seed findings are kept strictly identifiable and are **never** counted as adaptive discoveries. Only `generated` findings qualify as adaptive discoveries.

### Adaptive Attacker Feedback
The attacker module accepts feedback formatted as:
```json
{
  "type": "deny_reason",          // or "bot_reply"
  "rule": "executed_outside_policy", // optional
  "text": "Call blocked: recipient outside company.com domain."
}
```

---

## 4. Setup & Running on Windows

### Prerequisites
- Python 3.10+ (Tested on Python 3.14 on Windows)
- Node.js 18+ and npm (Tested on Node v24.12.0)
- Windows PowerShell 5.1+ or PowerShell 7+

### 1-Command Unified Startup (Recommended)
From the repository root, run:
```powershell
.\dev.ps1
```
This script automatically:
1. Verifies Python and Node/npm runtimes.
2. Creates `.venv` and verifies Python dependencies.
3. Installs `dashboard/node_modules` if needed.
4. Starts FastAPI backend on `http://127.0.0.1:8000` (Swagger docs at `/docs`).
5. Starts React/Vite dashboard on `http://127.0.0.1:5173`.
6. Gracefully shuts down child processes on Ctrl+C.

### Separate Startup (Fallback)
If you prefer running backend and frontend in separate terminals:

**Terminal 1 — Backend:**
```powershell
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — Frontend Dashboard:**
```powershell
cd dashboard
npm run dev
```

---

## 5. Verification & Testing

### 1. Python Smoke Tests (12 Tests, 9 Stages)
Run the deterministic verification suite:
```powershell
python spec/smoke_test.py
```
Covers:
- Frozen v2 schemas, `final_reply` step type, exact analyzer rules, feedback validation, and non-inflation of recorded findings.
- The complete 9-stage pipeline:
  1. `GET /health`
  2. `GET /target/configs` (called before target assignment)
  3. `POST /assessments`
  4. `POST /assessments/{id}/target` (and invalid target rejection)
  5. `POST /assessments/{id}/runs`
  6. `GET /assessments/{id}/runs` & `GET /runs/{run_id}` (verifying trace steps including `final_reply`)
  7. `GET /assessments/{id}/findings` (verifying exact rule IDs)
  8. `GET /assessments/{id}/defenses`, toggle, and `POST /assessments/{id}/challenge` (verifying adaptive generation)
  9. `POST /assessments/{id}/retest`, `GET /assessments/{id}/report`, `POST /assessments/{id}/verify-chain`, and `POST /assessments/{id}/tamper-test`

### 2. Python Compilation Check
```powershell
python -m compileall spec api
```

### 3. Frontend Production Build Check
```powershell
cd dashboard
npm run build
```

---

## 6. API Reference (Frozen P0 Endpoints)

Interactive documentation is available at `http://127.0.0.1:8000/docs`.

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health and system readiness |
| `GET` | `/target/configs` | List target configurations (demo first, real validation errors) |
| `POST` | `/assessments` | Create a new assessment session |
| `GET` | `/assessments` | List all stored assessment sessions |
| `GET` | `/assessments/{id}` | Retrieve full assessment session by ID |
| `POST` | `/assessments/{id}/target` | Assign a validated target agent to an assessment |
| `POST` | `/assessments/{id}/runs` | Execute benchmark attack suite against target |
| `GET` | `/assessments/{id}/runs` | Retrieve all execution runs for an assessment |
| `GET` | `/runs/{run_id}` | Retrieve run metadata and step-by-step trace |
| `GET` | `/assessments/{id}/findings` | Retrieve discovered security findings (filter by `?source=`) |
| `GET` | `/assessments/{id}/defenses` | List defense controls (D1–D3, with stub indicators) |
| `POST` | `/assessments/{id}/defenses/{id}/toggle` | Toggle defense guard on/off |
| `POST` | `/assessments/{id}/challenge` | Trigger adaptive challenge feedback loop (`generated` variant) |
| `POST` | `/assessments/{id}/retest` | Run comparative retest (before vs after exploit & pass rates) |
| `GET` | `/assessments/{id}/report` | Generate structured assessment report with disclosures |
| `POST` | `/assessments/{id}/verify-chain` | Verify cryptographic SHA-256 evidence hash chain |
| `POST` | `/assessments/{id}/tamper-test` | Run isolated tamper detection demonstration on disposable fixture |
| `GET` | `/recorded/runs` | Inspect sanitized recorded baseline fixture |

---

## 7. Presentation & Demo Guides

- **Live Walkthrough Script:** See [DEMO_SCRIPT.md](file:///c:/Users/Rohit%20Patil/OneDrive/Documents/ByteForge%20Hackathon/ByteForge_college_round/DEMO_SCRIPT.md) for a timed 3–4 minute presentation guide.
- **Pitch & Q&A Defense:** See [PITCH.md](file:///c:/Users/Rohit%20Patil/OneDrive/Documents/ByteForge%20Hackathon/ByteForge_college_round/PITCH.md) for core pitch statements and prepared answers to evaluator questions.
