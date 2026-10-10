# AgentBreak — AI-Agent Security Testing Platform

AgentBreak is an AI-agent security testing platform built to evaluate agent boundaries, policy conformance, and prompt injection resistance through adaptive testing and canary tracking.

---

## 1. Project Purpose & Honest Limitations

### Purpose
AgentBreak provides an automated testing harness for LLM agents to:
- Test policy constraints against adversarial and edge-case inputs.
- Track canary token leakage across tool execution arguments and final replies.
- Distinguish baseline/recorded fixtures from dynamic adaptive discoveries.
- Offer a minimal, standardized API contract across attacker, target sandbox, analyzer, and defense modules.

### Critical Limitations & Security Assumptions
1. **Canary String Matching Limitations**: Plain string matching only detects exact matching synthetic canary tokens. It does **not** guarantee detection of encoded (e.g., Base64, Hex, URL-encoded), hashed, paraphrased, translated, or transformed secrets.
2. **Tool Policy Enforcement vs. Final Reply Leakage**: Tool-call policy enforcement checks whether an authorized tool was invoked with allowed parameters. Blocking or restricting a tool call does **not** automatically prevent sensitive content or secret leakage from appearing in the final assistant reply (`final_reply`).
3. **Target Scope**: The target configuration is specifically bound to the configured synthetic demo agent (`demo-company-assistant`). The platform does not claim universal compatibility with arbitrary unconfigured agent code.
4. **Guard Failure Mode**: The policy engine and security guards fail closed (`guard_fail_mode: closed`). In the event of ambiguity, parsing failure, or unexpected states, actions are blocked by default.
5. **No Universal Guarantee**: Passing automated test suites or finding zero vulnerabilities in a test run does not prove or guarantee that an agent is immune to jailbreaks or prompt injections.

---

## 2. Project Structure & Module Ownership

```text
ByteForge_college_round/
├── spec/                       # [P4] Shared frozen contract, schemas, and smoke tests
│   ├── __init__.py
│   ├── schema.py               # Frozen v2 contract (Trace, Finding, Feedback, Rules)
│   └── smoke_test.py           # Verification suite
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
│   └── routes.py               # /health, /target/configs, /assessments/{id}/target
├── dashboard/                  # Frontend / UI dashboard
├── data/                       # Data storage
│   └── recorded/               # Sanitized recorded demo baseline fixtures
├── requirements.txt            # Python dependencies
├── .env.example                # Example environment configuration
├── .gitignore                  # Git exclusions for secrets, builds, and generated data
├── policy.yaml                 # Master security policy definitions (fail-closed)
├── dev.ps1                     # Windows PowerShell development boot script
└── README.md                   # This documentation
```

### Module Ownership Matrix
| Module | Lead | Responsibilities | Status |
| :--- | :--- | :--- | :--- |
| **Foundation & Integration** (`spec/`, `api/`) | **P4** | Shared v2 schemas, FastAPI routes, target listing, smoke tests, dev script | **Complete** |
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
  "type": "bot_reply",   // or "deny_reason"
  "rule": "executed_outside_policy", // optional
  "text": "Call blocked: recipient outside company.com domain."
}
```

---

## 4. Setup & Running on Windows

### Prerequisites
- Python 3.10+ (Tested on Python 3.14 on Windows)
- PowerShell 5.1+ or PowerShell 7+

### Environment Setup
1. Clone or navigate to the repository directory:
   ```powershell
   cd ByteForge_college_round
   ```
2. Copy the example environment file:
   ```powershell
   Copy-Item .env.example .env
   ```
3. Create and activate a virtual environment (optional if using `dev.ps1`):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

### Running Smoke Tests
Run the deterministic verification suite:
```powershell
python spec/smoke_test.py
```
Expected output:
```text
test_api_health ... ok
test_assessment_target_selection ... ok
test_target_configs_listing ... ok
test_exact_analyzer_rule_ids ... ok
test_finding_source_and_rule_fired ... ok
test_invalid_feedback_rejection ... ok
test_invalid_finding_rejection ... ok
test_required_trace_fields ... ok
test_trace_step_types_including_final_reply ... ok
test_trace_validation_missing_required_fields ... ok
test_valid_feedback_types ... ok

Ran 11 tests in ...s
OK
```

### Starting the API Server
Use the provided PowerShell boot script:
```powershell
.\dev.ps1
```
Or start Uvicorn directly:
```powershell
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 5. API Endpoints

| Method | Path | Description | Sample Response |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Check service health | `{"status": "ok", "service": "AgentBreak API", "version": "0.1.0"}` |
| `GET` | `/target/configs` | List target configurations | `[{"id": "demo-company-assistant", "name": "Demo Company Assistant", "valid": true, "validation_error": null}]` |
| `POST` | `/assessments/{id}/target` | Select assessment target | `{"assessment_id": "demo-01", "target_id": "demo-company-assistant", "status": "target_selected", ...}` |
| `GET` | `/docs` | Interactive Swagger API documentation | Swagger UI |

### Verifying Endpoints via PowerShell
```powershell
# Check health
Invoke-RestMethod -Uri http://127.0.0.1:8000/health

# List target configurations
Invoke-RestMethod -Uri http://127.0.0.1:8000/target/configs

# Select assessment target
Invoke-RestMethod -Uri http://127.0.0.1:8000/assessments/test-1/target -Method Post -ContentType "application/json" -Body '{"target_id": "demo-company-assistant"}'
```

---

## 6. Team Collaboration & Git Branching Workflow

To prevent conflicts and contract drift across P1, P2, P3, and P4:

1. **Feature Branches**: Every teammate must work on a dedicated feature branch:
   - P1: `git checkout -b feature/p1-agent-sandbox`
   - P2: `git checkout -b feature/p2-attacker-analyzer`
   - P3: `git checkout -b feature/p3-defense-evaluation`
2. **Contract Invariance**: Do not modify `spec/schema.py` without team consensus. If new fields are needed, coordinate with P4.
3. **No Secrets**: Never commit `.env` or sensitive credentials. `.gitignore` is pre-configured to exclude local environments, generated reports, and cached outputs.
4. **Smoke Test Verification**: Run `python spec/smoke_test.py` before submitting pull requests.
