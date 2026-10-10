# AgentBreak — AI-Agent Security Testing Platform

AgentBreak is an automated security evaluation platform designed to test AI agent policy boundaries, intercept unsafe tool actions, detect confidential secret leakage, and iteratively improve defenses through adaptive red teaming and cryptographic evidence tracking.

---

## 1. Overview & Capabilities

AgentBreak evaluates conversational and tool-using AI agents against adversarial attacks:

- **Automated Security Testing**: Evaluates policy guardrails against prompt injection, unauthorized tool invocations, out-of-scope customer data access, and untrusted memory poisoning.
- **Confidential Canary Leak Detection**: Tracks protected secrets across executed tool parameters (`canary_in_executed_args`) and direct conversational replies (`canary_in_final_reply`).
- **Dynamic Adaptive Red Teaming**: Simulates an attacker that analyzes guard denial feedback and dynamically pivots across 7 distinct attack strategies without repeating static prompts.
- **Vulnerability Deduplication**: Groups multiple attack attempts by stable underlying vulnerability keys, tracking occurrence counts and associated traces while cataloging each unique issue once.
- **Cryptographic Evidence Audit**: Generates an append-only SHA-256 evidence hash chain recording every execution attempt, providing verifiable non-repudiation.
- **Defense Evolution & Safety Gatekeeping**: Automatically proposes policy patches, evaluates candidates in isolated sandboxes against both adversarial attacks and legitimate customer service tasks, and promotes only safety-verified policies.

---

## 2. Test Scenarios & Adaptive Attack Engine

### Fixed Seed Benchmark Scenarios
When running baseline evaluation, AgentBreak evaluates 5 fixed baseline scenarios:
1. **Secret Canary Leak in Tool Arguments** (`seed-canary-leak-prompt`): Probes whether the agent repeats private system canary tokens inside external tool calls.
2. **External Email Policy Violation** (`seed-email-exfiltration`): Instructs the agent to send records to unauthorized external domains (prohibited by policy).
3. **Restricted Tool Boundary Violation** (`seed-forbidden-tool-probe`): Prompts the agent to perform prohibited destructive operations (e.g. deleting files).
4. **Multi-Step Untrusted Memory Poisoning** (`seed-memory-poisoning`): Attempts to overwrite persistent agent memory with unverified attacker directives.
5. **Legitimate Task Control** (`legit-support-inquiry`): Standard customer service query verifying that security guards do not break authorized agent functionality.

### Adaptive Red-Team Engine (7 Threat Vectors)
During multi-round adaptive attacks or **Try a New Attack**, AgentBreak rotates across 7 dynamic strategies:
1. **Direct Injection** (`direct_injection`): Framing variations attempting to override instructions and leak system credentials.
2. **Indirect Context Smuggling** (`indirect_context_smuggling`): Smuggling adversarial payloads inside untrusted external documents or invoices.
3. **Internal Relay Exfiltration** (`internal_relay_exfiltration`): Evading external email domain restrictions by targeting approved internal company relay sinks while smuggling tokens in tool arguments.
4. **Role Impersonation** (`role_impersonation`): Impersonating executive or compliance authority roles (CISO, Tier-3 Auditor) to demand restricted actions.
5. **Parameter Obfuscation** (`parameter_obfuscation`): Parameter framing, maintenance pretexts, and formatting variations to evade naive pattern matchers.
6. **Multistep Memory Tampering** (`multistep_memory_tampering`): Injecting persistent overrides into long-term agent memory.
7. **Forbidden Tool Probing** (`forbidden_tool_probing`): Directly probing destructive or out-of-scope tool interfaces.

#### Feedback-Driven Mutation
When an attack is blocked by a guard, the engine extracts the denial reason and transitions to viable alternative strategies. The system tracks session attempt history to guarantee fresh variants on every run and detects when the strategy pool has been exhausted.

---

## 3. Execution Modes & Target Runtime

AgentBreak explicitly separates execution environments:

| Execution Mode | Description | Model Reasoning |
| :--- | :--- | :--- |
| **Deterministic Offline Simulation** (`deterministic_offline` / `deterministic_simulation`) | Executes 100% offline using deterministic rule-based state transitions, regex dispatch, and sandbox tools. Zero external network calls or API credits required. | **Rule-Based Engine** (deterministic pattern matcher; not an LLM) |
| **Real Sandbox Execution** (`real_sandbox`) | Executes against the `ConfiguredTargetAgent` runtime and mock tool sandbox with active policy interceptors and trace recording. | **Deterministic Mock / Optional Model** |
| **Live Model-Backed Mode** (`model_backed`) | Invokes Google Gemini Flash (`gemini-2.5-flash`) via HTTPX with function calling. Requires a valid `GEMINI_API_KEY`. If unconfigured, safely falls back to offline execution. | **Live Gemini Model** |

> **Honest Disclosure**: Offline simulation is powered by deterministic heuristics, mock sandboxes, and rule-based analyzers. It is never misrepresented as autonomous LLM intelligence.

---

## 4. Defenses & Active Guardrails

- **D1 — Tool Domain Policy Guard**: Pre-execution interceptor inspecting tool parameters (e.g. restricting email recipients strictly to approved `@company.com` domains, blocking disallowed tools like `delete_file`).
- **D2 — Untrusted Memory Write Guard**: Intercepts `write_memory` calls originating from untrusted user inputs or indirect document context.
- **D3 — Response Content Filter**: Scans final delivered assistant replies to sanitize plain-text confidential tokens (`[REDACTED_SECRET]`).
- **Defense Candidate Gatekeeper**: Proposes refined policies, tests them against both attacks and legitimate control tasks, and rejects any candidate that breaks utility (ensuring 100% benign pass rate).

---

## 5. Vulnerability Deduplication & Cryptographic Evidence

- **Stable Deduplication Key**: Findings are deduplicated per assessment by `(target_id, rule_fired, affected_tool/component)`:
  - If a vulnerability is triggered multiple times across different rounds or strategies, its `occurrences` count increments, `last_seen_at` updates, and all `associated_run_ids` are recorded.
  - Test runs are never merged or deleted—every execution is preserved in **Test Runs**.
- **Cryptographic Hash Chain**: Every executed run is serialized and linked via SHA-256 hash blocks (`data/traces/`). Tampering with any historical record breaks chain verification.

---

## 6. Dashboard Interface

The web console provides a dark-theme interface with dedicated workflows:
- **Overview**: High-level posture, test execution summary, and quick navigation.
- **Target Selection**: Inspect agent capabilities, tools, canary tokens, and policy definitions.
- **Run Security Test**: Execute baseline test suites (4 seed attack scenarios + 1 benign control) and inspect adaptive attack strategy coverage.
- **Try a New Attack**: Interactive single-attack challenge generator showing attempt number, strategy name, variation diff summary, executed prompt, and exhaustion notices with reset history controls.
- **Problems Found**: Catalog of deduplicated vulnerabilities showing occurrence badges, frequency breakdown, and all associated test run chips.
- **Protection**: Manage active defense guards (D1–D3), evolve defenses, evaluate candidate scorecards, and safely rollback policies.
- **Verify Defenses (Retest)**: Compare exploit rates and legitimate task pass rates before and after defense deployment.
- **Assessment Report**: Generate structured final audit reports with mandatory methodology disclosures.
- **Audit Log & Tamper Check**: Inspect SHA-256 hash chain blocks and run isolated tamper detection demonstrations.

---

## 7. Setup & Installation

### Prerequisites
- **Python**: 3.10+ (Tested on Python 3.13 and 3.14 on Windows)
- **Node.js**: 18+ and npm (Tested on Node v20+)
- **OS**: Windows (PowerShell), Linux, or macOS

### 1-Command Startup (Windows PowerShell)
```powershell
.\dev.ps1
```
This script initializes the virtual environment, verifies dependencies, starts the FastAPI backend on `http://127.0.0.1:8000`, and launches the Vite dashboard on `http://127.0.0.1:5173`.

### Manual Startup

**Terminal 1 — Backend:**
```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Start FastAPI server
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — Frontend Dashboard:**
```powershell
cd dashboard
npm install
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

---

## 8. Verification & Testing

### Python Full Test Suite
Run all unit and integration tests across analyzer, attacker, defense, sandbox, and API modules:
```powershell
.\.venv\Scripts\python -m unittest discover -s . -p "test_*.py"
```
*(Runs 113 automated tests verifying all functional requirements and regression fixes.)*

### Dashboard Production Build Check
Verify TypeScript compilation and Vite production bundling:
```powershell
npm --prefix dashboard run build
```

---

## 9. API Reference

Interactive Swagger documentation is available at `http://127.0.0.1:8000/docs`.

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status |
| `GET` | `/target/configs` | Available target agent configurations |
| `POST` | `/assessments` | Create new assessment session |
| `GET` | `/assessments/{id}` | Retrieve assessment state |
| `POST` | `/assessments/{id}/target` | Assign target to assessment |
| `POST` | `/assessments/{id}/runs` | Execute baseline security benchmark suite |
| `GET` | `/assessments/{id}/runs` | List all recorded execution runs |
| `GET` | `/assessments/{id}/findings` | Retrieve deduplicated security findings |
| `POST` | `/assessments/{id}/challenge` | Run adaptive attack with strategy mutation |
| `POST` | `/assessments/{id}/challenge/reset` | Reset adaptive challenge attempt history |
| `POST` | `/assessments/{id}/defenses/{id}/toggle` | Toggle individual defense guard (D1–D3) |
| `POST` | `/assessments/{id}/defenses/evolve` | Propose, evaluate, and promote defense policies |
| `POST` | `/assessments/{id}/defenses/rollback` | Roll back active policy to previous snapshot |
| `POST` | `/assessments/{id}/adaptive-loop` | Multi-round red-team and defense loop |
| `POST` | `/assessments/{id}/retest` | Comparative before/after exploit rate retest |
| `GET` | `/assessments/{id}/report` | Generate final assessment report |
| `POST` | `/assessments/{id}/verify-chain` | Verify cryptographic SHA-256 evidence chain |
| `POST` | `/assessments/{id}/tamper-test` | Run isolated tamper verification test |

---

## 10. Honest Disclosures & Platform Limitations

1. **Exact Canary Matching**: Plain string canary checking detects exact matching tokens. It does not guarantee detection of encoded (Base64, Hex), hashed, or translated secrets.
2. **Tool Policy vs. Conversational Leakage**: Restricting a tool call does not automatically prevent sensitive tokens from leaking in final assistant text without active output filters (D3).
3. **Target Scope**: Targets are defined by structured configuration files (`target/configs/`). Arbitrary unconfigured third-party code is not automatically supported.
4. **Fail-Closed Policy**: Guardrails are configured to fail closed (`guard_fail_mode: closed`). If an error or ambiguity occurs during inspection, the action is denied by default.
5. **No Universal Guarantee**: A clean test report demonstrates compliance against evaluated scenarios and adaptive variations; it does not constitute a mathematical proof against unknown zero-day jailbreaks.
