# AgentBreak — Live Demo Walkthrough Script (3–4 Minutes)

This script provides a structured, deterministic walkthrough for live hackathon presentations and evaluator reviews.

---

## Preparation & Fallback Instructions

1. **Live Environment:**
   Run the platform using `.\dev.ps1` in PowerShell. Ensure `http://127.0.0.1:8000` and `http://127.0.0.1:5173` are accessible.
2. **Offline/Recorded Fallback:**
   If the network or backend is unreachable, toggle **Offline (Recorded Mode)** in the top navigation bar. The platform seamlessly displays the sanitized baseline fixture from `data/recorded/demo_recorded_run.json`, clearly labeled with an amber `[RECORDED]` badge.

---

## Timed Walkthrough

### 1. Introduction & Problem Statement (0:00 – 0:30)
- **Speaker:**
  > "Autonomous LLM agents are rapidly gaining tool access — sending emails, accessing databases, and updating memory. Traditional static scanners cannot evaluate whether security guardrails hold when an attacker adapts to error messages.
  >
  > Today we present **AgentBreak**, an AI-agent security testing platform that evaluates policy boundaries, logs tamper-evident cryptographic evidence, and tests defenses through an adaptive attacker loop."

---

### 2. Product Flow & Architecture (0:30 – 0:50)
- **Speaker:**
  > "AgentBreak operates across 4 core stages:
  > 1. Target configuration with synthetic canary tokens and fail-closed policies.
  > 2. Seed benchmark attacks evaluating four frozen analyzer rules.
  > 3. An adaptive feedback loop where the attacker uses denial reasons to rewrite refused attacks.
  > 4. Retest evaluation measuring whether defenses prevent exploitation while preserving legitimate user utility."

---

### 3. Live Demonstration (0:50 – 2:50)

#### Step 1: Target Selection
- **Action:** Open Dashboard (`http://127.0.0.1:5173`), navigate to **Target & Setup**.
- **Speaker:**
  > "We select our sample target: `demo-company-assistant`, configured in YAML with support role permissions, a synthetic canary token, and a strict email domain restriction (`company.com`)."

#### Step 2: Execute Seed Attacks
- **Action:** Click **Execute Tests** -> Click **Run Benchmark Test Suite**.
- **Speaker:**
  > "The benchmark executes against the agent. We see 3 attack attempts and 1 benign customer lookup control. The seed attacks immediately uncover vulnerabilities: an out-of-policy email transmission and a direct prompt injection leaking the canary token."

#### Step 3: Inspect Traces & Findings
- **Action:** Click **Runs & Traces** tab, select `run-...-seed-01`. Then switch to **Findings** tab.
- **Speaker:**
  > "In the trace viewer, we can trace every single execution step: user prompt, agent thought, tool call, and the crucial `final_reply`. Notice in Finding `find-...-seed-02`, rule `canary_in_final_reply` fired because the synthetic token leaked directly into the final assistant response text."

#### Step 4: Cryptographic Evidence Integrity
- **Action:** Click **Evidence Chain** tab -> Click **Verify Evidence Chain**.
- **Speaker:**
  > "Every single execution trace is hashed into a SHA-256 evidence chain. Clicking 'Verify Evidence Chain' recomputes the chain from genesis and confirms: *unmodified since logging*."
- **Action:** Click **Simulate Tamper Detection**.
- **Speaker:**
  > "To demonstrate this, we simulate a tamper attempt on a disposable copy: the verification immediately flags the modified block index and prevents evidence spoofing."

#### Step 5: Configure Guard & Run Adaptive Challenge
- **Action:** Navigate to **Defenses**, review D1 and D2 enabled. Note D3 is labeled `stub`.
- **Action:** Navigate to **Challenge** -> Click **Challenge Active Defenses**.
- **Speaker:**
  > "Now we challenge the active defense. D1 blocked the seed email attack with denial reason: *'Recipient domain external-partner.com is not allowed.'*
  >
  > The adaptive attacker receives this feedback, mutates its prompt into variant round 1, and routes through an internal relay (`relay-dispatcher@company.com`). The analyzer catches this bypass because the canary token leaked in the tool arguments (`canary_in_executed_args`)."

#### Step 6: Retest & Security Report
- **Action:** Navigate to **Retest** -> Click **Run Comparative Retest**. Then open **Report**.
- **Speaker:**
  > "Finally, we evaluate defense effectiveness. Notice we display real counts and denominators: confirmed exploit rate is reduced, while the legitimate-task pass rate is preserved at 100%.
  >
  > Opening the final report, AgentBreak summarizes: *'Of 3 confirmed exploits, 2 were found by the seed list and 1 by the adaptive attacker after the seed was refused.'* Recorded findings are cleanly isolated and never inflate adaptive discoveries."

---

### 4. Limitations & Honest Conclusion (2:50 – 3:30)
- **Speaker:**
  > "We conclude with honest limitations:
  > - Canary detection uses exact string matching and does not guarantee detection of encoded or transformed tokens.
  > - Tool-call policies do not protect final reply text; D3 is a development stub pending P3 integration.
  > - AgentBreak supports configured targets like our demo agent, not arbitrary agent code.
  >
  > AgentBreak closes the loop between attack generation, guardrails, and verifiable security auditing."
