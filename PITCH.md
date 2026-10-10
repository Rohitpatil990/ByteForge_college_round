# AgentBreak — Pitch Deck & Evaluator Q&A Guide

**Target Presentation Time:** 3–4 minutes  
**Target Audience:** Hackathon Judges, Security Evaluators, AI Engineers

---

## 1. Core Pitch Statement

> **“AgentBreak is an AI-agent security testing platform that discovers vulnerabilities, records reproducible execution evidence, and evaluates defenses through an adaptive attacker that challenges the fixes. It measures whether the tested defenses prevent exploitation while preserving legitimate functionality.”**

---

## 2. Pitch Structure (3–4 Minutes)

| Timing | Segment | Key Talking Points |
| :--- | :--- | :--- |
| **0:00 – 0:30** | **The Security Problem** | Static prompt testing fails against agents that interact with tools and maintain state. When an LLM receives refusal feedback, an intelligent attacker adapts. |
| **0:30 – 0:50** | **The AgentBreak Solution** | A unified closed-loop platform: seed attack benchmarking, denial-reason feedback loops, SHA-256 evidence audit trails, and dual-metric evaluation (security vs utility). |
| **0:50 – 2:50** | **Live Interactive Demo** | 1. Select demo target (`demo-company-assistant.yaml`).<br>2. Run seed attacks.<br>3. Inspect trace with `final_reply` & verify SHA-256 evidence chain.<br>4. Trigger adaptive challenge using feedback (`deny_reason`).<br>5. Retest and inspect final report with real denominators (`2 / 3`). |
| **2:50 – 3:30** | **Honest Limitations & Next Steps** | Exact string canary limitations, tool checks vs reply text leakage, D3 stub boundary, and roadmap for P1–P3 teammate module integration. |

---

## 3. Anticipated Questions & Prepared Answers

### Q1: "Isn't this just the problem statement?"
> **Prepared Answer:**  
> **“The problem statement lists the individual parts. Our contribution is the closed loop connecting them: the attacker uses the guard's denial reasons to challenge each fix, and every reported number comes from a saved run.”**

### Q2: "Can AgentBreak test any arbitrary agent codebase?"
> **Prepared Answer:**  
> **“No, and we make that limitation explicit in our report. Targets must be defined through structured configuration files specifying tool schemas and policy references. The demo agent is our working sample; arbitrary agent code is not supported without a corresponding target configuration.”**

### Q3: "Does AgentBreak guarantee that an agent is secure?"
> **Prepared Answer:**  
> **“No automated tool can prove an agent is immune to jailbreaks or prompt injection. Furthermore, our leak detection currently relies on plain string matching of synthetic canaries, which does not detect encoded, hashed, or translated secrets. AgentBreak provides an empirical benchmark and audit trail, not a proof of absolute security.”**

### Q4: "Why do tool-call guardrails fail to stop canary leaks?"
> **Prepared Answer:**  
> **“Tool-call guards (like D1 and D2) inspect outgoing function calls. If an attacker tricks the agent into outputting the secret directly to the user in its reply text (`final_reply`), no tool call is made. This is why our platform specifically isolates output filters (D3) as a separate defense layer.”**

### Q5: "How are recorded baseline benchmarks handled in the metrics?"
> **Prepared Answer:**  
> **“Recorded findings are tagged with an amber `[RECORDED]` badge and reported in their own distinct category. They are never counted as adaptive discoveries, ensuring that benchmark statistics are never artificially inflated.”**
