"""
Chapters 8 to 11 for AgentBreak V2 Technical Guide.
Includes Chapter 8 (Dashboard Metrics & Formulas), Chapter 9 (SHA-256 Evidence Chain),
Chapter 10 (Security Report), and Chapter 11 (Hackathon Demonstration Guide).
"""

from reportlab.platypus import (
    Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak, HRFlowable
)
from reportlab.lib.colors import HexColor
from generate_guide_base import (
    USABLE_WIDTH, make_callout, make_code_box, make_table
)

def build_chapter_8(styles):
    story = []
    story.append(Paragraph("CHAPTER 8: DASHBOARD METRICS & COUNTING FORMULAS", styles['ChapterHeading']))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#e2e8f0'), spaceBefore=4, spaceAfter=10))
    
    story.append(Paragraph("8.1 Mathematical Formulas and Data Sources", styles['SectionHeading']))
    story.append(Paragraph(
        "A critical test of an engineer's depth is knowing exactly how dashboard numbers are calculated. "
        "Do not guess or assume numbers from a screenshot; here are the exact formulas audited from the codebase:",
        styles['BodyCustom']
    ))
    
    metric_headers = ["Metric Label", "Source Property", "Exact Mathematical Formula", "Storage State"]
    metric_rows = [
        ["Attacks That Succeeded", "runs array", "count(r for r in runs if r.verdict == 'confirmed_exploit')", "Dynamically computed from runs"],
        ["Attacks Blocked", "runs array", "count(r for r in runs if r.verdict in ['blocked', 'blocked_attempt'])", "Dynamically computed (normalized)"],
        ["Total Tests", "runs array", "len(runs) (total executed traces in current session)", "Dynamically computed from runs"],
        ["Problems Found", "findings array", "len(findings) (deduplicated unique vulnerability instances)", "Persisted in AssessmentStore"],
        ["Recent Tests", "runs array", "runs[-5:] (most recent 5 execution traces in reverse order)", "Dynamically sliced"],
        ["Security Issues Detected", "findings array", "count(f for f in findings if f.status == 'open')", "Persisted in AssessmentStore"]
    ]
    story.append(make_table(metric_headers, metric_rows, [115, 95, 185, 110], styles))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("8.2 Why Findings Count Differs from Attacks Succeeded", styles['SectionHeading']))
    story.append(Paragraph(
        "Hackathon judges often ask: <i>'Why do you have 8 attacks that succeeded, but only 3 problems found?'</i><br/>"
        "<b>The Answer: Intelligent Deduplication.</b> If 5 different test cases all succeed in exfiltrating data via the same unvalidated "
        "`send_email` tool, they represent 5 successful exploit executions, but only <b>1 underlying root vulnerability</b>. "
        "AgentBreak deduplicates findings using the composite key: `${target_id}::${rule_fired}::${tool_involved}`. "
        "This mirrors enterprise CVE reporting standards and prevents alert fatigue.",
        styles['BodyCustom']
    ))
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("8.3 Verdict Normalization: 'blocked' vs 'blocked_attempt'", styles['SectionHeading']))
    story.append(Paragraph(
        "In the backend (`analyzer/core.py`), the canonical verdict string for an intercepted attack is `blocked_attempt`. "
        "However, legacy test fixtures and some mock seeds used the shortened string `blocked`. "
        "In `dashboard/src/App.tsx`, the frontend normalizes both values: "
        "`const blocked = runs.filter(r => r.verdict === 'blocked' || r.verdict === 'blocked_attempt').length;`. "
        "This ensures metrics remain perfectly synchronized regardless of whether fixtures or live API runs are displayed.",
        styles['BodyCustom']
    ))
    
    story.append(PageBreak())
    return story

def build_chapter_9(styles):
    story = []
    story.append(Paragraph("CHAPTER 9: EVIDENCE INTEGRITY & SHA-256 HASH CHAIN", styles['ChapterHeading']))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#e2e8f0'), spaceBefore=4, spaceAfter=10))
    
    story.append(Paragraph("9.1 Cryptographic Foundations: SHA-256", styles['SectionHeading']))
    story.append(Paragraph(
        "In enterprise and legal environments, security test reports are only valuable if they cannot be secretly edited after the fact. "
        "If a rogue developer could alter a test trace from `confirmed_exploit` to `blocked_attempt`, the audit is compromised. "
        "AgentBreak solves this using a <b>SHA-256 Cryptographic Hash Chain</b>.",
        styles['BodyCustom']
    ))
    story.append(Paragraph(
        "SHA-256 (Secure Hash Algorithm 256-bit) is a one-way cryptographic hash function. Given any input text, it generates a unique "
        "64-character hexadecimal string. It has two essential properties: <b>Preimage Resistance</b> (impossible to reverse-engineer input "
        "from hash) and the <b>Avalanche Effect</b> (changing a single character in the input completely randomizes the resulting hash).",
        styles['BodyCustom']
    ))
    
    story.append(Paragraph("9.2 How the Hash Chain Links Records", styles['SectionHeading']))
    story.append(Paragraph(
        "Every execution run generates an immutable Evidence Block containing: the block index, timestamp, run ID, trace payload, and "
        "the hash of the previous block. The mathematical formula for block <i>i</i> is:",
        styles['BodyCustom']
    ))
    story.append(make_code_box(
        "# Mathematical Hash Chain Formula:\n"
        "Block_0 (Genesis): prev_hash = '0000000000000000000000000000000000000000000000000000000000000000'\n"
        "Block_i: hash_i = SHA256( prev_hash_{i-1} + canonical_json_dumps(block_data_i) )",
        styles
    ))
    story.append(Paragraph(
        "Because each block embeds the hash of the preceding block, any alteration to block #2 immediately breaks the hash of block #3, "
        "block #4, and so on, propagating all the way to the root hash.",
        styles['BodyCustom']
    ))
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("9.3 Tamper Demonstration and Verification", styles['SectionHeading']))
    story.append(Paragraph(
        "The AgentBreak dashboard includes an interactive tamper verification suite in `dashboard/src/components/EvidenceChainView.tsx`:<br/>"
        "• <b>Verify Integrity:</b> Sequentially recalculates hashes from Block 0 to N. If all hashes match, a green confirmation badge appears: "
        "<i>'Chain Valid: 100% Immutable'</i>.<br/>"
        "• <b>Simulate Tamper:</b> Intentionally modifies a single character in an earlier test trace in memory and re-runs verification. "
        "The verifier instantly detects the anomaly, highlighting the exact invalid block and showing how subsequent blocks failed.",
        styles['BodyCustom']
    ))
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("9.4 Honest Security Reality: Internal vs. External Anchoring", styles['SectionHeading']))
    story.append(make_callout(
        "Crucial Judge Insight: An internal hash chain proves that records have not been accidentally corrupted or modified "
        "in storage. However, if a privileged server administrator has full root access to the database, they could rewrite the "
        "entire history and recompute ALL hashes from scratch. To prevent this, future production releases will anchor the root "
        "hash to an external public ledger (such as Ethereum, RFC 6962 Certificate Transparency log, or AWS CloudTrail KMS). "
        "Explaining this limitation demonstrates master-level security maturity.",
        title="LIMITATION & FUTURE EXTERNAL ANCHORING",
        alert_type="security",
        styles=styles
    ))
    
    story.append(PageBreak())
    return story

def build_chapter_10(styles):
    story = []
    story.append(Paragraph("CHAPTER 10: THE SECURITY ASSESSMENT REPORT", styles['ChapterHeading']))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#e2e8f0'), spaceBefore=4, spaceAfter=10))
    
    story.append(Paragraph("10.1 Executive Report Contents", styles['SectionHeading']))
    story.append(Paragraph(
        "The Security Assessment Report (`dashboard/src/components/ReportView.tsx`) compiles the comprehensive results of an "
        "adversarial audit into a formal executive document. The report structure conforms to enterprise vulnerability reporting guidelines:",
        styles['BodyCustom']
    ))
    story.append(Paragraph(
        "1. <b>Executive Summary:</b> Target agent name, test timestamp, total tests conducted, overall security score, and risk rating.<br/>"
        "2. <b>Test & Finding Counts:</b> Breakdown of confirmed exploits vs blocked attempts vs benign runs.<br/>"
        "3. <b>Confirmed Exploit Breakdown:</b> Detailed descriptions of every verified vulnerability, including the rule fired, tool involved, and severity.<br/>"
        "4. <b>Defense Posture Status:</b> Explicit disclosures of active guards (D1 Tool Guard, D2 Memory Guard) and stubbed defenses (D3 Reply Filter).<br/>"
        "5. <b>Cryptographic Root Hash:</b> The final SHA-256 ledger digest serving as an immutable audit seal.<br/>"
        "6. <b>JSON Export:</b> Standardized machine-readable assessment payload for automated ingestion into CI/CD security pipelines.",
        styles['BodyCustom']
    ))
    story.append(Spacer(1, 6))
    
    story.append(Paragraph("10.2 Generating and Exporting Reports", styles['SectionHeading']))
    story.append(Paragraph(
        "To generate and export the report during a live review:<br/>"
        "• Navigate to the <b>Security Report</b> tab in the sidebar.<br/>"
        "• Click <b>'Export JSON'</b> to download the complete assessment dataset, or use your browser's Print dialog (Ctrl+P) to save as a clean PDF.<br/>"
        "• The report serves as verifiable compliance evidence for stakeholder reviews.",
        styles['BodyCustom']
    ))
    
    story.append(PageBreak())
    return story

def build_chapter_11(styles):
    story = []
    story.append(Paragraph("CHAPTER 11: COMPLETE HACKATHON DEMONSTRATION GUIDE", styles['ChapterHeading']))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#e2e8f0'), spaceBefore=4, spaceAfter=10))
    
    story.append(Paragraph("11.1 Pre-Demonstration Checklist", styles['SectionHeading']))
    story.append(Paragraph(
        "Before judges arrive at your station, complete this 5-point verification checklist:",
        styles['BodyCustom']
    ))
    story.append(Paragraph("□ <b>Backend Running:</b> Confirm FastAPI is listening on port 8000.", styles['BulletCustom']))
    story.append(Paragraph("□ <b>Frontend Running:</b> Confirm Vite dev server is running on port 5173, or open Vercel production URL.", styles['BulletCustom']))
    story.append(Paragraph("□ <b>Browser Prepared:</b> Clean browser tab opened to http://localhost:5173 (zoom level 100%).", styles['BulletCustom']))
    story.append(Paragraph("□ <b>Clean Session:</b> Click 'New Session' or 'Seed Default Data' to ensure realistic KPIs are populated.", styles['BulletCustom']))
    story.append(Paragraph("□ <b>Backup Tab Ready:</b> Have the live production Vercel deployment (https://dashboard-bay-one-15.vercel.app) loaded in a secondary tab in case of local machine issues.", styles['BulletCustom']))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("11.2 Terminal Startup Commands", styles['SectionHeading']))
    story.append(Paragraph(
        "Use these verified terminal commands in PowerShell from the repository directory:",
        styles['BodyCustom']
    ))
    story.append(make_code_box(
        "# Terminal 1 - Start Backend API Server (from ByteForge_college_round):\n"
        "python -m uvicorn api.main:app --host 127.0.0.1 --port 8000\n"
        "# Expected Output: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)\n\n"
        "# Terminal 2 - Start Frontend Dashboard (from ByteForge_college_round/dashboard):\n"
        "npm run dev\n"
        "# Expected Output: Local: http://localhost:5173/",
        styles
    ))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph("11.3 Scripted 7-Step Hackathon Presentation Walkthrough", styles['SectionHeading']))
    
    steps = [
        ("Step 1: Introduction & Overview",
         "Show the Overview page. Point to the 4 KPI cards and explain: 'This is AgentBreak V2. We test autonomous AI agents by executing controlled adversarial attacks, intercepting policy violations with deterministic guards, and logging cryptographic proof.'"),
        ("Step 2: Triggering Benchmark Tests",
         "Navigate to 'Run Security Test' and click 'Execute Benchmark Suite'. Explain: 'We are now firing a battery of prompt injection, canary leakage, unauthorized tool, and memory write attacks against our demo assistant.'"),
        ("Step 3: Deep Trace Inspection",
         "Go to 'Test Runs' and click 'Inspect Trace' on a blocked attack. Show the multi-turn trace modal: 'Notice the agent thought about calling send_email to an external domain, but our D1 Tool Domain Guard intercepted the parameters and denied execution.'"),
        ("Step 4: Reviewing Deduplicated Findings",
         "Navigate to 'Problems Found'. Show the deduplicated vulnerability cards: 'Notice that multiple exploit attempts are grouped into root vulnerability findings using our composite deduplication key, preventing alert fatigue.'"),
        ("Step 5: Demonstrating the Adaptive Attacker",
         "Go to 'Try a New Attack'. Launch an adaptive attack. Explain: 'When an initial attack is blocked, human hackers don't stop. Our adaptive engine reads the rejection reason and mutates its strategy across 7 distinct attack modes.'"),
        ("Step 6: Showing Defenses & Retest",
         "Open 'Protection'. Show D1 and D2 active guards. State honestly: 'D1 and D2 are enforced; D3 is currently a development stub. We can apply hardened candidate policies and run a comparative retest to verify exploit reduction.'"),
        ("Step 7: Cryptographic Tamper Test",
         "Navigate to 'Check Evidence'. Click 'Verify Integrity' (shows green valid chain). Then click 'Simulate Tamper'. Watch the chain break: 'Because every test is linked in a SHA-256 hash chain, any retroactive tampering is immediately caught.'")
    ]
    for s_title, s_desc in steps:
        story.append(Paragraph(f"<b>{s_title}:</b> {s_desc}", styles['BodyCustom']))
        story.append(Spacer(1, 3))
        
    story.append(Spacer(1, 6))
    story.append(Paragraph("11.4 Troubleshooting and Quick Fixes", styles['SectionHeading']))
    story.append(Paragraph(
        "• <b>Port 8000 in use:</b> Run `netstat -ano | findstr 8000` and terminate the orphaned python process via `taskkill /F /PID <pid>`.<br/>"
        "• <b>Offline/Airplane Mode:</b> The frontend includes built-in offline fixtures. Toggle the 'Offline Fixture' button to seamlessly demonstrate all 12 views without any network connection.",
        styles['BodyCustom']
    ))
    
    story.append(PageBreak())
    return story

print("Chapters 8 to 11 module configured.")
