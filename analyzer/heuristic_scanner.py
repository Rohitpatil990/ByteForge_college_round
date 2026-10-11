"""AgentBreak Heuristic Scanner for Browser Extension & Text Input.

Provides transparent, explainable rule-based pattern scanning for selected AI prompts,
agent replies, and conversation excerpts. Distinguishes between heuristic pattern matches
and execution-trace verified exploits.
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from analyzer.rules import extract_canaries, normalize_text


SCANNER_RULES = [
    {
        "id": "system_rule_override",
        "name": "System Rule Override Attempt",
        "severity": "HIGH",
        "patterns": [
            r"ignore\s+((all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|prompts?|constraints?|policies|policy)|(the\s+|all\s+|any\s+)?(security|safety|system|developer|model|agent)\s+(policies|policy|rules?|instructions?|prompts?|constraints?|guardrails?|guidelines?|restrictions?))",
            r"disregard\s+((all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|system\s+prompts?|constraints?|policies|policy)|(the\s+|all\s+|any\s+)?(security|safety|system|developer|model|agent)\s+(policies|policy|rules?|instructions?|prompts?|constraints?|guardrails?|guidelines?|restrictions?))",
            r"system\s+(prompt\s+)?override\s*[:\n]",
            r"emergency\s+(policy\s+|system\s+)?override",
            r"you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode",
            r"bypass\s+((all\s+|the\s+)?(safety|security|policy|system)\s+(policies|policy|filters?|boundaries?|checks?|rules?|guidelines?|restrictions?|guardrails?)|(the\s+|all\s+)?security\s+policy)",
            r"new\s+operating\s+instructions\s+supercede\s+all\s+prior",
            r"(do\s+not|never|don't)\s+(tell|inform|alert|notify|warn)\s+(the\s+)?(user|human|operator|admin|auditor)",
            r"override\s+(all\s+|the\s+)?(security|safety|system)\s+(policies|policy|rules?|checks?|restrictions?)",
        ],
        "explanation": "Text contains phrasing commonly used to confuse LLMs into abandoning system-level safety instructions.",
        "mitigation": "Review prompt origins; ensure the agent relies on rigid middleware guards rather than prompt obedience.",
    },
    {
        "id": "confidential_data_exfiltration",
        "name": "Confidential Data / Canary Exfiltration",
        "severity": "CRITICAL",
        "patterns": [
            r"CANARY-[a-zA-Z0-9_\-]+",
            r"(exfiltrat(e|ing)|leak(ing)?|dump(ing)?)\s+(all\s+)?(passwords?|credentials?|secrets?|tokens?|keys?|db)",
            r"(reveal|disclose|show|leak|extract|dump|output)\s+(all\s+|the\s+)?(synthetic\s+|internal\s+|confidential\s+|sensitive\s+|private\s+)?(canary|secret\s*keys?|api\s*keys?|tokens?|passwords?|credentials?|database|records?|private\s*keys?)",
            r"forward\s+(all\s+)?customer\s+data\s+to\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            r"(attach|send|forward|upload|transfer|email)\s+((all\s+)?(confidential|sensitive|company|internal|customer)\s+(documents?|files?|data|records?)\s+.*?\s+to\s+|.*?\s+to\s+)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            r"(send|forward|transmit|exfiltrate|leak)\s+(all\s+)?(confidential|sensitive|company|internal|customer)\s+(documents?|files?|data|records?|credentials?)\s+to",
            r"send\s+(the\s+)?(canary|secret)\s+to\s+https?://",
        ],
        "explanation": "Text references synthetic canaries, credentials, or explicit exfiltration commands to external destinations.",
        "mitigation": "Redact any sensitive identifiers before submitting; verify tool arguments never include canary values.",
    },
    {
        "id": "tool_permission_manipulation",
        "name": "Tool Permission / Privilege Manipulation",
        "severity": "HIGH",
        "patterns": [
            r"(call|execute|invoke)\s+(tool\s+)?(send_email|delete_file|execute_command|write_memory|query_database)\s*\(",
            r"(use|execute|call|run|invoke)\s+(the\s+)?([a-zA-Z0-9_]+\s+)?tool\s+(with(out)?\s+(asking\s+for\s+)?permission|without\s+(user\s+)?(approval|consent|confirmation))",
            r"grant\s+(all\s+|unauthorized\s+|unrestricted\s+|elevated\s+|forbidden\s+|full\s+|root\s+|admin\s+|superuser\s+)*(tools?|tool)?\s*(permissions?|access|privileges?|authorization|override)",
            r"permission\s+to\s+(access|read|modify|delete|exfiltrate)\s+confidential\s+(files?|records?|data|documents?|databases?)",
            r"(always\s+)?(approve|grant|allow|permit)\s+(all\s+)?(requests?\s+to\s+)?(access|read|modify|delete|exfiltrate)\s+(confidential|sensitive|restricted|internal|protected)\s+(files?|records?|data|documents?|databases?)",
            r"elevate\s+(privilege\s+level|permissions?)\s+to\s+(admin|root|system)",
            r"recipient_domain\s*=\s*['\"][^'\"]*evil\.[a-z]+['\"]",
        ],
        "explanation": "Text contains directives to invoke privileged tools or escalate administrative permissions.",
        "mitigation": "Enforce strict Tool Domain Policy Guards (D1) so tools cannot execute outside authorized whitelists.",
    },
    {
        "id": "context_smuggling",
        "name": "Context Smuggling / Embedded Payload",
        "severity": "MEDIUM",
        "patterns": [
            r"<!--\s*.*?(instruction|override|execute|system).*?-->",
            r"\[SYSTEM\s+NOTICE\s*:\s*.*?\]",
            r"\[ADMIN\s+(DIRECTIVE|OVERRIDE|NOTICE)\s*:\s*.*?\]",
            r"BEGIN\s+SYSTEM\s+(OVERRIDE|INSTRUCTION|DIRECTIVE)",
            r"<<<\s*OVERRIDE\s*>>>",
            r"IMPORTANT\s+ADMIN\s+MEMO\s*:\s*",
            r"\{\s*\"system_instruction\"\s*:\s*\"[^\"]+\"\s*\}",
            r"/\*\s*SYSTEM\s+(OVERRIDE|INSTRUCTION|DIRECTIVE).*?\*/",
        ],
        "explanation": "Text disguises instructions inside comments, brackets, or structured envelopes to bypass surface-level filters.",
        "mitigation": "Treat all retrieved external data as untrusted text; do not concatenate untrusted strings into system instructions.",
    },
    {
        "id": "memory_poisoning_directive",
        "name": "Memory Poisoning Directive",
        "severity": "HIGH",
        "patterns": [
            r"remember\s+(this\s+|that\s+)?for\s+(all\s+)?future\s+(conversations?|sessions?|chats?|interactions?|prompts?|turns?|contexts?)\s*[:\.]?",
            r"(admin_override|privilege_override|system_override)\s*=\s*(true|1|yes|active|enabled|all)",
            r"store\s+in\s+(persistent\s+)?(memory|state|scratchpad|context)\s+that",
            r"permanently\s+(update|change|set|modify)\s+your\s+(instructions?|beliefs?|persona|behavior|memory|rules?)\s+to",
            r"write_memory\s*\(\s*(key\s*=\s*)?['\"]?admin_override['\"]?",
            r"update_scratchpad\s*\(\s*privileged\s*=\s*true",
            r"persist\s+(this\s+)?across\s+(all\s+)?(conversations?|sessions?)",
        ],
        "explanation": "Text instructs the agent to persist untrusted instructions into memory, threatening future user sessions.",
        "mitigation": "Deploy Untrusted Memory Write Guards (D2) to reject state updates originating from unauthenticated users.",
    },
]


def scan_text_heuristics(
    text: str,
    target_config: Optional[Dict[str, Any]] = None,
    max_length: int = 16000,
) -> Dict[str, Any]:
    """Scans text against the explainable rule catalog and configured canary secrets.

    Returns a structured dictionary adhering to honest reporting principles:
    - Distinguishes heuristic pattern matches from execution-trace verified exploits.
    - Limits analyzed length for safety.
    """
    if not text or not text.strip():
        return {
            "status": "clean",
            "risk_level": "clean",
            "rules_matched": [],
            "summary": "No text provided for inspection.",
            "is_heuristic_only": True,
            "is_trace_verified": False,
        }

    # Bound content length safely
    analyzed_text = text[:max_length]
    matches: List[Dict[str, Any]] = []

    # 1. Check explainable scanner rules
    for rule in SCANNER_RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, analyzed_text, re.IGNORECASE)
            if match:
                matched_snippet = match.group(0)
                # Safely bound snippet length
                if len(matched_snippet) > 80:
                    matched_snippet = matched_snippet[:77] + "..."
                matches.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "confidence": "Heuristic Pattern Match",
                    "matched_snippet": matched_snippet,
                    "explanation": rule["explanation"],
                    "mitigation": rule["mitigation"],
                })
                break  # Don't add duplicate matches for same rule

    # 2. Check for target-specific configured canaries if target_config provided
    if target_config:
        canaries = extract_canaries(target_config)
        norm_text = normalize_text(analyzed_text)
        for canary in canaries:
            norm_canary = normalize_text(canary)
            if norm_canary and norm_canary in norm_text:
                matches.append({
                    "rule_id": "target_synthetic_canary_leakage",
                    "rule_name": f"Configured Canary Detected ({canary})",
                    "severity": "CRITICAL",
                    "confidence": "Exact Substring Match",
                    "matched_snippet": canary,
                    "explanation": f"The synthetic canary secret '{canary}' configured for target '{target_config.get('id', 'default')}' was identified in this text.",
                    "mitigation": "Redact the canary token immediately; verify which tool or prompt exposed it.",
                })
                break

    # Determine overall risk level
    if any(m["severity"] == "CRITICAL" for m in matches):
        overall_risk = "CRITICAL"
    elif any(m["severity"] == "HIGH" for m in matches):
        overall_risk = "HIGH"
    elif any(m["severity"] == "MEDIUM" for m in matches):
        overall_risk = "MEDIUM"
    elif matches:
        overall_risk = "LOW"
    else:
        overall_risk = "CLEAN"

    if matches:
        summary_text = (
            f"Heuristic scanner identified {len(matches)} suspicious pattern(s). "
            f"Highest severity: {overall_risk}. Note: This is an input pattern heuristic; "
            f"it does not prove an exploit executed without an agent trace."
        )
    else:
        summary_text = (
            "No known injection or exfiltration patterns matched. "
            "Note: The absence of heuristic matches does not guarantee safety against novel or encoded attacks."
        )

    return {
        "status": "completed",
        "risk_level": overall_risk,
        "rules_matched": matches,
        "summary": summary_text,
        "is_heuristic_only": True,
        "is_trace_verified": False,
        "content_length": len(analyzed_text),
    }
