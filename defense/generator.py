"""Candidate Defense Generator for AgentBreak.

Owned by P3 (Defense & Evaluation).
Analyzes confirmed exploit findings and proposes targeted, minimal, and secure policy mutations:
- D1: Tool parameter constraint tightening (domain normalization, customer RBAC, forbidden tools).
- D2: Taint tracking enforcement and untrusted memory write protection.
- D3: Output filtering, canary secret redaction, and quarantine rate limiting.

Produces structured DefenseCandidate objects with explicit PolicyDiff and security rationales.
"""

import copy
import uuid
from typing import Any, Dict, List, Optional, Tuple

from defense.models import DefenseCandidate, PolicyDiff


def compute_policy_diff(base: Dict[str, Any], candidate: Dict[str, Any], prefix: str = "") -> PolicyDiff:
    """Compute a recursive structural diff between base and candidate policy configurations."""
    added: Dict[str, Any] = {}
    modified: Dict[str, Any] = {}
    removed: Dict[str, Any] = {}
    summary_lines: List[str] = []

    all_keys = set(base.keys()) | set(candidate.keys())
    for k in sorted(all_keys):
        full_key = f"{prefix}.{k}" if prefix else k
        if k not in base:
            added[full_key] = candidate[k]
            summary_lines.append(f"Added '{full_key}': {candidate[k]}")
        elif k not in candidate:
            removed[full_key] = base[k]
            summary_lines.append(f"Removed '{full_key}'")
        else:
            base_val = base[k]
            cand_val = candidate[k]
            if isinstance(base_val, dict) and isinstance(cand_val, dict):
                sub_diff = compute_policy_diff(base_val, cand_val, prefix=full_key)
                added.update(sub_diff.added)
                modified.update(sub_diff.modified)
                removed.update(sub_diff.removed)
                if sub_diff.summary:
                    summary_lines.extend(sub_diff.summary.split("\n"))
            elif base_val != cand_val:
                modified[full_key] = {"from": base_val, "to": cand_val}
                summary_lines.append(f"Modified '{full_key}': {base_val} -> {cand_val}")

    return PolicyDiff(
        added=added,
        modified=modified,
        removed=removed,
        summary="\n".join(summary_lines) if summary_lines else "No changes",
    )


def generate_candidate_policy(
    finding: Dict[str, Any],
    current_policy: Dict[str, Any],
    target_config: Dict[str, Any],
    base_version_id: str = "v1.0.0",
) -> DefenseCandidate:
    """Propose an adaptive candidate policy mutation based on an identified vulnerability finding.

    Analyzes finding rule and details to synthesize a targeted, minimal defense.
    """
    rule_fired = finding.get("rule_fired") or finding.get("rule")
    details = finding.get("details", {})
    target_id = target_config.get("id", "demo-company-assistant")

    new_policy = copy.deepcopy(current_policy)
    if "guard" not in new_policy:
        new_policy["guard"] = {}

    rationale = ""
    mutation_type = "policy_hardening"

    # 1. Finding: canary_in_final_reply -> D3 Output Filter activation
    if rule_fired == "canary_in_final_reply":
        new_policy["guard"]["output_filter"] = True
        new_policy["guard"]["redact_canaries"] = True
        new_policy["guard"]["deny_canary_leak"] = True
        if "quarantine" not in new_policy["guard"]:
            new_policy["guard"]["quarantine"] = {"enabled": True, "deny_threshold": 3}
        rationale = (
            "Detected canary secret leak in final agent reply. Activated Defense D3 output filter "
            "with automatic [REDACTED_SECRET] sanitization and quarantine lockout."
        )
        mutation_type = "canary_redaction_filter"

    # 2. Finding: canary_in_executed_args -> D1/D3 argument inspection
    elif rule_fired == "canary_in_executed_args":
        new_policy["guard"]["scan_tool_args_for_canaries"] = True
        if "send_email" not in new_policy:
            new_policy["send_email"] = {}
        new_policy["send_email"]["block_canaries"] = True
        new_policy["send_email"]["disallow_internal_relays"] = True
        rationale = (
            "Detected canary token smuggled into tool execution arguments. Enforced pre-execution "
            "canary inspection across sensitive tool parameters and blocked internal exfiltration relays."
        )
        mutation_type = "parameter_canary_inspection"

    # 3. Finding: executed_outside_policy -> D1 domain tightening, customer RBAC, or forbidden tools
    elif rule_fired == "executed_outside_policy":
        reason = str(details.get("reason", "")).lower()

        if "email" in reason or "domain" in reason or "recipient" in reason:
            if "send_email" not in new_policy:
                new_policy["send_email"] = {}
            # Clean and tighten allowed domains from target_config tool config
            email_tool = next(
                (t for t in target_config.get("tools", []) if t.get("name") == "send_email"),
                {},
            )
            raw_domains = email_tool.get("allowed_domains", ["company.com"])
            clean_domains = [d.strip().lower() for d in raw_domains if "@" not in d]
            new_policy["send_email"]["allowed_domains"] = clean_domains or ["company.com"]
            new_policy["send_email"]["strict_domain_validation"] = True
            new_policy["send_email"]["strip_whitespace"] = True
            rationale = (
                f"Unauthorized external email attempt detected. Tightened D1 send_email domain whitelist "
                f"to strictly enforce {new_policy['send_email']['allowed_domains']} with trimmed whitespace validation."
            )
            mutation_type = "domain_whitelist_tightening"

        elif "customer" in reason or "cust-" in reason or "role" in reason or "limit" in reason:
            if "read_customer_record" not in new_policy:
                new_policy["read_customer_record"] = {}
            new_policy["read_customer_record"]["roles"] = ["support"]
            new_policy["read_customer_record"]["max_per_run"] = 1
            rationale = (
                "Out-of-scope customer record access detected. Restricted D1 read_customer_record role "
                "to ['support'] and strictly capped max queries per run to 1."
            )
            mutation_type = "customer_rbac_hardening"

        elif "delete" in reason or "forbidden" in reason or "file" in reason:
            forbidden = new_policy["guard"].get("forbidden_tools", [])
            if "delete_file" not in forbidden:
                forbidden.append("delete_file")
            new_policy["guard"]["forbidden_tools"] = forbidden
            if "delete_file" not in new_policy:
                new_policy["delete_file"] = {}
            new_policy["delete_file"]["allowed"] = False
            rationale = (
                "Attempted execution of prohibited destructive tool. Explicitly added 'delete_file' "
                "to D1 forbidden_tools policy with allowed=False."
            )
            mutation_type = "forbidden_tool_enforcement"

        else:
            # General policy tightening
            new_policy["guard"]["fail_closed"] = True
            rationale = "General out-of-policy violation. Configured fail_closed enforcement."
            mutation_type = "fail_closed_hardening"

    # 4. Finding: memory_write_untrusted -> D2 Taint Tracking enforcement
    elif rule_fired == "memory_write_untrusted":
        if "write_memory" not in new_policy:
            new_policy["write_memory"] = {}
        new_policy["write_memory"]["allow_untrusted_source"] = False
        new_policy["write_memory"]["strict_taint_enforcement"] = True
        forbidden_keys = new_policy["write_memory"].get("forbidden_keys", [])
        for k in ["security_override", "admin_bypass", "allow_all_domains", "privilege_escalation"]:
            if k not in forbidden_keys:
                forbidden_keys.append(k)
        new_policy["write_memory"]["forbidden_keys"] = forbidden_keys
        rationale = (
            "Untrusted persistent memory tampering detected. Enforced Defense D2 strict taint tracking, "
            "disabled allow_untrusted_source, and blacklisted override keys."
        )
        mutation_type = "taint_tracking_enforcement"

    else:
        # Fallback hardening
        new_policy["guard"]["fail_closed"] = True
        rationale = f"Enforced fail_closed policy protection for unclassified rule '{rule_fired}'."
        mutation_type = "general_hardening"

    # Compute policy diff
    diff = compute_policy_diff(current_policy, new_policy)

    candidate_id = f"cand-{uuid.uuid4().hex[:8]}"
    return DefenseCandidate(
        candidate_id=candidate_id,
        target_id=target_id,
        base_version_id=base_version_id,
        proposed_policy=new_policy,
        diff=diff,
        trigger_finding=finding,
        status="pending",
        rejection_reason=None,
    )


def validate_candidate_supported(candidate: DefenseCandidate) -> Tuple[bool, Optional[str]]:
    """Validate that candidate proposes only supported and enforceable policy mutations.

    Returns (is_valid, rejection_reason).
    """
    if not isinstance(candidate, DefenseCandidate):
        return False, "Candidate is not an instance of DefenseCandidate."

    proposed = candidate.proposed_policy
    if not isinstance(proposed, dict):
        return False, "Proposed policy must be a dictionary."

    # Validate guard settings if present
    guard_cfg = proposed.get("guard", {})
    if not isinstance(guard_cfg, dict):
        return False, "Proposed policy 'guard' section must be a dictionary."

    # Validate supported tool policies
    supported_tool_keys = {
        "send_email": {"allowed_domains", "strict_domain_validation", "strip_whitespace", "block_canaries", "disallow_internal_relays", "name", "description", "parameters", "sensitive"},
        "read_customer_record": {"roles", "max_per_run", "name", "description", "parameters", "sensitive"},
        "write_memory": {"allow_untrusted_source", "strict_taint_enforcement", "forbidden_keys", "name", "description", "parameters", "sensitive"},
        "delete_file": {"allowed", "name", "description", "parameters", "sensitive"},
        "read_doc": {"name", "description", "parameters", "sensitive", "allowed"},
        "search_kb": {"name", "description", "parameters", "sensitive", "allowed"},
        "read_memory": {"name", "description", "parameters", "sensitive", "allowed"},
        "guard": {"output_filter", "redact_canaries", "deny_canary_leak", "quarantine", "scan_tool_args_for_canaries", "forbidden_tools", "fail_closed"},
    }

    for section, rules in proposed.items():
        if section not in supported_tool_keys:
            return False, f"Unsupported policy section '{section}'. Only supported tools and guard rules may be proposed."
        if not isinstance(rules, dict):
            return False, f"Policy section '{section}' must be a dictionary."
        allowed_keys = supported_tool_keys[section]
        unknown_keys = set(rules.keys()) - allowed_keys
        if unknown_keys:
            return False, f"Unsupported policy rule keys {sorted(unknown_keys)} in section '{section}'."

    # Validate type constraints
    if "send_email" in proposed:
        domains = proposed["send_email"].get("allowed_domains")
        if domains is not None and not isinstance(domains, list):
            return False, "send_email.allowed_domains must be a list of domain strings."

    if "read_customer_record" in proposed:
        roles = proposed["read_customer_record"].get("roles")
        if roles is not None and not isinstance(roles, list):
            return False, "read_customer_record.roles must be a list of role strings."
        max_run = proposed["read_customer_record"].get("max_per_run")
        if max_run is not None and (not isinstance(max_run, int) or max_run <= 0):
            return False, "read_customer_record.max_per_run must be a positive integer."

    return True, None
