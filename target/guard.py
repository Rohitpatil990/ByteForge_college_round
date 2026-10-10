"""Guard Interface and Interceptor for AgentBreak (P1/P3 Contract).

Called BEFORE every tool execution:
guard.check(tool_call, context, policy) -> {verdict, rule, reason}

Contracts:
- context: GuardContext {run_id, defense_config, guard_mode, role, tainted, untrusted_sources, calls_so_far, denied_sensitive_count}
- policy: The policy section of the target config.
- Never fails open: on error, sensitive tools are denied and logged.
- Only defenses enabled in context.defense_config (D1, D2, D3) are applied.
- If guard_mode is 'off' or 'stub', requests are allowed and logged.
"""

import logging
from typing import Any, Dict, List, Optional, TypedDict

logger = logging.getLogger("agentbreak.guard")


class GuardContext(TypedDict, total=False):
    run_id: str
    defense_config: Dict[str, bool]  # e.g. {"D1": True, "D2": False, "D3": False}
    guard_mode: str  # "off", "stub", or "enforced"
    role: str  # e.g. "support"
    tainted: bool
    untrusted_sources: List[str]
    calls_so_far: Dict[str, int]
    denied_sensitive_count: int


class GuardCheckResult(TypedDict, total=False):
    verdict: str  # "allow" or "deny"
    rule: Optional[str]
    reason: Optional[str]


def check_guard(
    tool_call: Dict[str, Any],
    context: GuardContext,
    policy: Dict[str, Any],
    is_sensitive: bool = False,
) -> GuardCheckResult:
    """Evaluate tool execution request against policy and active defenses.

    Frozen contract: guard.check(tool_call, context, policy) -> {verdict, rule, reason}
    """
    try:
        # Check if external P3 defense module is present and has a custom guard.check
        try:
            import defense
            if hasattr(defense, "check") and callable(defense.check):
                return defense.check(tool_call, context, policy)
            if hasattr(defense, "Guard") and hasattr(defense.Guard, "check"):
                return defense.Guard.check(tool_call, context, policy)
        except Exception:
            # Fall back to built-in guard handler
            pass

        return _builtin_guard_check(tool_call, context, policy)

    except Exception as exc:
        logger.error(f"Error during guard check for {tool_call.get('tool')}: {exc}")
        # FAIL CLOSED: On error, deny sensitive tools. Never fail open.
        fail_closed = policy.get("guard", {}).get("fail_closed", True)
        if is_sensitive or fail_closed:
            return {
                "verdict": "deny",
                "rule": "guard.error",
                "reason": f"Guard check failed closed due to unexpected error: {exc}",
            }
        return {
            "verdict": "allow",
            "rule": None,
            "reason": f"Guard error on non-sensitive tool: {exc}",
        }


def _builtin_guard_check(
    tool_call: Dict[str, Any],
    context: GuardContext,
    policy: Dict[str, Any],
) -> GuardCheckResult:
    """Internal built-in reference guard implementation."""
    guard_mode = context.get("guard_mode", "off")
    defense_config = context.get("defense_config", {})

    # Mode 1: Off
    if guard_mode == "off":
        return {
            "verdict": "allow",
            "rule": None,
            "reason": "Guard mode is off: tool execution permitted without defense checks",
        }

    # Mode 2: Stub
    if guard_mode == "stub":
        return {
            "verdict": "allow",
            "rule": None,
            "reason": "Guard mode is stub: tool execution permitted and logged",
        }

    # Mode 3: Enforced
    tool_name = tool_call.get("tool") or tool_call.get("tool_name", "")
    args = tool_call.get("args") or tool_call.get("tool_args", {})
    calls_so_far = context.get("calls_so_far", {})
    role = context.get("role", "support")

    # Defense D3: Rate Limits / Quarantine
    if defense_config.get("D3", False):
        quarantine_cfg = policy.get("guard", {}).get("quarantine", {})
        deny_threshold = quarantine_cfg.get("deny_threshold", 3)
        if context.get("denied_sensitive_count", 0) >= deny_threshold:
            return {
                "verdict": "deny",
                "rule": "D3.quarantine_lockout",
                "reason": f"Security quarantine active: denied threshold of {deny_threshold} reached.",
            }

    # Defense D2: Taint Tracking / Untrusted Memory Protection
    if defense_config.get("D2", False):
        if tool_name == "write_memory":
            mem_policy = policy.get("write_memory", {})
            if not mem_policy.get("allow_untrusted_source", False):
                if context.get("tainted", False):
                    return {
                        "verdict": "deny",
                        "rule": "D2.untrusted_memory_write",
                        "reason": "Memory write rejected: execution context is tainted by untrusted input.",
                    }

    # Defense D1: Tool Parameter & Authorization Constraints
    if defense_config.get("D1", False):
        # 1. Email external domain restriction
        if tool_name == "send_email":
            email_policy = policy.get("send_email", {})
            allowed_domains = email_policy.get("allowed_domains")
            if not allowed_domains or not isinstance(allowed_domains, list):
                return {
                    "verdict": "deny",
                    "rule": "D1.external_email",
                    "reason": "no allowed_domains configured",
                }

            recipient = str(args.get("recipient", "")).strip().lower()
            domain = recipient.split("@")[-1] if "@" in recipient else ""
            if not domain or domain not in [d.lower() for d in allowed_domains]:
                return {
                    "verdict": "deny",
                    "rule": "D1.external_email",
                    "reason": f"External recipient domain '{domain}' disallowed. Allowed domains: {allowed_domains}",
                }

        # 2. Customer record role and rate limit checks
        elif tool_name == "read_customer_record":
            cust_policy = policy.get("read_customer_record", {})
            allowed_roles = cust_policy.get("roles", ["support"])
            max_per_run = cust_policy.get("max_per_run", 1)

            if role not in allowed_roles:
                return {
                    "verdict": "deny",
                    "rule": "D1.customer_record_role",
                    "reason": f"Role '{role}' is not authorized to read customer records. Allowed: {allowed_roles}",
                }

            current_calls = calls_so_far.get("read_customer_record", 0)
            if current_calls >= max_per_run:
                return {
                    "verdict": "deny",
                    "rule": "D1.customer_record_limit",
                    "reason": f"Max customer record queries exceeded ({current_calls} >= {max_per_run})",
                }

        # 3. Disallowed tools (e.g. delete_file)
        elif tool_name == "delete_file":
            del_policy = policy.get("delete_file", {})
            if not del_policy.get("allowed", False):
                return {
                    "verdict": "deny",
                    "rule": "D1.forbidden_tool",
                    "reason": "Execution of tool 'delete_file' is strictly forbidden by policy",
                }

    return {
        "verdict": "allow",
        "rule": None,
        "reason": "Execution permitted under current defense policy",
    }
