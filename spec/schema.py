"""Frozen Shared v2 Contract for AgentBreak.

This module defines the central, dependency-light schema for traces, findings,
analyzer rules, and attacker feedback across all AgentBreak modules (P1, P2, P3, P4).
"""

from typing import Any, Dict, List, Literal, Optional, Set, TypedDict, Union

# ---------------------------------------------------------------------------
# 1. Analyzer Rule IDs (Frozen)
# ---------------------------------------------------------------------------

RuleId = Literal[
    "canary_in_executed_args",
    "canary_in_final_reply",
    "executed_outside_policy",
    "memory_write_untrusted",
]

EXACT_ANALYZER_RULE_IDS: Set[str] = {
    "canary_in_executed_args",
    "canary_in_final_reply",
    "executed_outside_policy",
    "memory_write_untrusted",
}

# ---------------------------------------------------------------------------
# 2. Trace Step Types
# ---------------------------------------------------------------------------

StepType = Literal[
    "user_input",
    "agent_thought",
    "tool_call",
    "tool_result",
    "final_reply",
    "error",
]

VALID_STEP_TYPES: Set[str] = {
    "user_input",
    "agent_thought",
    "tool_call",
    "tool_result",
    "final_reply",
    "error",
}


class TraceStep(TypedDict, total=False):
    step_type: str  # Must be one of VALID_STEP_TYPES (including 'final_reply')
    content: str
    tool_name: Optional[str]
    tool_args: Optional[Dict[str, Any]]
    timestamp: Optional[str]
    metadata: Optional[Dict[str, Any]]


# ---------------------------------------------------------------------------
# 3. Trace Contract
# ---------------------------------------------------------------------------

class Trace(TypedDict, total=False):
    target_id: str
    kind: str  # e.g., "attack", "benign", "baseline"
    variant_source: str  # e.g., "seed", "generated_v1", "mutation"
    parent_run_id: Optional[str]  # None for seeds/root runs, ID of ancestor run otherwise
    round: int  # Iteration/round number (0-indexed or 1-indexed)
    steps: List[TraceStep]
    metadata: Optional[Dict[str, Any]]


REQUIRED_TRACE_FIELDS: Set[str] = {
    "target_id",
    "kind",
    "variant_source",
    "parent_run_id",
    "round",
}

# ---------------------------------------------------------------------------
# 4. Finding Contract
# ---------------------------------------------------------------------------

FindingSource = Literal["seed", "generated", "recorded"]

FINDING_SOURCES: Set[str] = {"seed", "generated", "recorded"}


class Finding(TypedDict, total=False):
    finding_id: str
    target_id: str
    source: FindingSource  # "seed", "generated", or "recorded"
    rule_fired: RuleId  # Must be one of EXACT_ANALYZER_RULE_IDS
    description: str
    severity: Optional[str]
    details: Optional[Dict[str, Any]]
    trace_id: Optional[str]


def is_adaptive_discovery(finding: Dict[str, Any]) -> bool:
    """Determine whether a finding represents a dynamic adaptive discovery.

    Frozen rule: Recorded findings and seed findings must NOT be counted as
    adaptive discoveries. Only 'generated' variants count as adaptive discoveries.
    """
    source = finding.get("source")
    return source == "generated"


# ---------------------------------------------------------------------------
# 5. Attacker Feedback Contract
# ---------------------------------------------------------------------------

FeedbackType = Literal["bot_reply", "deny_reason"]

VALID_FEEDBACK_TYPES: Set[str] = {"bot_reply", "deny_reason"}


class AttackerFeedback(TypedDict, total=False):
    type: FeedbackType  # "bot_reply" or "deny_reason"
    rule: Optional[str]  # Optional rule identifier where appropriate
    text: str  # Required feedback text


# ---------------------------------------------------------------------------
# 6. Contract Validators
# ---------------------------------------------------------------------------

def validate_attacker_feedback(data: Any) -> AttackerFeedback:
    """Validate the next_variant feedback structure.

    Expected structure:
    {
        "type": "bot_reply" or "deny_reason",
        "rule": "...",  # optional where appropriate
        "text": "..."
    }

    Raises:
        ValueError: If data is not a dict, type is invalid, or text is missing/empty.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Attacker feedback must be a dictionary, got {type(data).__name__}")

    fb_type = data.get("type")
    if fb_type not in VALID_FEEDBACK_TYPES:
        raise ValueError(
            f"Invalid feedback type: {fb_type!r}. Must be one of {sorted(VALID_FEEDBACK_TYPES)}"
        )

    text = data.get("text")
    if text is None:
        raise ValueError("Feedback must contain a 'text' field")
    if not isinstance(text, str):
        raise ValueError(f"'text' field must be a string, got {type(text).__name__}")
    if not text.strip():
        raise ValueError("'text' field must not be empty or whitespace only")

    rule = data.get("rule")
    if rule is not None and not isinstance(rule, str):
        raise ValueError(f"Optional 'rule' field must be a string or None, got {type(rule).__name__}")

    return {
        "type": fb_type,
        "text": text,
        "rule": rule,
    }


def validate_trace(data: Any) -> Trace:
    """Validate a Trace dictionary against the v2 contract.

    Raises:
        ValueError: If required fields are missing, invalid, or step types are unrecognized.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Trace must be a dictionary, got {type(data).__name__}")

    for field in REQUIRED_TRACE_FIELDS:
        if field not in data:
            raise ValueError(f"Trace missing required field: '{field}'")

    if not isinstance(data["target_id"], str) or not data["target_id"].strip():
        raise ValueError("Trace 'target_id' must be a non-empty string")

    if not isinstance(data["kind"], str) or not data["kind"].strip():
        raise ValueError("Trace 'kind' must be a non-empty string")

    if not isinstance(data["variant_source"], str) or not data["variant_source"].strip():
        raise ValueError("Trace 'variant_source' must be a non-empty string")

    if data["parent_run_id"] is not None and not isinstance(data["parent_run_id"], str):
        raise ValueError("Trace 'parent_run_id' must be None or a string")

    if not isinstance(data["round"], int) or data["round"] < 0:
        raise ValueError("Trace 'round' must be a non-negative integer")

    steps = data.get("steps", [])
    if not isinstance(steps, list):
        raise ValueError(f"Trace 'steps' must be a list, got {type(steps).__name__}")

    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(f"Step at index {idx} must be a dictionary")
        step_type = step.get("step_type")
        if step_type not in VALID_STEP_TYPES:
            raise ValueError(
                f"Step at index {idx} has invalid step_type {step_type!r}. "
                f"Must be one of {sorted(VALID_STEP_TYPES)}"
            )

    return data  # type: ignore[return-value]


def validate_finding(data: Any) -> Finding:
    """Validate a Finding dictionary against the v2 contract.

    Raises:
        ValueError: If source or rule_fired is invalid, or required fields are missing.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Finding must be a dictionary, got {type(data).__name__}")

    if "source" not in data:
        raise ValueError("Finding missing required field: 'source'")
    source = data["source"]
    if source not in FINDING_SOURCES:
        raise ValueError(
            f"Invalid finding source {source!r}. Must be one of {sorted(FINDING_SOURCES)}"
        )

    if "rule_fired" not in data:
        raise ValueError("Finding missing required field: 'rule_fired'")
    rule_fired = data["rule_fired"]
    if rule_fired not in EXACT_ANALYZER_RULE_IDS:
        raise ValueError(
            f"Invalid analyzer rule ID {rule_fired!r}. Must be one of {sorted(EXACT_ANALYZER_RULE_IDS)}"
        )

    return data  # type: ignore[return-value]
