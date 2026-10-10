"""AgentBreak Specification Package.

Contains shared v2 contract schemas, types, validation utilities,
and smoke tests for cross-module integration.
"""

from spec.schema import (
    EXACT_ANALYZER_RULE_IDS,
    FINDING_SOURCES,
    VALID_FEEDBACK_TYPES,
    VALID_STEP_TYPES,
    AttackerFeedback,
    Finding,
    FindingSource,
    RuleId,
    Trace,
    TraceStep,
    is_adaptive_discovery,
    validate_attacker_feedback,
    validate_finding,
    validate_trace,
)

__all__ = [
    "EXACT_ANALYZER_RULE_IDS",
    "FINDING_SOURCES",
    "VALID_FEEDBACK_TYPES",
    "VALID_STEP_TYPES",
    "AttackerFeedback",
    "Finding",
    "FindingSource",
    "RuleId",
    "Trace",
    "TraceStep",
    "is_adaptive_discovery",
    "validate_attacker_feedback",
    "validate_finding",
    "validate_trace",
]
