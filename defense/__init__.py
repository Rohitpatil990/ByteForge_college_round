"""AgentBreak Defense Package.

Owned by P3 (Defense & Evaluation).
Provides guardrail enforcement, dynamic policy verification, adaptive defense evolution,
and active mitigation adapters.
"""

from defense.engine import Guard, check, filter_final_reply
from defense.evolution import DefenseEvolutionOrchestrator, get_evolution_orchestrator
from defense.generator import compute_policy_diff, generate_candidate_policy
from defense.models import (
    DefenseCandidate,
    EvaluationScorecard,
    PolicyDiff,
    PolicyVersion,
)
from defense.registry import PolicyRegistry, get_policy_registry

__all__ = [
    "check",
    "Guard",
    "filter_final_reply",
    "PolicyRegistry",
    "get_policy_registry",
    "generate_candidate_policy",
    "compute_policy_diff",
    "DefenseCandidate",
    "PolicyVersion",
    "EvaluationScorecard",
    "PolicyDiff",
    "DefenseEvolutionOrchestrator",
    "get_evolution_orchestrator",
]
