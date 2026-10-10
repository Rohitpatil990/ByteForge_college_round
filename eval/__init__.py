"""AgentBreak Evaluation Package.

Owned by P3 (Defense & Evaluation).
Computes metrics, benchmarks attack success rates, and generates security assessment summaries.
Provides isolated defense candidate evaluation and gatekeeper verification.
"""

from eval.defense_evaluator import DefenseEvaluator, evaluate_candidate_defense

__all__ = [
    "DefenseEvaluator",
    "evaluate_candidate_defense",
]
