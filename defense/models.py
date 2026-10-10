"""Data models and schemas for AgentBreak Defense and Evaluation Engine.

Owned by P3 (Defense & Evaluation).
Defines:
- PolicyVersion: Immutable versioned snapshot of target security policies.
- PolicyDiff: Detailed diff between two policy configurations.
- DefenseCandidate: Proposed policy change generated in response to an exploit.
- EvaluationScorecard: Strict evaluation scorecard verifying candidate against
  security improvement and legitimate task preservation (zero regressions).
"""

from dataclasses import asdict, dataclass, field
import datetime
from typing import Any, Dict, List, Optional


@dataclass
class PolicyDiff:
    """Represents differences between a base policy and a proposed candidate."""
    added: Dict[str, Any] = field(default_factory=dict)
    modified: Dict[str, Any] = field(default_factory=dict)
    removed: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "added": self.added,
            "modified": self.modified,
            "removed": self.removed,
            "summary": self.summary,
        }


@dataclass
class EvaluationScorecard:
    """Metrics and gatekeeper verdict for a candidate defense evaluation."""
    candidate_id: str
    target_id: str
    gatekeeper_verdict: str  # "ACCEPTED" or "REJECTED"
    exploit_mitigated: bool
    adaptive_exploit_mitigated: bool
    baseline_exploits_tested: int
    baseline_exploits_blocked: int
    legit_tasks_total: int
    legit_tasks_passed: int
    legit_task_pass_rate: float
    rejection_reasons: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "target_id": self.target_id,
            "gatekeeper_verdict": self.gatekeeper_verdict,
            "exploit_mitigated": self.exploit_mitigated,
            "adaptive_exploit_mitigated": self.adaptive_exploit_mitigated,
            "baseline_exploits_tested": self.baseline_exploits_tested,
            "baseline_exploits_blocked": self.baseline_exploits_blocked,
            "legit_tasks_total": self.legit_tasks_total,
            "legit_tasks_passed": self.legit_tasks_passed,
            "legit_task_pass_rate": self.legit_task_pass_rate,
            "rejection_reasons": self.rejection_reasons,
            "latency_ms": self.latency_ms,
            "details": self.details,
        }


@dataclass
class PolicyVersion:
    """Versioned immutable policy record."""
    version_id: str  # e.g. "v1.0.0", "v1.1.0"
    target_id: str
    status: str  # "active", "candidate", "rejected", "archived", "rolled_back"
    policy: Dict[str, Any]
    parent_version_id: Optional[str] = None
    rationale: str = ""
    mutation_type: str = "baseline"
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "target_id": self.target_id,
            "status": self.status,
            "parent_version_id": self.parent_version_id,
            "policy": self.policy,
            "rationale": self.rationale,
            "mutation_type": self.mutation_type,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass
class DefenseCandidate:
    """A proposed defense candidate undergoing or pending isolated evaluation."""
    candidate_id: str
    target_id: str
    base_version_id: str
    proposed_policy: Dict[str, Any]
    diff: PolicyDiff
    trigger_finding: Optional[Dict[str, Any]] = None
    status: str = "pending"  # "pending", "evaluating", "accepted", "rejected"
    scorecard: Optional[EvaluationScorecard] = None
    rejection_reason: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "target_id": self.target_id,
            "base_version_id": self.base_version_id,
            "proposed_policy": self.proposed_policy,
            "diff": self.diff.to_dict() if isinstance(self.diff, PolicyDiff) else self.diff,
            "trigger_finding": self.trigger_finding,
            "status": self.status,
            "scorecard": self.scorecard.to_dict() if isinstance(self.scorecard, EvaluationScorecard) else self.scorecard,
            "rejection_reason": self.rejection_reason,
            "created_at": self.created_at,
        }
