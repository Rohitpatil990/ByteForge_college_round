"""Policy Registry and Version Management for AgentBreak.

Owned by P3 (Defense & Evaluation).
Manages:
- Version history (v1.0.0 -> v1.1.0 -> v1.2.0) with immutable snapshots.
- Storage in data/generated/policies_{target_id}.json.
- Isolated candidate testing via thread-safe scoped_override context manager.
- Safe rollback to previous policy versions.
"""

from contextlib import contextmanager
import copy
import json
import logging
from pathlib import Path
import threading
from typing import Any, Dict, Generator, List, Optional

from defense.models import DefenseCandidate, EvaluationScorecard, PolicyDiff, PolicyVersion

logger = logging.getLogger("agentbreak.defense.registry")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GENERATED_DIR = PROJECT_ROOT / "data" / "generated"


class PolicyRegistry:
    """Manages active, historic, and candidate security policies per target."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self._storage_dir = storage_dir or GENERATED_DIR
        self._lock = threading.RLock()
        self._thread_local = threading.local()
        self._versions: Dict[str, List[PolicyVersion]] = {}
        self._active_versions: Dict[str, PolicyVersion] = {}
        self._candidates: Dict[str, List[DefenseCandidate]] = {}
        self._override_policy: Dict[str, Optional[Dict[str, Any]]] = {}

    def reset(self, target_id: Optional[str] = None) -> None:
        """Reset in-memory and disk cache for testing or fresh initializations."""
        with self._lock:
            if target_id:
                self._versions.pop(target_id, None)
                self._active_versions.pop(target_id, None)
                self._candidates.pop(target_id, None)
                self._override_policy.pop(target_id, None)
                p = self._get_storage_path(target_id)
                if p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass
            else:
                self._versions.clear()
                self._active_versions.clear()
                self._candidates.clear()
                self._override_policy.clear()

    def _get_storage_path(self, target_id: str) -> Path:
        return self._storage_dir / f"policies_{target_id}.json"

    def _persist(self, target_id: str) -> None:
        """Persist versions and candidates to local disk if directory is writable."""
        try:
            self._storage_dir.mkdir(parents=True, exist_ok=True)
            path = self._get_storage_path(target_id)
            data = {
                "target_id": target_id,
                "active_version_id": self._active_versions.get(target_id).version_id if self._active_versions.get(target_id) else None,
                "versions": [v.to_dict() for v in self._versions.get(target_id, [])],
                "candidates": [c.to_dict() for c in self._candidates.get(target_id, [])],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning(f"Could not persist policy history for {target_id}: {exc}")

    def init_target(self, target_config: Dict[str, Any]) -> PolicyVersion:
        """Initialize baseline v1.0.0 policy for target if not already loaded."""
        target_id = target_config.get("id", "demo-company-assistant")
        with self._lock:
            # Check if file already exists
            path = self._get_storage_path(target_id)
            if path.exists() and target_id not in self._versions:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    versions = []
                    for v_dict in data.get("versions", []):
                        versions.append(
                            PolicyVersion(
                                version_id=v_dict["version_id"],
                                target_id=v_dict["target_id"],
                                status=v_dict["status"],
                                policy=v_dict["policy"],
                                parent_version_id=v_dict.get("parent_version_id"),
                                rationale=v_dict.get("rationale", ""),
                                mutation_type=v_dict.get("mutation_type", "baseline"),
                                created_at=v_dict.get("created_at"),
                                metadata=v_dict.get("metadata", {}),
                            )
                        )
                    self._versions[target_id] = versions

                    candidates = []
                    for c_dict in data.get("candidates", []):
                        diff_raw = c_dict.get("diff", {})
                        diff = PolicyDiff(
                            added=diff_raw.get("added", {}),
                            modified=diff_raw.get("modified", {}),
                            removed=diff_raw.get("removed", {}),
                            summary=diff_raw.get("summary", ""),
                        )
                        sc_raw = c_dict.get("scorecard")
                        sc = EvaluationScorecard(**sc_raw) if sc_raw else None
                        candidates.append(
                            DefenseCandidate(
                                candidate_id=c_dict["candidate_id"],
                                target_id=c_dict["target_id"],
                                base_version_id=c_dict["base_version_id"],
                                proposed_policy=c_dict["proposed_policy"],
                                diff=diff,
                                trigger_finding=c_dict.get("trigger_finding"),
                                status=c_dict.get("status", "pending"),
                                scorecard=sc,
                                rejection_reason=c_dict.get("rejection_reason"),
                                created_at=c_dict.get("created_at"),
                            )
                        )
                    self._candidates[target_id] = candidates

                    # Active version
                    active_id = data.get("active_version_id")
                    for v in versions:
                        if v.version_id == active_id:
                            self._active_versions[target_id] = v
                            break
                    if target_id not in self._active_versions and versions:
                        self._active_versions[target_id] = versions[-1]
                except Exception as exc:
                    logger.warning(f"Error loading persisted policy for {target_id}: {exc}")

            if target_id in self._active_versions:
                return self._active_versions[target_id]

            # Construct initial baseline v1.0.0
            base_policy = copy.deepcopy(target_config.get("policy", {}))
            if "guard" not in base_policy:
                base_policy["guard"] = {"fail_closed": True, "output_filter": False}

            # Seed tool policies from target_config.tools
            for tool in target_config.get("tools", []):
                tname = tool.get("name")
                if tname and tname not in base_policy:
                    base_policy[tname] = copy.deepcopy(tool)

            baseline = PolicyVersion(
                version_id="v1.0.0",
                target_id=target_id,
                status="active",
                policy=base_policy,
                parent_version_id=None,
                rationale="Initial baseline security policy loaded from target configuration.",
                mutation_type="baseline",
            )
            self._versions[target_id] = [baseline]
            self._active_versions[target_id] = baseline
            self._candidates[target_id] = []
            self._persist(target_id)
            return baseline

    def get_active_policy(self, target_id: str) -> Dict[str, Any]:
        """Return the current active policy (or temporary candidate override if set)."""
        with self._lock:
            override = self._override_policy.get(target_id)
            if override is not None:
                return override
            active = self._active_versions.get(target_id)
            if active:
                return copy.deepcopy(active.policy)
            return {}

    def get_active_version(self, target_id: str) -> Optional[PolicyVersion]:
        """Return current active PolicyVersion record."""
        with self._lock:
            return self._active_versions.get(target_id)

    def get_history(self, target_id: str) -> List[PolicyVersion]:
        """Return full policy version history for target."""
        with self._lock:
            return list(self._versions.get(target_id, []))

    def get_candidates(self, target_id: str) -> List[DefenseCandidate]:
        """Return all generated candidates for target."""
        with self._lock:
            return list(self._candidates.get(target_id, []))

    def add_candidate(self, candidate: DefenseCandidate) -> None:
        """Register a new candidate."""
        with self._lock:
            target_id = candidate.target_id
            if target_id not in self._candidates:
                self._candidates[target_id] = []
            # Prevent duplicate candidate IDs
            self._candidates[target_id] = [c for c in self._candidates[target_id] if c.candidate_id != candidate.candidate_id]
            self._candidates[target_id].append(candidate)
            self._persist(target_id)

    @contextmanager
    def scoped_override(self, target_id: str, candidate_policy: Dict[str, Any]) -> Generator[None, None, None]:
        """Context manager to test a candidate policy in memory without mutating active production state."""
        with self._lock:
            old_override = self._override_policy.get(target_id)
            self._override_policy[target_id] = candidate_policy
        self._thread_local.override = candidate_policy
        self._thread_local.target_id = target_id
        try:
            yield
        finally:
            with self._lock:
                self._override_policy[target_id] = old_override
            self._thread_local.override = None
            self._thread_local.target_id = None

    def get_current_override(self) -> Optional[Dict[str, Any]]:
        """Return currently active thread-scoped or target-scoped candidate policy override."""
        override = getattr(self._thread_local, "override", None)
        if override is not None:
            return override
        with self._lock:
            for tid, pol in self._override_policy.items():
                if pol is not None:
                    return pol
        return None

    def promote_candidate(
        self,
        candidate_id: str,
        scorecard: EvaluationScorecard,
    ) -> PolicyVersion:
        """Promote an accepted candidate to a new active version (e.g. v1.1.0)."""
        with self._lock:
            # Find candidate
            found_cand: Optional[DefenseCandidate] = None
            found_target: Optional[str] = None
            for tid, cands in self._candidates.items():
                for c in cands:
                    if c.candidate_id == candidate_id:
                        found_cand = c
                        found_target = tid
                        break
                if found_cand:
                    break

            if not found_cand or not found_target:
                raise ValueError(f"Candidate {candidate_id} not found in registry.")

            found_cand.status = "accepted"
            found_cand.scorecard = scorecard

            # Determine next version id
            versions = self._versions.get(found_target, [])
            current_active = self._active_versions.get(found_target)
            curr_v_str = current_active.version_id if current_active else "v1.0.0"
            try:
                parts = curr_v_str.lstrip("v").split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                next_version_id = f"v{major}.{minor + 1}.0"
            except Exception:
                next_version_id = f"v1.{len(versions)}.0"

            # Archive old active version
            if current_active:
                current_active.status = "archived"

            # Create new version
            new_version = PolicyVersion(
                version_id=next_version_id,
                target_id=found_target,
                status="active",
                policy=copy.deepcopy(found_cand.proposed_policy),
                parent_version_id=current_active.version_id if current_active else None,
                rationale=found_cand.diff.summary if found_cand.diff else "Evolved defense policy.",
                mutation_type="adaptive_evolution",
                metadata={"candidate_id": candidate_id, "scorecard": scorecard.to_dict()},
            )
            versions.append(new_version)
            self._versions[found_target] = versions
            self._active_versions[found_target] = new_version
            self._persist(found_target)
            return new_version

    def reject_candidate(
        self,
        candidate_id: str,
        scorecard: EvaluationScorecard,
        reason: str,
    ) -> None:
        """Mark a candidate as rejected with reason and evaluation metrics."""
        with self._lock:
            for tid, cands in self._candidates.items():
                for c in cands:
                    if c.candidate_id == candidate_id:
                        c.status = "rejected"
                        c.scorecard = scorecard
                        c.rejection_reason = reason
                        self._persist(tid)
                        return

    def rollback(self, target_id: str, target_version_id: Optional[str] = None) -> PolicyVersion:
        """Rollback target policy to parent or specified historic version."""
        with self._lock:
            versions = self._versions.get(target_id, [])
            current_active = self._active_versions.get(target_id)
            if not current_active:
                raise ValueError(f"No active version found for target {target_id}.")

            restore_target: Optional[PolicyVersion] = None
            if target_version_id:
                for v in versions:
                    if v.version_id == target_version_id:
                        restore_target = v
                        break
                if not restore_target:
                    raise ValueError(f"Version {target_version_id} not found in history for {target_id}.")
            else:
                # Roll back to parent
                parent_id = current_active.parent_version_id
                if parent_id:
                    for v in versions:
                        if v.version_id == parent_id:
                            restore_target = v
                            break
                if not restore_target and len(versions) > 1:
                    # Previous version before current
                    restore_target = versions[-2]

            if not restore_target:
                raise ValueError(f"Cannot rollback: no earlier version available for target {target_id}.")

            current_active.status = "rolled_back"
            restore_target.status = "active"
            self._active_versions[target_id] = restore_target
            self._persist(target_id)
            return restore_target


# Global registry singleton
_REGISTRY: Optional[PolicyRegistry] = None


def get_policy_registry() -> PolicyRegistry:
    """Retrieve the global policy registry instance."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PolicyRegistry()
    return _REGISTRY
