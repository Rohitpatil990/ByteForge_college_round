"""Defense Evolution Orchestrator for AgentBreak.

Owned by P3 (Defense & Evaluation).
Coordinates the complete adversarial learning loop:
1. Attack Execution & Vulnerability Detection (via Attacker + Analyzer).
2. Dynamic Candidate Policy Proposal (via Generator).
3. Isolated Sandbox Evaluation against adversarial & benign tasks (via Evaluator).
4. Automated Acceptance Gatekeeping (100% legitimate task pass rate required).
5. Version Promotion, History Tracking, and Rollback (via PolicyRegistry).
"""

import copy
import logging
from typing import Any, Callable, Dict, List, Optional

from analyzer.core import analyze
from attacker.strategy_engine import AttackStrategy, get_dynamic_engine, is_strategy_viable
from defense.generator import generate_candidate_policy, validate_candidate_supported
from defense.models import DefenseCandidate, EvaluationScorecard, PolicyVersion
from defense.registry import PolicyRegistry, get_policy_registry
from eval.defense_evaluator import DefenseEvaluator
from target.runner import run_agent

logger = logging.getLogger("agentbreak.defense.evolution")


class DefenseEvolutionOrchestrator:
    """Manages iterative defense improvement cycles."""

    def __init__(self, registry: Optional[PolicyRegistry] = None):
        self._registry = registry or get_policy_registry()
        self._evaluator = DefenseEvaluator(self._registry)

    def evolve(
        self,
        target_config: Dict[str, Any],
        findings: List[Dict[str, Any]],
        auto_promote: bool = True,
        seed: int = 42,
    ) -> Dict[str, Any]:
        """Execute defense evolution cycle for a set of confirmed vulnerability findings."""
        target_id = target_config.get("id", "demo-company-assistant")
        self._registry.init_target(target_config)

        active_ver = self._registry.get_active_version(target_id)
        current_policy = self._registry.get_active_policy(target_id)
        base_version_id = active_ver.version_id if active_ver else "v1.0.0"

        candidates_evaluated: List[Dict[str, Any]] = []
        accepted_count = 0
        rejected_count = 0

        for idx, finding in enumerate(findings):
            # 1. Propose candidate policy
            candidate = generate_candidate_policy(
                finding=finding,
                current_policy=current_policy,
                target_config=target_config,
                base_version_id=base_version_id,
            )
            self._registry.add_candidate(candidate)

            # Pre-validation: ensure candidate only proposes supported policy keys
            is_supported, unsupp_reason = validate_candidate_supported(candidate)
            if not is_supported:
                rejected_count += 1
                self._registry.reject_candidate(
                    candidate_id=candidate.candidate_id,
                    scorecard=None,
                    reason=unsupp_reason or "Unsupported policy rule",
                )
                candidates_evaluated.append({
                    "candidate_id": candidate.candidate_id,
                    "status": "rejected",
                    "promoted": False,
                    "diff": candidate.diff.to_dict(),
                    "rejection_reason": unsupp_reason,
                })
                continue

            # 2. Evaluate candidate in isolation
            scorecard = self._evaluator.evaluate_candidate(
                candidate=candidate,
                target_config=target_config,
                seed=seed + idx,
            )

            # 3. Gatekeeper decision & promotion
            if scorecard.gatekeeper_verdict == "ACCEPTED":
                accepted_count += 1
                if auto_promote:
                    new_version = self._registry.promote_candidate(
                        candidate_id=candidate.candidate_id,
                        scorecard=scorecard,
                    )
                    current_policy = self._registry.get_active_policy(target_id)
                    base_version_id = new_version.version_id

                candidates_evaluated.append({
                    "candidate_id": candidate.candidate_id,
                    "status": "accepted",
                    "promoted": auto_promote,
                    "diff": candidate.diff.to_dict(),
                    "scorecard": scorecard.to_dict(),
                })
            else:
                rejected_count += 1
                primary_reason = scorecard.rejection_reasons[0] if scorecard.rejection_reasons else "Gatekeeper criteria failed"
                self._registry.reject_candidate(
                    candidate_id=candidate.candidate_id,
                    scorecard=scorecard,
                    reason=primary_reason,
                )
                candidates_evaluated.append({
                    "candidate_id": candidate.candidate_id,
                    "status": "rejected",
                    "promoted": False,
                    "diff": candidate.diff.to_dict(),
                    "scorecard": scorecard.to_dict(),
                    "rejection_reason": primary_reason,
                })

        final_active_ver = self._registry.get_active_version(target_id)
        return {
            "target_id": target_id,
            "initial_version_id": base_version_id,
            "final_version_id": final_active_ver.version_id if final_active_ver else base_version_id,
            "candidates_total": len(findings),
            "candidates_accepted": accepted_count,
            "candidates_rejected": rejected_count,
            "candidates": candidates_evaluated,
            "history": [v.to_dict() for v in self._registry.get_history(target_id)],
        }

    def run_adaptive_red_team_loop(
        self,
        target_config: Dict[str, Any],
        initial_attack: Optional[Dict[str, Any]] = None,
        max_rounds: int = 5,
        target_execution_mode: str = "deterministic_offline",
        target_model_client: Optional[Callable] = None,
        attacker_use_model: bool = False,
        attacker_model_client: Optional[Callable] = None,
        seed: int = 42,
        defense_config: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """Execute a genuine multi-round adaptive red-team and defense learning loop.

        Cycles through:
        1. Attack generation / pivot based on feedback and attempted strategies.
        2. Execution against sandbox target agent.
        3. Real trace analysis via analyzer.core.analyze().
        4. If exploit confirmed: candidate proposal, isolated evaluation, and promotion.
        5. Retest against newly promoted defense.
        6. Stops when attack mitigated, max rounds reached, or no viable attack remains.
        """
        target_id = target_config.get("id", "demo-company-assistant")
        self._registry.init_target(target_config)
        def_cfg = dict(defense_config or {"D1": True, "D2": True, "D3": True})

        engine = get_dynamic_engine(seed=seed)
        rounds_executed: List[Dict[str, Any]] = []
        attempted_strategies: List[str] = []
        promoted_versions: List[str] = []
        current_parent_run_id: Optional[str] = None
        current_feedback: Optional[Dict[str, Any]] = None
        termination_reason = "max_rounds_reached"

        for round_num in range(1, max_rounds + 1):
            # 1. Attacker generates scenario
            if round_num == 1 and initial_attack:
                scenario = copy.deepcopy(initial_attack)
                scenario["round"] = 1
            else:
                scenario = engine.generate_scenario(
                    target_config=target_config,
                    parent_run_id=current_parent_run_id,
                    round_num=round_num,
                    feedback=current_feedback,
                    seed=seed + round_num,
                    use_model=attacker_use_model,
                    model_client=attacker_model_client,
                    attempted_strategies=attempted_strategies,
                    max_rounds=max_rounds,
                )

            # Check if attack engine has exhausted all viable strategies
            if scenario.get("no_viable_attack_remaining") and round_num > 1:
                termination_reason = "no_viable_attack_remaining"
                break

            strat = scenario.get("strategy") or scenario.get("surface") or "unknown"
            if strat not in attempted_strategies:
                attempted_strategies.append(strat)

            # 2. Configure target agent with currently active policy
            active_policy = self._registry.get_active_policy(target_id)
            run_target_config = copy.deepcopy(target_config)
            if active_policy:
                run_target_config["policy"] = copy.deepcopy(active_policy)

            scenario["target_execution_mode"] = target_execution_mode
            if target_model_client:
                scenario["target_model_client"] = target_model_client

            # 3. Target executes request in sandbox
            trace = run_agent(scenario, defense_config=def_cfg, target_config=run_target_config)
            run_id = trace.get("run_id")
            current_parent_run_id = run_id

            # 4. Analyzer evaluates trace
            verdict = analyze(trace, target_config=run_target_config, persist=False)
            verdict_label = verdict.get("label", "no_violation")

            # 5. Extract feedback from trace for next round
            extracted_feedback: Optional[Dict[str, Any]] = None
            for step in trace.get("steps", []):
                if step.get("step_type") == "guard_decision" and step.get("verdict") == "deny":
                    extracted_feedback = {
                        "type": "deny_reason",
                        "rule": step.get("rule", "policy_denial"),
                        "text": step.get("reason", "Action denied by security guard"),
                    }
                    break
                elif step.get("step_type") == "final_reply" and not extracted_feedback:
                    extracted_feedback = {"type": "bot_reply", "text": step.get("content", "")}

            current_feedback = extracted_feedback

            # 6. Defense evolution reaction if exploit confirmed
            candidate_info: Optional[Dict[str, Any]] = None
            promoted_version_id: Optional[str] = None

            if verdict_label == "confirmed_exploit":
                finding = verdict.get("finding") or {
                    "finding_id": f"find-{run_id}",
                    "target_id": target_id,
                    "rule_fired": verdict.get("rule", "executed_outside_policy"),
                    "source": "generated" if round_num > 1 else "seed",
                    "description": f"Exploit discovered in adaptive round {round_num}",
                    "details": {"round": round_num, "rule": verdict.get("rule")},
                }

                current_active_ver = self._registry.get_active_version(target_id)
                cand = generate_candidate_policy(
                    finding=finding,
                    current_policy=active_policy or target_config.get("policy", {}),
                    target_config=run_target_config,
                    base_version_id=current_active_ver.version_id if current_active_ver else "v1.0.0",
                )

                is_supported, unsupp_reason = validate_candidate_supported(cand)
                if not is_supported:
                    cand.status = "rejected"
                    cand.rejection_reason = unsupp_reason
                    self._registry.add_candidate(cand)
                    self._registry.reject_candidate(cand.candidate_id, None, reason=unsupp_reason)
                    candidate_info = {
                        "candidate_id": cand.candidate_id,
                        "status": "rejected",
                        "rejection_reason": unsupp_reason,
                    }
                else:
                    self._registry.add_candidate(cand)
                    scorecard = self._evaluator.evaluate_candidate(
                        candidate=cand,
                        target_config=run_target_config,
                        seed=seed + round_num * 10,
                    )
                    if scorecard.gatekeeper_verdict == "ACCEPTED":
                        new_ver = self._registry.promote_candidate(cand.candidate_id, scorecard)
                        promoted_version_id = new_ver.version_id
                        promoted_versions.append(promoted_version_id)
                        candidate_info = {
                            "candidate_id": cand.candidate_id,
                            "status": "accepted",
                            "promoted_version_id": promoted_version_id,
                            "scorecard": scorecard.to_dict(),
                        }
                    else:
                        prim_reason = scorecard.rejection_reasons[0] if scorecard.rejection_reasons else "Gatekeeper criteria failed"
                        self._registry.reject_candidate(cand.candidate_id, scorecard, reason=prim_reason)
                        candidate_info = {
                            "candidate_id": cand.candidate_id,
                            "status": "rejected",
                            "rejection_reason": prim_reason,
                            "scorecard": scorecard.to_dict(),
                        }

            # Record round metadata
            curr_active_ver = self._registry.get_active_version(target_id)
            round_record = {
                "round": round_num,
                "run_id": run_id,
                "parent_run_id": current_parent_run_id,
                "strategy": strat,
                "attacker_generation_mode": scenario.get("generation_mode", "offline_adaptive_template"),
                "is_attacker_model_generated": scenario.get("is_model_generated", False),
                "target_execution_mode": trace.get("target_execution_mode", "deterministic_offline"),
                "is_target_model_invoked": trace.get("is_target_model_invoked", False),
                "verdict": verdict_label,
                "rule": verdict.get("rule"),
                "feedback": extracted_feedback,
                "candidate": candidate_info,
                "active_policy_version": curr_active_ver.version_id if curr_active_ver else "v1.0.0",
                "trace": trace,
            }
            rounds_executed.append(round_record)

            # Check termination:
            # 1. If an evolved defense was promoted and current attack is mitigated
            if len(promoted_versions) > 0 and verdict_label in ("blocked_attempt", "no_violation"):
                termination_reason = "attack_mitigated_by_evolved_defense"
                break

            # 2. Check if all viable strategies have been exhausted
            available_tools = [t.get("name") for t in target_config.get("tools", []) if isinstance(t, dict)]
            all_viable_strats = {s.value for s in AttackStrategy if is_strategy_viable(s, available_tools)}
            unattempted_viable = all_viable_strats - set(attempted_strategies)

            if not unattempted_viable and verdict_label in ("blocked_attempt", "no_violation"):
                termination_reason = "attack_mitigated"
                break

        final_active_ver = self._registry.get_active_version(target_id)
        return {
            "target_id": target_id,
            "rounds_executed": rounds_executed,
            "total_rounds": len(rounds_executed),
            "termination_reason": termination_reason,
            "attempted_strategies": attempted_strategies,
            "promoted_versions": promoted_versions,
            "final_active_version_id": final_active_ver.version_id if final_active_ver else "v1.0.0",
            "is_mitigated": termination_reason in ("attack_mitigated_by_evolved_defense", "attack_mitigated"),
        }


def get_evolution_orchestrator() -> DefenseEvolutionOrchestrator:
    """Factory creating defense evolution orchestrator."""
    return DefenseEvolutionOrchestrator()
