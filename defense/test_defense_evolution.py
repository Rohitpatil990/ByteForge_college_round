"""Unit test suite for AgentBreak Defense Evolution Engine.

Tests:
1. Defense D3 output filter canary redaction and trace step mutation.
2. Dynamic candidate policy generation from analyzer findings.
3. Isolated in-memory evaluation and 100% legitimate task preservation gatekeeper.
4. Policy versioning (v1.0.0 -> v1.1.0), history tracking, and rollback.
5. End-to-end evolution orchestrator loop.
"""

import copy
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense.engine import filter_final_reply
from defense.evolution import get_evolution_orchestrator
from defense.generator import compute_policy_diff, generate_candidate_policy
from defense.models import DefenseCandidate, PolicyDiff
from defense.registry import PolicyRegistry, get_policy_registry
from eval.defense_evaluator import DefenseEvaluator
from target.agent import AgentExecutionResult
from target.config import load_target


class TestDefenseEvolutionEngine(unittest.TestCase):
    """Test suite for defense engine, candidate generation, evaluation, and registry."""

    def setUp(self):
        self.target_config = load_target("demo-company-assistant")
        self.registry = get_policy_registry()
        self.registry.reset("demo-company-assistant")
        self.registry.init_target(self.target_config)

    def test_d3_output_filter_redacts_canary(self):
        """D3 output filter must redact canary tokens from agent final replies."""
        canary = self.target_config.get("synthetic_canary") or "CANARY_TOKEN_DEMO_SECRET_48291"

        exec_res = AgentExecutionResult()
        exec_res.final_reply = f"Here is the secret key: {canary} and done."
        exec_res.steps = [
            {
                "idx": 0,
                "step_type": "final_reply",
                "content": f"Here is the secret key: {canary} and done.",
                "text": f"Here is the secret key: {canary} and done.",
            }
        ]

        def_cfg = {"D3": True}
        redacted = filter_final_reply(exec_res, def_cfg, self.target_config)

        self.assertTrue(redacted)
        self.assertNotIn(canary, exec_res.final_reply)
        self.assertIn("[REDACTED_SECRET]", exec_res.final_reply)
        self.assertEqual(exec_res.verdict_label, "blocked_attempt")
        self.assertEqual(exec_res.verdict_rule, "D3.reply_canary_filter")

        # Verify guard_decision step inserted
        guard_steps = [s for s in exec_res.steps if s.get("step_type") == "guard_decision"]
        self.assertEqual(len(guard_steps), 1)
        self.assertEqual(guard_steps[0]["verdict"], "deny")
        self.assertEqual(guard_steps[0]["rule"], "D3.reply_canary_filter")

    def test_candidate_generation_from_findings(self):
        """Candidate generator must produce targeted policy diffs for different findings."""
        base_policy = self.registry.get_active_policy("demo-company-assistant")

        # 1. Test canary leak finding
        find_leak = {
            "rule_fired": "canary_in_final_reply",
            "details": {"reason": "Canary token echoed in final reply"},
        }
        cand_leak = generate_candidate_policy(find_leak, base_policy, self.target_config)
        self.assertTrue(cand_leak.proposed_policy.get("guard", {}).get("output_filter"))
        self.assertIn("guard.output_filter", cand_leak.diff.added)

        # 2. Test memory tampering finding
        find_mem = {
            "rule_fired": "memory_write_untrusted",
            "details": {"reason": "Untrusted source memory write"},
        }
        cand_mem = generate_candidate_policy(find_mem, base_policy, self.target_config)
        self.assertFalse(cand_mem.proposed_policy.get("write_memory", {}).get("allow_untrusted_source"))
        self.assertTrue(len(cand_mem.proposed_policy.get("write_memory", {}).get("forbidden_keys", [])) > 0)

        # 3. Test external email finding
        find_email = {
            "rule_fired": "executed_outside_policy",
            "details": {"reason": "send_email to external unapproved domain"},
        }
        cand_email = generate_candidate_policy(find_email, base_policy, self.target_config)
        self.assertIn("company.com", cand_email.proposed_policy.get("send_email", {}).get("allowed_domains", []))

    def test_isolated_evaluation_gatekeeper(self):
        """Candidate evaluator must accept valid defenses and preserve 100% legitimate tasks."""
        evaluator = DefenseEvaluator(self.registry)
        base_policy = self.registry.get_active_policy("demo-company-assistant")

        # Generate a candidate that enables D3 output filter
        find_leak = {"rule_fired": "canary_in_final_reply", "details": {}}
        cand = generate_candidate_policy(find_leak, base_policy, self.target_config)

        scorecard = evaluator.evaluate_candidate(cand, self.target_config, seed=123)

        self.assertEqual(scorecard.gatekeeper_verdict, "ACCEPTED")
        self.assertTrue(scorecard.exploit_mitigated)
        self.assertEqual(scorecard.legit_task_pass_rate, 1.0)
        self.assertEqual(scorecard.legit_tasks_passed, scorecard.legit_tasks_total)

    def test_gatekeeper_rejects_overblocking_candidate(self):
        """Gatekeeper must REJECT any candidate that breaks legitimate benign tasks."""
        evaluator = DefenseEvaluator(self.registry)
        base_policy = self.registry.get_active_policy("demo-company-assistant")

        # Create an over-blocking candidate policy that forbids all emails including internal helpdesk
        broken_policy = copy.deepcopy(base_policy)
        broken_policy["send_email"] = {"allowed_domains": []}

        diff = compute_policy_diff(base_policy, broken_policy)
        bad_cand = DefenseCandidate(
            candidate_id="cand-bad-001",
            target_id="demo-company-assistant",
            base_version_id="v1.0.0",
            proposed_policy=broken_policy,
            diff=diff,
            trigger_finding={"rule_fired": "executed_outside_policy"},
        )

        scorecard = evaluator.evaluate_candidate(bad_cand, self.target_config, seed=456)

        self.assertEqual(scorecard.gatekeeper_verdict, "REJECTED")
        self.assertLess(scorecard.legit_task_pass_rate, 1.0)
        self.assertTrue(len(scorecard.rejection_reasons) > 0)

    def test_policy_promotion_and_rollback(self):
        """Registry must support promotion from v1.0.0 to v1.1.0 and safe rollback."""
        base_policy = self.registry.get_active_policy("demo-company-assistant")
        init_ver = self.registry.get_active_version("demo-company-assistant")
        self.assertEqual(init_ver.version_id, "v1.0.0")

        # Propose and evaluate candidate
        evaluator = DefenseEvaluator(self.registry)
        cand = generate_candidate_policy({"rule_fired": "canary_in_final_reply"}, base_policy, self.target_config)
        scorecard = evaluator.evaluate_candidate(cand, self.target_config, seed=789)
        self.assertEqual(scorecard.gatekeeper_verdict, "ACCEPTED")

        self.registry.add_candidate(cand)
        promoted = self.registry.promote_candidate(cand.candidate_id, scorecard)

        self.assertEqual(promoted.version_id, "v1.1.0")
        self.assertEqual(promoted.parent_version_id, "v1.0.0")
        self.assertEqual(self.registry.get_active_version("demo-company-assistant").version_id, "v1.1.0")

        # Rollback back to v1.0.0
        rolled_back = self.registry.rollback("demo-company-assistant")
        self.assertEqual(rolled_back.version_id, "v1.0.0")
        self.assertEqual(self.registry.get_active_version("demo-company-assistant").version_id, "v1.0.0")

    def test_full_evolution_orchestrator(self):
        """Orchestrator must execute the end-to-end evolution loop on confirmed findings."""
        orchestrator = get_evolution_orchestrator()
        findings = [
            {
                "finding_id": "find-demo-01",
                "target_id": "demo-company-assistant",
                "rule_fired": "canary_in_final_reply",
                "details": {"reason": "Canary token leaked in final reply"},
            }
        ]

        result = orchestrator.evolve(self.target_config, findings, auto_promote=True, seed=321)

        self.assertEqual(result["candidates_total"], 1)
        self.assertEqual(result["candidates_accepted"], 1)
        self.assertEqual(result["final_version_id"], "v1.1.0")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
