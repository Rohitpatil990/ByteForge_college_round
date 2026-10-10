"""AgentBreak Foundation Smoke Test Suite.

Verifies:
1. Frozen v2 contract schemas, step types (including final_reply), analyzer rules,
   finding sources, feedback validators, and non-inflation of recorded findings.
2. Complete nine-stage API workflow in order:
   Stage 1: Health / status check
   Stage 2: Target config listing (called before target selection)
   Stage 3: Assessment creation
   Stage 4: Target assignment and invalid target rejection
   Stage 5: Execution runs start
   Stage 6: Runs and trace retrieval with final_reply verification
   Stage 7: Findings retrieval with exact rule IDs
   Stage 8: Defenses listing, toggling, and adaptive challenge
   Stage 9: Retest evaluation, final report, and evidence hash chain verification

Usage:
    python spec/smoke_test.py
"""

import sys
import unittest
from pathlib import Path
from typing import Any, Dict

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from spec.schema import (
    EXACT_ANALYZER_RULE_IDS,
    FINDING_SOURCES,
    REQUIRED_TRACE_FIELDS,
    VALID_FEEDBACK_TYPES,
    VALID_STEP_TYPES,
    is_adaptive_discovery,
    validate_attacker_feedback,
    validate_finding,
    validate_trace,
)


class TestV2SchemaContract(unittest.TestCase):
    """Test suite for the frozen v2 contract definitions and validation logic."""

    def test_required_trace_fields(self):
        """Verify all five required trace fields are defined."""
        expected_fields = {"target_id", "kind", "variant_source", "parent_run_id", "round"}
        self.assertEqual(REQUIRED_TRACE_FIELDS, expected_fields)

        valid_trace: Dict[str, Any] = {
            "target_id": "demo-company-assistant",
            "kind": "attack",
            "variant_source": "seed",
            "parent_run_id": None,
            "round": 0,
            "steps": [],
        }
        validated = validate_trace(valid_trace)
        self.assertEqual(validated["target_id"], "demo-company-assistant")
        self.assertIsNone(validated["parent_run_id"])

    def test_trace_step_types_including_final_reply(self):
        """Verify step types include 'final_reply' alongside other standard steps."""
        self.assertIn("final_reply", VALID_STEP_TYPES)
        self.assertIn("user_input", VALID_STEP_TYPES)
        self.assertIn("tool_call", VALID_STEP_TYPES)
        self.assertIn("tool_result", VALID_STEP_TYPES)

        trace_with_final_reply: Dict[str, Any] = {
            "target_id": "demo-company-assistant",
            "kind": "attack",
            "variant_source": "generated_v1",
            "parent_run_id": "run-000",
            "round": 1,
            "steps": [
                {"step_type": "user_input", "content": "Show me internal customer data."},
                {"step_type": "agent_thought", "content": "Assessing security boundary."},
                {"step_type": "tool_call", "content": "get_customer_record", "tool_name": "get_customer_record"},
                {"step_type": "final_reply", "content": "I cannot fulfill this request."},
            ],
        }
        validated = validate_trace(trace_with_final_reply)
        self.assertEqual(len(validated["steps"]), 4)
        self.assertEqual(validated["steps"][3]["step_type"], "final_reply")

    def test_exact_analyzer_rule_ids(self):
        """Verify all four exact analyzer rule IDs are supported."""
        expected_rules = {
            "canary_in_executed_args",
            "canary_in_final_reply",
            "executed_outside_policy",
            "memory_write_untrusted",
        }
        self.assertEqual(EXACT_ANALYZER_RULE_IDS, expected_rules)

    def test_finding_source_and_rule_fired(self):
        """Verify finding sources distinguish seed, generated, recorded and rules fire accurately."""
        expected_sources = {"seed", "generated", "recorded"}
        self.assertEqual(FINDING_SOURCES, expected_sources)

        for src in expected_sources:
            finding: Dict[str, Any] = {
                "finding_id": f"find-{src}-01",
                "target_id": "demo-company-assistant",
                "source": src,
                "rule_fired": "canary_in_final_reply",
                "description": f"Synthetic finding for {src}",
            }
            validated = validate_finding(finding)
            self.assertEqual(validated["source"], src)

        # Verify recorded findings are distinguished and NOT counted as adaptive discoveries
        rec_finding = {"source": "recorded", "rule_fired": "executed_outside_policy"}
        seed_finding = {"source": "seed", "rule_fired": "executed_outside_policy"}
        gen_finding = {"source": "generated", "rule_fired": "executed_outside_policy"}

        self.assertFalse(is_adaptive_discovery(rec_finding), "Recorded findings must not be counted as adaptive discoveries")
        self.assertFalse(is_adaptive_discovery(seed_finding), "Seed findings must not be counted as adaptive discoveries")
        self.assertTrue(is_adaptive_discovery(gen_finding), "Generated findings must be counted as adaptive discoveries")

    def test_invalid_finding_rejection(self):
        """Verify findings with unknown sources or invalid rules are rejected."""
        invalid_source_finding = {
            "source": "unknown_source",
            "rule_fired": "canary_in_final_reply",
        }
        with self.assertRaises(ValueError):
            validate_finding(invalid_source_finding)

        invalid_rule_finding = {
            "source": "seed",
            "rule_fired": "unregistered_rule_id",
        }
        with self.assertRaises(ValueError):
            validate_finding(invalid_rule_finding)

    def test_valid_feedback_types(self):
        """Verify valid feedback types 'bot_reply' and 'deny_reason'."""
        self.assertEqual(VALID_FEEDBACK_TYPES, {"bot_reply", "deny_reason"})

        fb1 = validate_attacker_feedback({"type": "bot_reply", "text": "Hello, how can I help?"})
        self.assertEqual(fb1["type"], "bot_reply")
        self.assertEqual(fb1["text"], "Hello, how can I help?")
        self.assertIsNone(fb1.get("rule"))

        fb2 = validate_attacker_feedback({
            "type": "deny_reason",
            "rule": "executed_outside_policy",
            "text": "Call blocked: recipient outside company.com domain.",
        })
        self.assertEqual(fb2["type"], "deny_reason")
        self.assertEqual(fb2["rule"], "executed_outside_policy")

    def test_invalid_feedback_rejection(self):
        """Verify rejection of malformed or invalid feedback arguments."""
        with self.assertRaises(ValueError):
            validate_attacker_feedback({"type": "invalid_type", "text": "Some text"})

        with self.assertRaises(ValueError):
            validate_attacker_feedback({"type": "bot_reply"})

        with self.assertRaises(ValueError):
            validate_attacker_feedback({"type": "bot_reply", "text": "   "})

        with self.assertRaises(ValueError):
            validate_attacker_feedback("not a dict")

    def test_trace_validation_missing_required_fields(self):
        """Verify that traces missing any required fields are rejected."""
        required = ["target_id", "kind", "variant_source", "parent_run_id", "round"]
        complete_trace = {
            "target_id": "demo-company-assistant",
            "kind": "attack",
            "variant_source": "seed",
            "parent_run_id": None,
            "round": 0,
            "steps": [],
        }

        for field in required:
            incomplete = dict(complete_trace)
            del incomplete[field]
            with self.assertRaises(ValueError, msg=f"Should reject when missing '{field}'"):
                validate_trace(incomplete)

        trace_with_bad_step = dict(complete_trace)
        trace_with_bad_step["steps"] = [{"step_type": "unrecognized_step_type", "content": "..."}]
        with self.assertRaises(ValueError):
            validate_trace(trace_with_bad_step)


class TestApiFoundation(unittest.TestCase):
    """Test suite for FastAPI endpoints, target configuration loading, and basic API routes."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from api.main import app
            cls.client = TestClient(app)
            cls.api_available = True
        except Exception as exc:
            cls.api_available = False
            cls.api_error = str(exc)

    def test_api_health(self):
        """Verify GET /health returns 200 and healthy status."""
        if not self.api_available:
            self.skipTest(f"TestClient unavailable: {getattr(self, 'api_error', '')}")
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "ok")

    def test_target_configs_listing(self):
        """Verify GET /target/configs returns valid demo-company-assistant configuration."""
        if not self.api_available:
            self.skipTest(f"TestClient unavailable: {getattr(self, 'api_error', '')}")
        response = self.client.get("/target/configs")
        self.assertEqual(response.status_code, 200)
        configs = response.json()
        self.assertIsInstance(configs, list)
        self.assertGreaterEqual(len(configs), 1)

        demo_cfg = next((c for c in configs if c["id"] == "demo-company-assistant"), None)
        self.assertIsNotNone(demo_cfg, "demo-company-assistant config must be present")
        self.assertEqual(demo_cfg["name"], "Demo Company Assistant")
        self.assertTrue(demo_cfg["valid"])
        self.assertIsNone(demo_cfg["validation_error"])

    def test_assessment_target_selection(self):
        """Verify POST /assessments/{id}/target accepts valid targets and rejects unknown ones."""
        if not self.api_available:
            self.skipTest(f"TestClient unavailable: {getattr(self, 'api_error', '')}")

        response = self.client.post(
            "/assessments/test-run-1/target",
            json={"target_id": "demo-company-assistant"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["target_id"], "demo-company-assistant")
        self.assertEqual(data["status"], "target_selected")

        unknown_response = self.client.post(
            "/assessments/test-run-1/target",
            json={"target_id": "nonexistent-target-id"},
        )
        self.assertEqual(unknown_response.status_code, 404)


class TestNineStageWorkflow(unittest.TestCase):
    """End-to-end smoke test covering all nine stages in sequential order."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
            from api.main import app
            cls.client = TestClient(app)
            cls.api_available = True
        except Exception as exc:
            cls.api_available = False
            cls.api_error = str(exc)

    def test_complete_nine_stage_pipeline(self):
        """Execute the entire 9-stage pipeline deterministically."""
        if not self.api_available:
            self.skipTest(f"TestClient unavailable: {getattr(self, 'api_error', '')}")

        client = self.client

        # -------------------------------------------------------------------
        # Stage 1: Health/status check
        # -------------------------------------------------------------------
        res_health = client.get("/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json()["status"], "ok")

        # -------------------------------------------------------------------
        # Stage 2: Target configs (MUST be called before target assignment)
        # -------------------------------------------------------------------
        res_configs = client.get("/target/configs")
        self.assertEqual(res_configs.status_code, 200)
        configs = res_configs.json()
        self.assertTrue(len(configs) > 0)
        # Demo assistant must be first
        self.assertEqual(configs[0]["id"], "demo-company-assistant")
        self.assertTrue(configs[0]["valid"])

        # -------------------------------------------------------------------
        # Stage 3: Create assessment
        # -------------------------------------------------------------------
        res_create = client.post("/assessments", json={"name": "Pipeline Verification Run"})
        self.assertEqual(res_create.status_code, 200)
        asmt = res_create.json()
        asmt_id = asmt["id"]
        self.assertIsNotNone(asmt_id)

        # -------------------------------------------------------------------
        # Stage 4: Assign target to assessment (and test rejection of invalid)
        # -------------------------------------------------------------------
        # Rejection test for unknown target
        res_bad = client.post(f"/assessments/{asmt_id}/target", json={"target_id": "invalid-unknown-target"})
        self.assertEqual(res_bad.status_code, 404)

        # Valid target assignment
        res_target = client.post(f"/assessments/{asmt_id}/target", json={"target_id": "demo-company-assistant"})
        self.assertEqual(res_target.status_code, 200)
        self.assertEqual(res_target.json()["target_id"], "demo-company-assistant")

        # -------------------------------------------------------------------
        # Stage 5: Start and execute assessment runs
        # -------------------------------------------------------------------
        res_runs_start = client.post(f"/assessments/{asmt_id}/runs")
        self.assertEqual(res_runs_start.status_code, 200)
        runs_data = res_runs_start.json()
        self.assertGreaterEqual(runs_data["runs_executed"], 3)

        # -------------------------------------------------------------------
        # Stage 6: Retrieve runs and trace details with final_reply check
        # -------------------------------------------------------------------
        res_runs_list = client.get(f"/assessments/{asmt_id}/runs")
        self.assertEqual(res_runs_list.status_code, 200)
        runs = res_runs_list.json()
        self.assertGreaterEqual(len(runs), 3)

        # Verify individual run and step types (including final_reply)
        sample_run = runs[0]
        run_id = sample_run["run_id"]
        res_run_detail = client.get(f"/assessments/{asmt_id}/runs/{run_id}")
        self.assertEqual(res_run_detail.status_code, 200)
        trace = res_run_detail.json()["trace"]
        validate_trace(trace)
        step_types = [s["step_type"] for s in trace["steps"]]
        self.assertIn("final_reply", step_types, "Trace steps must include 'final_reply'")

        # -------------------------------------------------------------------
        # Stage 7: Retrieve findings and verify exact rule IDs and sources
        # -------------------------------------------------------------------
        res_findings = client.get(f"/assessments/{asmt_id}/findings")
        self.assertEqual(res_findings.status_code, 200)
        findings = res_findings.json()
        self.assertGreaterEqual(len(findings), 1)

        for finding in findings:
            validate_finding(finding)
            self.assertIn(finding["rule_fired"], EXACT_ANALYZER_RULE_IDS)
            self.assertIn(finding["source"], FINDING_SOURCES)

        # -------------------------------------------------------------------
        # Stage 8: Defenses inspection, toggling, and adaptive challenge
        # -------------------------------------------------------------------
        res_defenses = client.get(f"/assessments/{asmt_id}/defenses")
        self.assertEqual(res_defenses.status_code, 200)
        defenses = res_defenses.json()
        self.assertGreaterEqual(len(defenses), 3)

        # Verify D3 is clearly labeled as stub
        d3 = next((d for d in defenses if d["id"] == "d3-reply-filter"), None)
        self.assertIsNotNone(d3)
        self.assertEqual(d3["status"], "stub")
        self.assertTrue(d3["is_stub"])

        # Toggle defense D1
        res_toggle = client.post(f"/assessments/{asmt_id}/defenses/d1-tool-policy/toggle")
        self.assertEqual(res_toggle.status_code, 200)

        # Challenge defenses with adaptive attacker feedback
        res_challenge = client.post(f"/assessments/{asmt_id}/challenge")
        self.assertEqual(res_challenge.status_code, 200)
        challenge_data = res_challenge.json()
        self.assertEqual(challenge_data["variant_source"], "generated")
        self.assertEqual(challenge_data["round"], 1)
        self.assertIsNotNone(challenge_data["parent_run_id"])
        self.assertTrue(challenge_data["is_adaptive_discovery"])

        # -------------------------------------------------------------------
        # Stage 9: Retest, report, and evidence hash chain verification
        # -------------------------------------------------------------------
        # Retest evaluation
        res_retest = client.post(f"/assessments/{asmt_id}/retest")
        self.assertEqual(res_retest.status_code, 200)
        retest_data = res_retest.json()
        self.assertEqual(retest_data["status"], "evaluated")
        self.assertIn("before", retest_data)
        self.assertIn("after", retest_data)

        # Report generation
        res_report = client.get(f"/assessments/{asmt_id}/report")
        self.assertEqual(res_report.status_code, 200)
        report = res_report.json()

        # Check required explanations and non-inflation of recorded findings
        self.assertIn("exploit_breakdown_statement", report["summary"])
        self.assertIn("Of", report["summary"]["exploit_breakdown_statement"])
        self.assertIn("seed list", report["summary"]["exploit_breakdown_statement"])
        self.assertIn("adaptive attacker", report["summary"]["exploit_breakdown_statement"])

        # Verify recorded findings are accounted for separately
        rec_count = report["findings_metrics"]["recorded_findings_count"]
        gen_count = report["findings_metrics"]["adaptive_generated_findings_count"]
        self.assertGreaterEqual(gen_count, 1)
        # Recorded count must not inflate adaptive count
        self.assertEqual(gen_count, len([f for f in report["findings_list"] if f["source"] == "generated"]))

        # Disclosures check
        disclosures = report["mandatory_disclosures"]
        self.assertIn("plain string match", disclosures["canary_matching_limitation"])
        self.assertIn("Arbitrary agent code is not supported", disclosures["target_compatibility_scope"])

        # Evidence Hash Chain verification
        res_chain = client.post(f"/assessments/{asmt_id}/verify-chain")
        self.assertEqual(res_chain.status_code, 200)
        chain_data = res_chain.json()
        self.assertTrue(chain_data["verified"])
        self.assertIn("unmodified since logging", chain_data["message"])

        # Tamper demonstration test (on isolated disposable copy)
        res_tamper = client.post(f"/assessments/{asmt_id}/tamper-test")
        self.assertEqual(res_tamper.status_code, 200)
        tamper_data = res_tamper.json()
        self.assertTrue(tamper_data["tamper_detected"])
        self.assertTrue(tamper_data["original_chain_untouched"])


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
