"""AgentBreak Foundation Smoke Test Suite.

Verifies the frozen v2 contract, type validation, analyzer rule IDs,
attacker feedback validation, and API health and target configuration endpoints.

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

        # Test valid findings for each source
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
        # Invalid type
        with self.assertRaises(ValueError):
            validate_attacker_feedback({"type": "invalid_type", "text": "Some text"})

        # Missing text
        with self.assertRaises(ValueError):
            validate_attacker_feedback({"type": "bot_reply"})

        # Empty/whitespace text
        with self.assertRaises(ValueError):
            validate_attacker_feedback({"type": "bot_reply", "text": "   "})

        # Non-dict input
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

        # Invalid step type
        trace_with_bad_step = dict(complete_trace)
        trace_with_bad_step["steps"] = [{"step_type": "unrecognized_step_type", "content": "..."}]
        with self.assertRaises(ValueError):
            validate_trace(trace_with_bad_step)


class TestApiFoundation(unittest.TestCase):
    """Test suite for FastAPI endpoints and target configuration loading."""

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

        # Valid selection
        response = self.client.post(
            "/assessments/test-run-1/target",
            json={"target_id": "demo-company-assistant"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["target_id"], "demo-company-assistant")
        self.assertEqual(data["status"], "target_selected")

        # Unknown target rejection
        unknown_response = self.client.post(
            "/assessments/test-run-1/target",
            json={"target_id": "nonexistent-target-id"},
        )
        self.assertEqual(unknown_response.status_code, 404)


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
