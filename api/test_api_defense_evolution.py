"""Integration test suite for defense evolution API endpoints.

Tests:
1. POST /assessments/{id}/defenses/evolve executes candidate generation, isolated eval, and promotion.
2. GET /assessments/{id}/defenses/candidates retrieves candidates and scorecards.
3. GET /assessments/{id}/defenses/history retrieves version history.
4. POST /assessments/{id}/defenses/rollback safely rolls back policy.
5. POST /assessments/{id}/retest reflects 100% exploit mitigation after evolution.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from api.main import app
from api.store import STORE


class TestApiDefenseEvolution(unittest.TestCase):
    """Test suite for API routes relating to defense evolution."""

    def setUp(self):
        self.client = TestClient(app)
        from defense.registry import get_policy_registry
        get_policy_registry().reset("demo-company-assistant")
        # Create fresh assessment
        res = self.client.post("/assessments", json={"name": "Evolution Test Suite", "target_id": "demo-company-assistant"})
        self.assertEqual(res.status_code, 200)
        self.asmt_id = res.json()["id"]

    def test_defense_evolution_lifecycle(self):
        # 1. Start seed runs to establish baseline
        seed_res = self.client.post(f"/assessments/{self.asmt_id}/runs")
        self.assertEqual(seed_res.status_code, 200)

        # 2. Call evolve defenses endpoint
        evolve_res = self.client.post(f"/assessments/{self.asmt_id}/defenses/evolve")
        self.assertEqual(evolve_res.status_code, 200)
        data = evolve_res.json()

        self.assertEqual(data["target_id"], "demo-company-assistant")
        self.assertTrue(data["candidates_total"] >= 1)
        self.assertTrue(data["candidates_accepted"] >= 1)
        self.assertTrue(data["final_version_id"].startswith("v1."))
        self.assertNotEqual(data["final_version_id"], "v1.0.0")
        evolved_version = data["final_version_id"]

        # 3. Retrieve candidates
        cand_res = self.client.get(f"/assessments/{self.asmt_id}/defenses/candidates")
        self.assertEqual(cand_res.status_code, 200)
        candidates = cand_res.json()
        self.assertTrue(len(candidates) > 0)
        self.assertEqual(candidates[0]["status"], "accepted")
        self.assertEqual(candidates[0]["scorecard"]["gatekeeper_verdict"], "ACCEPTED")

        # 4. Check defense history
        hist_res = self.client.get(f"/assessments/{self.asmt_id}/defenses/history")
        self.assertEqual(hist_res.status_code, 200)
        hist = hist_res.json()
        self.assertEqual(hist["active_version"]["version_id"], evolved_version)
        self.assertTrue(len(hist["history"]) >= 2)

        # 5. Retest reflection
        retest_res = self.client.post(f"/assessments/{self.asmt_id}/retest")
        self.assertEqual(retest_res.status_code, 200)
        retest = retest_res.json()
        self.assertEqual(retest["after"]["confirmed_exploits"], 0)
        self.assertEqual(retest["after"]["exploit_rate"], 0.0)
        self.assertIn("Adaptive Defense Evolution", retest["defense_evaluation_note"])

        # 6. Test rollback endpoint
        rb_res = self.client.post(f"/assessments/{self.asmt_id}/defenses/rollback")
        self.assertEqual(rb_res.status_code, 200)
        rb_data = rb_res.json()
        self.assertNotEqual(rb_data["version_id"], evolved_version)

        # Verify active version is rolled back
        hist_res2 = self.client.get(f"/assessments/{self.asmt_id}/defenses/history")
        self.assertEqual(hist_res2.json()["active_version"]["version_id"], rb_data["version_id"])


if __name__ == "__main__":
    unittest.main()
