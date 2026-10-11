"""Regression tests for QuantumGuard's explainable multi-factor risk scoring."""
import unittest
from core.mosca_engine import MoscaEngine
from database.models import CryptoAsset


class MultiFactorRiskScoringTests(unittest.TestCase):
    def setUp(self):
        self.engine = MoscaEngine(crqc_year=2033, current_year=2026, default_migration_years=3)

    def score(self, **kwargs):
        defaults = dict(name="asset", location="/app", algorithm="RSA", key_size=2048,
                        purpose="application encryption", exposure_level="INTERNAL_NETWORK",
                        data_shelf_life_years=10)
        defaults.update(kwargs)
        vuln, explanation = self.engine.assess_asset(CryptoAsset(**defaults))
        return vuln, explanation

    def test_factor_weights_total_100_and_contributions_reconcile(self):
        vuln, _ = self.score(name="patient_records", purpose="medical patient records", exposure_level="PUBLIC_INTERNET", data_shelf_life_years=30)
        factors = vuln.risk_factors
        self.assertEqual(sum(f["weight_pct"] for f in factors.values()), 100)
        self.assertAlmostEqual(sum(f["weighted_points"] for f in factors.values()), vuln.q_score, places=1)
        self.assertTrue(0 <= vuln.q_score <= 100)

    def test_public_sensitive_long_lived_asset_ranks_above_local_demo(self):
        high, _ = self.score(name="patient_health_records", purpose="medical patient records", exposure_level="PUBLIC_INTERNET", data_shelf_life_years=30)
        low, _ = self.score(name="test_demo", purpose="temporary demo", exposure_level="LOCAL_DEV", data_shelf_life_years=1, algorithm="AES-256", key_size=256)
        self.assertGreater(high.q_score, low.q_score)
        self.assertEqual(high.severity, "CRITICAL")

    def test_pqc_primitive_has_zero_quantum_vulnerability_score(self):
        vuln, _ = self.score(algorithm="ML-KEM-768", key_size=None, exposure_level="PUBLIC_INTERNET", data_shelf_life_years=30)
        self.assertEqual(vuln.q_score, 0.0)
        self.assertEqual(vuln.severity, "QUANTUM_SAFE")

    def test_factor_sources_mark_sensitivity_as_assumption(self):
        vuln, explanation = self.score(name="unknown_service")
        self.assertIn("data_sensitivity", vuln.risk_factors)
        self.assertIn("assumption", vuln.risk_factors["data_sensitivity"]["observed_or_assumed"])
        self.assertIn("not a breach probability", explanation)


if __name__ == "__main__":
    unittest.main()
