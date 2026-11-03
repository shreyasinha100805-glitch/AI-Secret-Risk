
"""Unit tests for the risk scoring module."""

import unittest

from risk.risk_model import calculate_risk_score
from risk.severity import get_severity


class RiskModelTests(unittest.TestCase):

    def test_confirmed_api_key_gets_risk_assessment(self):

        candidate = {
            "value": "SyntheticApiKey-A8fK92LmX71",
            "type": "api_key",
            "method": "regex",
        }

        result = {
            "classification": "REAL_SECRET",
            "type": "api_key",
            "confidence": 0.90,
        }

        scored = calculate_risk_score(
            candidate,
            result,
            'api_key = "SyntheticApiKey-A8fK92LmX71"'
        )

        self.assertGreater(
            scored["risk_score"],
            0
        )

        self.assertEqual(
            scored["secret_type"],
            "API_KEY"
        )

        self.assertEqual(
            scored["status"],
            "ASSESSED"
        )

        self.assertIn(
            scored["severity"],
            {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        )

    def test_placeholder_is_not_scored_as_confirmed_secret(self):

        candidate = {
            "value": "Z8pL21QwR73xT91K",
            "type": "unknown",
            "entropy": 3.88,
        }

        result = {
            "classification": "PLACEHOLDER",
            "type": "unknown",
            "confidence": 0.98,
        }

        scored = calculate_risk_score(
            candidate,
            result,
            'sample_secret = "Z8pL21QwR73xT91K"'
        )

        self.assertEqual(
            scored["risk_score"],
            0.0
        )

        self.assertEqual(
            scored["severity"],
            "NOT_APPLICABLE"
        )

        self.assertEqual(
            scored["status"],
            "EXCLUDED"
        )

    def test_unknown_requires_manual_review(self):

        candidate = {
            "value": "A8fK92LmX71QpR5Z",
            "type": "unknown",
            "entropy": 4.0,
        }

        result = {
            "classification": "UNKNOWN",
            "type": "unknown",
            "confidence": 0.50,
        }

        scored = calculate_risk_score(
            candidate,
            result,
            'unclassified_value = "A8fK92LmX71QpR5Z"'
        )

        self.assertEqual(
            scored["status"],
            "REVIEW_REQUIRED"
        )

        self.assertGreater(
            scored["risk_score"],
            0
        )

    def test_non_secret_is_excluded(self):

        candidate = {
            "value": "A8fK92LmX71QpR5Z",
            "type": "unknown",
            "entropy": 4.0,
        }

        result = {
            "classification": "NOT_SECRET",
            "type": "unknown",
            "confidence": 0.95,
        }

        scored = calculate_risk_score(
            candidate,
            result,
            'user_id = "A8fK92LmX71QpR5Z"'
        )

        self.assertEqual(
            scored["risk_score"],
            0.0
        )

        self.assertEqual(
            scored["secret_type"],
            "OTHER"
        )

    def test_severity_boundaries(self):

        self.assertEqual(
            get_severity(0),
            "LOW"
        )

        self.assertEqual(
            get_severity(29.99),
            "LOW"
        )

        self.assertEqual(
            get_severity(30),
            "MEDIUM"
        )

        self.assertEqual(
            get_severity(50),
            "HIGH"
        )

        self.assertEqual(
            get_severity(80),
            "CRITICAL"
        )

        self.assertEqual(
            get_severity(100),
            "CRITICAL"
        )


if __name__ == "__main__":

    unittest.main(verbosity=2)
