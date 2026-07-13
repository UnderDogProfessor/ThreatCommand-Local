import unittest

from app.detection_lab import evaluate_fixture, fixture_catalog, lab_material, learning_level_for_rank


class DetectionLabTests(unittest.TestCase):
    def test_sigma_expected_fixture_matches_without_execution(self):
        item = {
            "title": "On-Prem - Encoded PowerShell (Detection Pattern)",
            "rule_format": "Sigma",
            "rule_content": "title: Lab\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: '<review for Encoded PowerShell>'\n  condition: selection",
            "attack_techniques": ["T1059.001"],
            "required_telemetry": ["Process creation"],
        }
        result = evaluate_fixture(item, fixture_catalog(item)[0])

        self.assertTrue(result["observed_match"])
        self.assertTrue(result["test_passed"])
        self.assertIn("No process, query, or external system was used", result["reasoning"])

    def test_kql_benign_fixture_teaches_that_broad_query_needs_tuning(self):
        item = {"title": "Cloud - Impossible-travel sign-in (Hunt & Tuning Pattern)", "rule_format": "Microsoft Sentinel KQL", "rule_content": "SigninLogs | where isnotempty(Account)", "required_telemetry": ["Identity sign-in logs"]}
        result = evaluate_fixture(item, fixture_catalog(item)[1])

        self.assertTrue(result["observed_match"])
        self.assertTrue(result["test_passed"])
        self.assertIn("did not interpret, run, or send KQL", result["reasoning"])

    def test_learning_material_has_configuration_tuning_and_interview_help(self):
        material = lab_material({"title": "Cloud - MFA fatigue pattern (Detection Pattern)", "rule_format": "Sigma", "attack_techniques": ["T1621"], "required_telemetry": ["Identity MFA logs"]})

        self.assertEqual(len(material["fixtures"]), 3)
        self.assertEqual(len(material["interview"]), 3)
        self.assertTrue(material["configuration"])
        self.assertTrue(material["improvements"])

    def test_learning_levels_create_a_progression(self):
        self.assertEqual(learning_level_for_rank(1), "beginner")
        self.assertEqual(learning_level_for_rank(12), "intermediate")
        self.assertEqual(learning_level_for_rank(24), "advanced")
