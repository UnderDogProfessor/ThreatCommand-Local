import unittest

from app.main import static_detection_lint


class DetectionLintTests(unittest.TestCase):
    def test_sigma_advisory_reports_missing_required_sections_without_executing(self):
        outcome, evidence = static_detection_lint({"rule_format": "Sigma", "rule_content": "title: Example\ndetection:\n  selection: true"})

        self.assertEqual(outcome, "fail")
        self.assertIn("Missing Sigma 'logsource:' section.", evidence)
        self.assertIn("no query, rule, fixture, telemetry, or adversary behavior was executed", evidence)

    def test_kql_advisory_accepts_a_basic_query_but_remains_non_executing(self):
        outcome, evidence = static_detection_lint({"rule_format": "Microsoft Sentinel KQL", "rule_content": "SigninLogs | where ResultType != 0 | take 10"})

        self.assertEqual(outcome, "pass")
        self.assertIn("Static structural advisory only", evidence)

    def test_sigma_rule_is_parsed_by_the_local_sigma_library(self):
        content = """title: Process start example
id: 12345678-1234-1234-1234-123456789012
status: test
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
"""

        outcome, evidence = static_detection_lint({"rule_format": "Sigma", "rule_content": content})

        self.assertEqual(outcome, "pass")
        self.assertIn("Sigma parser accepted 1 rule document", evidence)
        self.assertIn("no query, rule, fixture, telemetry, or adversary behavior was executed", evidence)
