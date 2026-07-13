import unittest

from app.schemas import CopilotRequest


class CopilotSafetyTests(unittest.TestCase):
    def test_external_approval_is_opt_in(self):
        request = CopilotRequest(question="Summarize the local KEV records")

        self.assertFalse(request.approve_external)

    def test_external_approval_requires_a_true_boolean(self):
        request = CopilotRequest(question="Summarize the local KEV records", approve_external=True)

        self.assertTrue(request.approve_external)
