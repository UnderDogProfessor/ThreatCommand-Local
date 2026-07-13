import unittest

from app.main import access_token_valid, make_access_token, password_hash, password_matches


class LocalAccessTests(unittest.TestCase):
    def test_password_verifier_accepts_only_the_original_passphrase(self):
        stored = password_hash("correct local passphrase")
        self.assertTrue(password_matches("correct local passphrase", stored))
        self.assertFalse(password_matches("wrong local passphrase", stored))

    def test_session_token_is_bound_to_the_stored_verifier(self):
        stored = password_hash("correct local passphrase")
        token = make_access_token(stored)
        self.assertTrue(access_token_valid(token, stored))
        self.assertFalse(access_token_valid(token, password_hash("another passphrase")))
