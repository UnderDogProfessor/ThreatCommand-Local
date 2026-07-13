import unittest

from app.main import RATE_LIMIT_BUCKETS, rate_limit_allowed


class LocalRateLimitTests(unittest.TestCase):
    def setUp(self):
        RATE_LIMIT_BUCKETS.clear()

    def test_bucket_rejects_requests_after_its_limit(self):
        self.assertTrue(rate_limit_allowed("test", 2, 60, now=100.0))
        self.assertTrue(rate_limit_allowed("test", 2, 60, now=101.0))
        self.assertFalse(rate_limit_allowed("test", 2, 60, now=102.0))

    def test_bucket_expires_old_requests(self):
        self.assertTrue(rate_limit_allowed("test", 1, 60, now=100.0))
        self.assertTrue(rate_limit_allowed("test", 1, 60, now=160.0))
