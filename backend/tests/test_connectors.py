import unittest

from app.connectors import _classify_feed_item, _rss_entries


class ConnectorParsingTests(unittest.TestCase):
    def test_rss_content_is_converted_to_plain_text(self):
        entries = _rss_entries("""<rss><channel><item><title>Example &amp; alert</title><link>https://example.test/item</link><description>&lt;b&gt;Important&lt;/b&gt; update</description></item></channel></rss>""")
        self.assertEqual(entries[0]["title"], "Example & alert")
        self.assertEqual(entries[0]["summary"], "Important update")

    def test_zero_day_requires_nearby_exploit_context(self):
        _, evidence_tags = _classify_feed_item("Zero-day flaw exploited", "Vendor advisory")
        _, mention_tags = _classify_feed_item("Zero-day history", "Background reading")
        self.assertIn("zero-day-evidence", evidence_tags)
        self.assertNotIn("zero-day-evidence", mention_tags)
        self.assertIn("zero-day-mentioned", mention_tags)
