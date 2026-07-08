"""
Unit tests for phishing_detector.py
Author: Munifa Abbas
"""

import unittest
from phishing_detector import (
    check_urgency_language,
    check_links,
    extract_links,
    get_verdict,
)


class TestPhishingDetector(unittest.TestCase):

    def test_urgency_language_detected(self):
        body = "This is urgent, please act now and verify your account immediately."
        reasons = []
        score = check_urgency_language(body, 0, reasons)
        self.assertGreater(score, 0)
        self.assertTrue(len(reasons) > 0)

    def test_no_urgency_language(self):
        body = "Hi, here is the schedule for next week's class."
        reasons = []
        score = check_urgency_language(body, 0, reasons)
        self.assertEqual(score, 0)
        self.assertEqual(len(reasons), 0)

    def test_extract_links(self):
        body = "Click here http://example.com/login and also https://test.tk/x"
        links = extract_links(body)
        self.assertEqual(len(links), 2)

    def test_link_domain_mismatch_flagged(self):
        body = "Verify here: http://fake-domain.tk/verify"
        reasons = []
        score = check_links(body, "paypal.com", 0, reasons)
        self.assertGreater(score, 0)

    def test_link_domain_match_not_flagged_for_mismatch(self):
        body = "Read more at https://phytrainings.com/portal"
        reasons = []
        score = check_links(body, "phytrainings.com", 0, reasons)
        mismatch_reasons = [r for r in reasons if "does not match" in r]
        self.assertEqual(len(mismatch_reasons), 0)

    def test_verdict_thresholds(self):
        self.assertEqual(get_verdict(0), "LOW RISK")
        self.assertEqual(get_verdict(25), "MEDIUM RISK")
        self.assertEqual(get_verdict(60), "HIGH RISK")


if __name__ == "__main__":
    unittest.main()
