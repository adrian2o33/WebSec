import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.models import CrawlResult, Finding, VulnerabilityType
from scanner.fuzzer import FuzzResult
from scanner.detectors.xss_detector import XSSDetector
from scanner.detectors.sqli_detector import SQLiDetector
from scanner.detectors.path_traversal_detector import PathTraversalDetector

class TestWebDetectors(unittest.TestCase):
    """
    Accuracy Tests for Web Vulnerability Detectors.
    Implements a Positive/Negative testing methodology.
    """

    def setUp(self):
        self.xss_detector = XSSDetector()
        self.sqli_detector = SQLiDetector()
        self.pt_detector = PathTraversalDetector()

    # --- XSS TESTS ---
    def test_xss_positive(self):
        """Positive Test: Malicious XSS payload should be flagged."""
        vuln_res = FuzzResult(
            url="http://test.com/search?q=<script>alert(1)</script>",
            parameter="q",
            payload="<script>alert(1)</script>",
            method="GET",
            response_status=200,
            response_body="<html>Results for: <script>alert(1)</script></html>",
            response_headers={"Content-Type": "text/html"},
            response_time=0.1
        )
        findings = self.xss_detector.analyse([vuln_res])
        self.assertGreater(len(findings), 0, "Failed to flag reflected XSS payload.")
        self.assertEqual(findings[0].vuln_type, VulnerabilityType.XSS_REFLECTED)

    def test_xss_negative(self):
        """Negative Test: Benign payload should NOT be flagged."""
        safe_res = FuzzResult(
            url="http://test.com/search?q=normal_search",
            parameter="q",
            payload="normal_search",
            method="GET",
            response_status=200,
            response_body="<html>Results for: normal_search</html>",
            response_headers={"Content-Type": "text/html"},
            response_time=0.1
        )
        findings = self.xss_detector.analyse([safe_res])
        self.assertEqual(len(findings), 0, "False positive detected in XSS scanner.")

    # --- SQLi TESTS ---
    def test_sqli_positive(self):
        """Positive Test: Database error message should be flagged as SQLi."""
        vuln_res = FuzzResult(
            url="http://test.com/product?id=1' OR 1=1--",
            parameter="id",
            payload="' OR 1=1--",
            method="GET",
            response_status=200,
            response_body="<html>Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given</html>",
            response_headers={"Content-Type": "text/html"},
            response_time=0.1
        )
        findings = self.sqli_detector.analyse([vuln_res])
        self.assertGreater(len(findings), 0, "Failed to flag SQL Injection error pattern.")
        self.assertEqual(findings[0].vuln_type, VulnerabilityType.SQL_INJECTION)

    def test_sqli_negative(self):
        """Negative Test: Normal response should NOT be flagged as SQLi."""
        safe_res = FuzzResult(
            url="http://test.com/product?id=1",
            parameter="id",
            payload="1",
            method="GET",
            response_status=200,
            response_body="<html>Product ID 1: A great product!</html>",
            response_headers={"Content-Type": "text/html"},
            response_time=0.1
        )
        findings = self.sqli_detector.analyse([safe_res])
        self.assertEqual(len(findings), 0, "False positive detected in SQLi scanner.")

    # --- Path Traversal TESTS ---
    def test_path_traversal_positive(self):
        """Positive Test: System file leak should be flagged."""
        vuln_res = FuzzResult(
            url="http://test.com/download?file=../../../../etc/passwd",
            parameter="file",
            payload="../../../../etc/passwd",
            method="GET",
            response_status=200,
            response_body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            response_headers={"Content-Type": "text/plain"},
            response_time=0.1
        )
        findings = self.pt_detector.analyse([vuln_res])
        self.assertGreater(len(findings), 0, "Failed to flag /etc/passwd path traversal leak.")
        self.assertEqual(findings[0].vuln_type, VulnerabilityType.PATH_TRAVERSAL)

    def test_path_traversal_negative(self):
        """Negative Test: Normal file download should NOT be flagged."""
        safe_res = FuzzResult(
            url="http://test.com/download?file=report.pdf",
            parameter="file",
            payload="report.pdf",
            method="GET",
            response_status=200,
            response_body="%PDF-1.4\n1 0 obj\n<<...",
            response_headers={"Content-Type": "application/pdf"},
            response_time=0.1
        )
        findings = self.pt_detector.analyse([safe_res])
        self.assertEqual(len(findings), 0, "False positive detected in Path Traversal scanner.")

if __name__ == '__main__':
    unittest.main()
