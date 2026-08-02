import unittest
from unittest.mock import patch, MagicMock
import socket
import logging

# Set logging level to DEBUG to see why it fails
logging.getLogger("scanner.subdomain_enumerator").setLevel(logging.DEBUG)

from scanner.subdomain_enumerator import SubdomainEnumerator
from scanner.models import VulnerabilityType, SeverityLevel

class TestSubdomainEnum(unittest.TestCase):
    
    def setUp(self):
        self.enumerator = SubdomainEnumerator()

    @patch('scanner.subdomain_enumerator.requests.get')
    @patch('scanner.subdomain_enumerator.socket.gethostbyname')
    def test_subdomain_enum_positive(self, mock_gethostbyname, mock_requests_get):
        """Positive Test: Enumerator should return findings for live subdomains."""
        
        # Mock crt.sh API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "dev.example.com"},
            {"name_value": "staging.example.com\napi.example.com"}
        ]
        mock_requests_get.return_value = mock_response

        # Mock DNS resolution to succeed (simulating live domains)
        mock_gethostbyname.return_value = "192.168.1.100"

        findings = self.enumerator.enumerate("https://example.com")

        self.assertEqual(len(findings), 3, "Failed to find all mocked live subdomains.")
        
        found_urls = [f.url for f in findings]
        self.assertIn("https://dev.example.com", found_urls)
        self.assertIn("https://staging.example.com", found_urls)
        self.assertIn("https://api.example.com", found_urls)
        
        # Verify Finding properties
        self.assertEqual(findings[0].vuln_type, VulnerabilityType.EXPOSED_SUBDOMAIN)
        self.assertEqual(findings[0].severity, SeverityLevel.INFO)


    @patch('scanner.subdomain_enumerator.requests.get')
    @patch('scanner.subdomain_enumerator.socket.gethostbyname')
    def test_subdomain_enum_negative(self, mock_gethostbyname, mock_requests_get):
        """Negative Test: Enumerator MUST NOT return findings for dead subdomains."""
        
        # Mock crt.sh API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "old-admin.example.com"}
        ]
        mock_requests_get.return_value = mock_response

        # Mock DNS resolution to fail (simulating dead domains)
        def mock_dns_fail(domain):
            raise socket.gaierror("Name or service not known")
            
        mock_gethostbyname.side_effect = mock_dns_fail

        findings = self.enumerator.enumerate("https://example.com")

        self.assertEqual(len(findings), 0, "False positive! Dead domains should not be reported.")

if __name__ == '__main__':
    unittest.main()
