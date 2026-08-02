import logging
from typing import List
from scanner.fuzzer import FuzzResult
from scanner.models import Finding, VulnerabilityType, SeverityLevel
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class OpenRedirectDetector:
    """Detects Open Redirect vulnerabilities from fuzz results."""

    def analyse(self, fuzz_results: List[FuzzResult]) -> List[Finding]:
        findings = []
        for result in fuzz_results:
            if result.response_status in [301, 302, 303, 307, 308]:
                location = result.response_headers.get('Location', '')
                if not location or not result.payload:
                    continue
                    
                # If the payload was an absolute URL like http://evil.com
                # and the Location header points to it, it's an open redirect
                if location.startswith(result.payload) or location == result.payload:
                    parsed_loc = urlparse(location)
                    if parsed_loc.netloc and parsed_loc.scheme:
                        findings.append(Finding(
                            url=result.url,
                            parameter=result.parameter,
                            payload=result.payload,
                            vuln_type=VulnerabilityType.OPEN_REDIRECT,
                            severity=SeverityLevel.MEDIUM,
                            evidence=f"Status: {result.response_status}\nLocation: {location}",
                            confidence=0.95,
                            description=f"Open Redirect detected in parameter '{result.parameter}'. The application blindly redirects users to an arbitrary external domain.",
                            recommendation="Validate redirect URLs against a strict allowlist of allowed domains, or use relative paths. Never blindly redirect based on user input."
                        ))
        return findings
