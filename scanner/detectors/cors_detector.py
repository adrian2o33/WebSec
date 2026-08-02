"""
CORS Misconfiguration Detector
Analyzes endpoints for overly permissive Cross-Origin Resource Sharing configurations.
"""
import logging
from typing import List
from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult

logger = logging.getLogger(__name__)

class CORSDetector:
    """Detects CORS misconfigurations allowing arbitrary origins."""

    def analyse(self, crawl_results: List[CrawlResult]) -> List[Finding]:
        """Analyse response headers from crawled pages for CORS vulnerabilities."""
        findings = []
        
        # In a real scanner we would send a specific 'Origin: https://evil.com' request during crawling.
        # Assuming the crawler has been modified to send this, we analyze the response headers.
        
        checked = set()
        for result in crawl_results:
            # Prevent duplicating findings for the same endpoint pattern
            if result.url in checked:
                continue
            checked.add(result.url)
            
            headers = {k.lower(): v for k, v in result.response_headers.items()}
            
            allow_origin = headers.get("access-control-allow-origin")
            allow_credentials = headers.get("access-control-allow-credentials", "false").lower() == "true"
            
            if allow_origin:
                # Critical CORS: Allow Origin * with Credentials (technically blocked by modern browsers, but some old apps force it)
                # Or reflecting the evil origin (which we assume the crawler sends)
                if (allow_origin == "*" and allow_credentials) or "evil" in allow_origin.lower():
                    findings.append(Finding(
                        url=result.url,
                        parameter="Header: Origin",
                        payload="Origin: https://evil.com",
                        vuln_type=VulnerabilityType.CORS_MISCONFIGURATION,
                        severity=SeverityLevel.HIGH if allow_credentials else SeverityLevel.MEDIUM,
                        evidence=f"Server returned Access-Control-Allow-Origin: {allow_origin} with Access-Control-Allow-Credentials: {allow_credentials}.",
                        confidence=0.95,
                        description="CORS Misconfiguration detected. The server trusts arbitrary origins. If credentials are allowed, an attacker can read sensitive user data via malicious JavaScript hosted on another site.",
                        recommendation="Configure Access-Control-Allow-Origin to strictly whitelist trusted domains. Never reflect the incoming Origin header blindly, and avoid using the wildcard '*' if authentication is required."
                    ))

        return findings
