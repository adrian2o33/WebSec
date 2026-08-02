import logging
from typing import List
from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult

logger = logging.getLogger(__name__)

class DirectoryListingDetector:
    """Detects Directory Listing vulnerabilities from crawled pages."""

    def analyse(self, crawl_results: List[CrawlResult]) -> List[Finding]:
        findings = []
        for result in crawl_results:
            if result.status_code == 200 and result.response_body:
                body = result.response_body
                if "Index of /" in body or "<title>Index of" in body or ">Parent Directory<" in body:
                    findings.append(Finding(
                        url=result.url,
                        parameter="",
                        payload="",
                        vuln_type=VulnerabilityType.DIRECTORY_LISTING,
                        severity=SeverityLevel.MEDIUM,
                        evidence=body[:200],
                        confidence=0.95,
                        description="Directory Listing is enabled on this endpoint. Attackers can view and download the contents of the directory, potentially exposing sensitive files or source code.",
                        recommendation="Disable directory listing (autoindex) in your web server configuration (e.g., 'Options -Indexes' in Apache, or 'autoindex off' in Nginx)."
                    ))
        return findings
