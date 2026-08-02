"""
Security Headers Checker
Analyses HTTP response headers for missing or misconfigured security headers.
"""
import logging
from typing import List, Dict

from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult

logger = logging.getLogger(__name__)

# Security headers and their expected configurations
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": SeverityLevel.LOW,
        "description": "HSTS (HTTP Strict Transport Security) forces browsers to use HTTPS.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "check_value": lambda v: "max-age" in v.lower() and int(
            v.lower().split("max-age=")[1].split(";")[0].strip()
        ) >= 10368000 if "max-age=" in v.lower() else False,
    },
    "Content-Security-Policy": {
        "severity": SeverityLevel.MEDIUM,
        "description": "CSP prevents XSS and data injection attacks by controlling resource loading.",
        "recommendation": "Implement a Content-Security-Policy header. Start with "
                          "'Content-Security-Policy: default-src \\'self\\'' and refine.",
        "check_value": lambda v: "default-src" in v.lower() or "script-src" in v.lower(),
    },
    "X-Content-Type-Options": {
        "severity": SeverityLevel.LOW,
        "description": "Prevents MIME-type sniffing, reducing drive-by download attacks.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
        "check_value": lambda v: v.lower().strip() == "nosniff",
    },
    "X-Frame-Options": {
        "severity": SeverityLevel.MEDIUM,
        "description": "Prevents clickjacking by controlling whether the page can be framed.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "check_value": lambda v: v.lower().strip() in ("deny", "sameorigin"),
    },
    "Permissions-Policy": {
        "severity": SeverityLevel.LOW,
        "description": "Controls which browser features (camera, mic, etc.) the page can use.",
        "recommendation": "Add a Permissions-Policy header restricting unnecessary browser features.",
        "check_value": lambda v: len(v) > 0,
    },
}

# Headers that should NOT be present (information disclosure)
INSECURE_HEADERS = {
    "Server": {
        "severity": SeverityLevel.INFO,
        "description": "Server header reveals web server software and version.",
        "recommendation": "Remove or genericize the Server header to prevent version disclosure.",
        "check_insecure": lambda v: any(ver in v.lower() for ver in
                                        ["apache/", "nginx/", "iis/", "tomcat/", "jetty/"]),
    },
    "X-Powered-By": {
        "severity": SeverityLevel.INFO,
        "description": "X-Powered-By reveals the server-side technology (e.g., PHP, ASP.NET).",
        "recommendation": "Remove the X-Powered-By header entirely.",
        "check_insecure": lambda v: True,  # Always bad to have this
    },
    "X-AspNet-Version": {
        "severity": SeverityLevel.INFO,
        "description": "Reveals the ASP.NET version used by the application.",
        "recommendation": "Remove X-AspNet-Version header from responses.",
        "check_insecure": lambda v: True,
    },
}


class HeaderChecker:
    """Checks HTTP response headers for security best practices."""

    def analyse(self, crawl_results: List[CrawlResult]) -> List[Finding]:
        """Analyse response headers from crawled pages."""
        findings = []
        # Only check the first page's headers (main domain config)
        # to avoid duplicate findings for every page
        checked = False
        for result in crawl_results:
            if result.response_headers and not checked:
                findings.extend(self._check_missing_headers(result))
                findings.extend(self._check_insecure_headers(result))
                checked = True
        return findings

    def _check_missing_headers(self, result: CrawlResult) -> List[Finding]:
        """Check for missing security headers."""
        findings = []
        headers = {k.lower(): v for k, v in result.response_headers.items()}

        for header_name, config in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower not in headers:
                findings.append(Finding(
                    url=result.url,
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
                    severity=config["severity"],
                    evidence=f"Missing header: {header_name}",
                    confidence=0.95,
                    description=f"Security header '{header_name}' is missing. "
                                f"{config['description']}",
                    recommendation=config["recommendation"],
                ))
            else:
                # Header exists — check if properly configured
                value = headers[header_lower]
                try:
                    if not config["check_value"](value):
                        findings.append(Finding(
                            url=result.url,
                            parameter="",
                            payload="",
                            vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
                            severity=SeverityLevel.LOW,
                            evidence=f"Weak configuration for {header_name}: {value}",
                            confidence=0.7,
                            description=f"Security header '{header_name}' is present but may be "
                                        f"misconfigured. Current value: '{value}'",
                            recommendation=config["recommendation"],
                        ))
                except Exception:
                    pass  # Skip validation errors for malformed values

        return findings

    def _check_insecure_headers(self, result: CrawlResult) -> List[Finding]:
        """Check for headers that disclose sensitive information."""
        findings = []
        headers = {k.lower(): v for k, v in result.response_headers.items()}

        for header_name, config in INSECURE_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower in headers:
                value = headers[header_lower]
                if config["check_insecure"](value):
                    findings.append(Finding(
                        url=result.url,
                        parameter="",
                        payload="",
                        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        severity=config["severity"],
                        evidence=f"{header_name}: {value}",
                        confidence=0.9,
                        description=config["description"],
                        recommendation=config["recommendation"],
                    ))

        return findings
