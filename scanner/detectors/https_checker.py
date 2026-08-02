"""
HTTPS and Certificate Checker
Analyses target sites for HTTPS enforcement and certificate issues.
"""
import ssl
import socket
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import List

import requests

from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult

logger = logging.getLogger(__name__)


class HTTPSChecker:
    """Checks HTTPS configuration, certificate validity, and enforcement."""

    def analyse(self, target_url: str, crawl_results: List[CrawlResult] = None) -> List[Finding]:
        """Run all HTTPS-related checks on the target."""
        findings = []
        parsed = urlparse(target_url)
        hostname = parsed.netloc.split(":")[0]
        port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 443

        # Check 1: Is HTTPS available?
        findings.extend(self._check_https_available(target_url, hostname, port))

        # Check 2: Certificate validation
        findings.extend(self._check_certificate(hostname, port))

        # Check 3: HTTP to HTTPS redirect
        findings.extend(self._check_redirect(hostname))

        # Check 4: Mixed content (if crawl results available)
        if crawl_results:
            findings.extend(self._check_mixed_content(crawl_results))

        return findings

    def _check_https_available(self, target_url: str, hostname: str, port: int) -> List[Finding]:
        """Check if the site is accessible via HTTPS."""
        findings = []
        if target_url.startswith("http://"):
            # Try HTTPS version
            https_url = target_url.replace("http://", "https://", 1)
            try:
                resp = requests.get(https_url, timeout=5, verify=False,
                                    allow_redirects=True)
                if resp.status_code >= 400:
                    findings.append(Finding(
                        url=target_url,
                        parameter="",
                        payload="",
                        vuln_type=VulnerabilityType.MISSING_HTTPS,
                        severity=SeverityLevel.HIGH,
                        evidence=f"HTTPS version returned status {resp.status_code}",
                        confidence=0.9,
                        description="The site does not appear to support HTTPS properly.",
                        recommendation="Enable HTTPS with a valid TLS certificate. "
                                       "Use services like Let's Encrypt for free certificates.",
                    ))
            except Exception:
                findings.append(Finding(
                    url=target_url,
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.MISSING_HTTPS,
                    severity=SeverityLevel.HIGH,
                    evidence="HTTPS connection failed — site may not support TLS",
                    confidence=0.85,
                    description="The target site does not support HTTPS encryption.",
                    recommendation="Configure TLS/SSL on the web server. "
                                   "Use a trusted certificate authority.",
                ))
        return findings

    def _check_certificate(self, hostname: str, port: int) -> List[Finding]:
        """Check TLS certificate validity."""
        findings = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Check expiry
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(Finding(
                            url=f"https://{hostname}",
                            parameter="",
                            payload="",
                            vuln_type=VulnerabilityType.INSECURE_CERTIFICATE,
                            severity=SeverityLevel.CRITICAL,
                            evidence=f"Certificate expired on {cert['notAfter']}",
                            confidence=1.0,
                            description="The site's TLS certificate has expired.",
                            recommendation="Renew the TLS certificate immediately.",
                        ))
                    elif days_left < 7:
                        findings.append(Finding(
                            url=f"https://{hostname}",
                            parameter="",
                            payload="",
                            vuln_type=VulnerabilityType.INSECURE_CERTIFICATE,
                            severity=SeverityLevel.INFO,
                            evidence=f"Certificate expires in {days_left} days ({cert['notAfter']})",
                            confidence=0.9,
                            description="The TLS certificate will expire soon (less than 7 days).",
                            recommendation="Ensure automated renewal (e.g. Let's Encrypt / ACME) is functioning properly.",
                        ))
        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                url=f"https://{hostname}",
                parameter="",
                payload="",
                vuln_type=VulnerabilityType.INSECURE_CERTIFICATE,
                severity=SeverityLevel.HIGH,
                evidence=f"SSL verification failed: {str(e)[:300]}",
                confidence=0.95,
                description="The TLS certificate is invalid or untrusted.",
                recommendation="Use a certificate from a trusted certificate authority. "
                               "Ensure the certificate matches the hostname.",
            ))
        except Exception as e:
            logger.debug(f"Certificate check failed for {hostname}: {e}")
        return findings

    def _check_redirect(self, hostname: str) -> List[Finding]:
        """Check if HTTP redirects to HTTPS."""
        findings = []
        try:
            resp = requests.get(f"http://{hostname}", timeout=5,
                                allow_redirects=False, verify=False)
            if resp.status_code not in (301, 302, 307, 308):
                findings.append(Finding(
                    url=f"http://{hostname}",
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.MISSING_HTTPS,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"HTTP request returned {resp.status_code} instead of redirect to HTTPS",
                    confidence=0.8,
                    description="The site does not redirect HTTP traffic to HTTPS.",
                    recommendation="Configure HTTP to HTTPS redirect (301 permanent redirect). "
                                   "This ensures all traffic is encrypted.",
                ))
            elif resp.is_redirect:
                location = resp.headers.get("Location", "")
                if not location.startswith("https://"):
                    findings.append(Finding(
                        url=f"http://{hostname}",
                        parameter="",
                        payload="",
                        vuln_type=VulnerabilityType.MISSING_HTTPS,
                        severity=SeverityLevel.MEDIUM,
                        evidence=f"HTTP redirects to {location} (not HTTPS)",
                        confidence=0.75,
                        description="HTTP redirects to another HTTP URL instead of HTTPS.",
                        recommendation="Ensure the redirect target uses HTTPS.",
                    ))
        except Exception as e:
            logger.debug(f"Redirect check failed for {hostname}: {e}")
        return findings

    def _check_mixed_content(self, crawl_results: List[CrawlResult]) -> List[Finding]:
        """Check for HTTP resources loaded on HTTPS pages (mixed content)."""
        findings = []
        for result in crawl_results:
            if not result.url.startswith("https://") or not result.response_body:
                continue
            import re
            http_resources = re.findall(
                r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
                result.response_body, re.IGNORECASE
            )
            if http_resources:
                findings.append(Finding(
                    url=result.url,
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.MISSING_HTTPS,
                    severity=SeverityLevel.LOW,
                    evidence=f"Mixed content: {len(http_resources)} HTTP resource(s) on HTTPS page. "
                             f"Examples: {'; '.join(http_resources[:3])}",
                    confidence=0.85,
                    description="HTTPS page loads resources over insecure HTTP (mixed content).",
                    recommendation="Serve all resources over HTTPS. Use protocol-relative URLs or HTTPS.",
                ))
        return findings
