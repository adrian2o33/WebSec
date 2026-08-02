"""
Cookie Security Checker
Analyses cookies for missing security flags (HttpOnly, Secure, SameSite).
"""
import logging
from typing import List
from urllib.parse import urlparse

import requests

from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult

logger = logging.getLogger(__name__)


class CookieChecker:
    """Checks cookies for security best practices."""

    def analyse(self, target_url: str, session: requests.Session = None,
                crawl_results: List[CrawlResult] = None) -> List[Finding]:
        """Analyse cookies set by the target site."""
        findings = []

        if session:
            findings.extend(self._check_session_cookies(target_url, session))

        if crawl_results:
            findings.extend(self._check_set_cookie_headers(crawl_results))

        return findings

    def _check_session_cookies(self, target_url: str,
                                session: requests.Session) -> List[Finding]:
        """Check cookies stored in the session jar."""
        findings = []
        is_https = target_url.startswith("https://")

        for cookie in session.cookies:
            cookie_name = cookie.name
            issues = []

            # Check Secure flag
            if not cookie.secure:
                issues.append("Missing 'Secure' flag")

            # Check HttpOnly (not directly accessible from cookiejar in requests,
            # but we check via Set-Cookie headers below)

            # Check domain scope
            if cookie.domain and cookie.domain.startswith("."):
                # Wildcard domain — could be too broad
                issues.append(f"Broad domain scope: {cookie.domain}")

            # Check path scope
            if cookie.path == "/":
                pass  # This is normal but worth noting for session cookies

            # Check expiry — persistent cookies
            if cookie.expires and cookie.expires > 0:
                import time
                remaining = cookie.expires - time.time()
                if remaining > 365 * 24 * 3600:
                    issues.append(f"Very long expiry ({remaining / (24 * 3600):.0f} days)")

            if issues:
                findings.append(Finding(
                    url=target_url,
                    parameter=cookie_name,
                    payload="",
                    vuln_type=VulnerabilityType.INSECURE_COOKIE,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"Cookie '{cookie_name}': {'; '.join(issues)}",
                    confidence=0.85,
                    description=f"Cookie '{cookie_name}' has security configuration issues: "
                                f"{', '.join(issues)}.",
                    recommendation="Set the 'Secure' flag on all cookies (especially session cookies). "
                                   "Set 'HttpOnly' to prevent JavaScript access. "
                                   "Set 'SameSite=Strict' or 'SameSite=Lax' to prevent CSRF.",
                ))

        return findings

    def _check_set_cookie_headers(self, crawl_results: List[CrawlResult]) -> List[Finding]:
        """Parse Set-Cookie headers for security flags."""
        findings = []
        checked_cookies = set()

        for result in crawl_results:
            # Get Set-Cookie headers
            set_cookie = result.response_headers.get("Set-Cookie", "")
            if not set_cookie:
                # Check case-insensitive
                for key, val in result.response_headers.items():
                    if key.lower() == "set-cookie":
                        set_cookie = val
                        break

            if not set_cookie:
                continue

            # Parse each Set-Cookie directive
            cookies = set_cookie.split(",") if "expires=" not in set_cookie.lower() else [set_cookie]
            for cookie_str in cookies:
                parts = cookie_str.strip().split(";")
                if not parts:
                    continue

                name_value = parts[0].strip()
                if "=" not in name_value:
                    continue
                cookie_name = name_value.split("=")[0].strip()

                if cookie_name in checked_cookies:
                    continue
                checked_cookies.add(cookie_name)

                directives = [p.strip().lower() for p in parts[1:]]
                issues = []

                # Check HttpOnly
                if not any("httponly" in d for d in directives):
                    issues.append("Missing 'HttpOnly' flag (cookie accessible via JavaScript)")

                # Check Secure
                if not any("secure" in d for d in directives):
                    issues.append("Missing 'Secure' flag (cookie sent over HTTP)")

                # Check SameSite
                samesite_set = any("samesite" in d for d in directives)
                if not samesite_set:
                    issues.append("Missing 'SameSite' attribute (vulnerable to CSRF)")
                else:
                    for d in directives:
                        if "samesite" in d and "none" in d:
                            issues.append("SameSite=None (cross-site requests allowed)")

                if issues:
                    severity = SeverityLevel.MEDIUM
                    if "httponly" in str(issues).lower() and (
                        "session" in cookie_name.lower() or "token" in cookie_name.lower()
                    ):
                        severity = SeverityLevel.HIGH

                    findings.append(Finding(
                        url=result.url,
                        parameter=cookie_name,
                        payload="",
                        vuln_type=VulnerabilityType.INSECURE_COOKIE,
                        severity=severity,
                        evidence=f"Cookie '{cookie_name}': {'; '.join(issues)}",
                        confidence=0.9,
                        description=f"Cookie '{cookie_name}' is missing important security flags. "
                                    f"{', '.join(issues)}.",
                        recommendation="Add 'HttpOnly; Secure; SameSite=Lax' flags to all cookies. "
                                       "Session cookies should always have HttpOnly and Secure flags.",
                    ))

        return findings
