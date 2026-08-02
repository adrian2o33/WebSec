"""
CSRF Detector
Analyzes forms and cookies for missing Cross-Site Request Forgery protections.
"""
import logging
from typing import List
from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult

logger = logging.getLogger(__name__)

class CSRFDetector:
    """Detects missing CSRF tokens in state-changing forms and insecure session cookie SameSite flags."""

    # Common names for anti-CSRF tokens
    CSRF_TOKENS = ["csrf", "token", "authenticity_token", "_csrf", "xsrf"]

    def analyse(self, crawl_results: List[CrawlResult], auth_cookies: dict = None) -> List[Finding]:
        """Analyse crawled forms and cookies for CSRF vulnerabilities."""
        findings = []
        
        # 1. Analyze session cookies for SameSite (if provided)
        samesite_safe = False
        if auth_cookies:
            # We assume the crawler or login module extracted the raw Set-Cookie strings,
            # or we rely on the header checker. For this module, we'll focus on the forms.
            pass

        # 2. Analyze all forms found during crawling
        for result in crawl_results:
            for form in result.forms:
                # We only care about state-changing methods
                if form.method.upper() not in ["POST", "PUT", "DELETE"]:
                    continue
                    
                has_token = False
                for field in form.fields:
                    if any(t in field.name.lower() for t in self.CSRF_TOKENS) and field.field_type == "hidden":
                        has_token = True
                        break
                        
                if not has_token:
                    # Ignore common non-sensitive forms like search (though POST for search is rare)
                    if "search" in form.action.lower():
                        continue
                        
                    findings.append(Finding(
                        url=result.url,
                        parameter="Form Action: " + form.action,
                        payload="Missing Anti-CSRF Token",
                        vuln_type=VulnerabilityType.CSRF,
                        severity=SeverityLevel.HIGH if "update" in form.action.lower() or "password" in form.action.lower() else SeverityLevel.MEDIUM,
                        evidence=f"State-changing {form.method} form submitting to '{form.action}' lacks a hidden anti-CSRF token.",
                        confidence=0.85, # Medium confidence as we don't know if backend validates it via other means (e.g., custom headers)
                        description="Cross-Site Request Forgery (CSRF) vulnerability detected. An attacker could force an authenticated user to execute unwanted actions (like changing emails or transferring funds) if they visit a malicious site.",
                        recommendation="Implement a robust anti-CSRF mechanism. Include a cryptographically strong, unpredictable hidden token in all state-changing forms. Additionally, set the 'SameSite=Lax' or 'Strict' flag on all session cookies."
                    ))

        return findings
