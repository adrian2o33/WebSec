"""
XSS Detector
Analyses fuzzing responses for signs of Cross-Site Scripting vulnerabilities.
"""
import re
import logging
from typing import List, Optional
from scanner.fuzzer import FuzzResult
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# Patterns that indicate XSS when payload is reflected
XSS_REFLECTION_PATTERNS = [
    (r'<script[^>]*>.*?alert\s*\(', "Script tag with alert reflected"),
    (r'<img[^>]+onerror\s*=', "Image tag with onerror handler reflected"),
    (r'<svg[^>]+onload\s*=', "SVG tag with onload handler reflected"),
    (r'<body[^>]+onload\s*=', "Body tag with onload handler reflected"),
    (r'<input[^>]+onfocus\s*=', "Input tag with onfocus handler reflected"),
    (r'<details[^>]+ontoggle\s*=', "Details tag with ontoggle handler reflected"),
    (r'<marquee[^>]+onstart\s*=', "Marquee tag with onstart handler reflected"),
    (r'<video[^>]+onerror\s*=', "Video tag with onerror reflected"),
    (r'<audio[^>]+onerror\s*=', "Audio tag with onerror reflected"),
    (r'javascript\s*:', "JavaScript URI scheme reflected"),
    (r'on\w+\s*=\s*["\']?\s*alert', "Event handler with alert reflected"),
]

# Context-sensitive patterns
DANGEROUS_CONTEXTS = [
    (r'<script[^>]*>[^<]*{payload}', "Payload inside script block"),
    (r'on\w+\s*=\s*["\'][^"\']*{payload}', "Payload inside event handler"),
    (r'href\s*=\s*["\']javascript:[^"\']*{payload}', "Payload inside javascript: URI"),
    (r'<[^>]+{payload}[^>]*>', "Payload inside HTML tag attributes"),
]


class XSSDetector:
    """Detects reflected XSS vulnerabilities from fuzz results."""

    def analyse(self, fuzz_results: List[FuzzResult]) -> List[Finding]:
        """Analyse fuzz results and return XSS findings."""
        findings = []
        for result in fuzz_results:
            finding = self._check_xss(result)
            if finding:
                findings.append(finding)
        return findings

    def _check_xss(self, result: FuzzResult) -> Optional[Finding]:
        """Check a single fuzz result for XSS indicators."""
        if not result.response_body:
            return None

        body = result.response_body
        payload = result.payload

        # Skip non-XSS payloads
        xss_indicators = ['<script', '<img', '<svg', '<body', 'onerror', 'onload',
                          'onfocus', 'alert(', 'javascript:', 'onmouseover',
                          'ontoggle', 'onstart', '{{', '${', '<%']
        if not any(ind.lower() in payload.lower() for ind in xss_indicators):
            return None

        confidence = 0.0
        evidence_parts = []

        # Check 1: Direct payload reflection (strongest signal)
        if payload in body:
            confidence += 0.6
            # Find context around the reflected payload
            idx = body.find(payload)
            start = max(0, idx - 50)
            end = min(len(body), idx + len(payload) + 50)
            evidence_parts.append(f"Payload reflected verbatim: ...{body[start:end]}...")

            # Check if payload is inside a dangerous context (not escaped)
            surrounding = body[max(0, idx - 200):min(len(body), idx + len(payload) + 200)]
            # Not inside an HTML comment
            if '<!--' not in surrounding[:surrounding.find(payload)] or '-->' in surrounding[:surrounding.find(payload)]:
                confidence += 0.1

        # Check 2: Pattern-based detection
        for pattern, description in XSS_REFLECTION_PATTERNS:
            try:
                if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                    confidence += 0.15
                    evidence_parts.append(description)
                    break  # One match is enough
            except re.error:
                continue

        # Check 3: Template injection indicators
        if '{{' in payload or '${' in payload:
            # Check if the template was evaluated (e.g., {{73*73}} -> 5329)
            if '5329' in body and ('{{73*73}}' in payload or '${73*73}' in payload):
                confidence += 0.7
                evidence_parts.append("Template expression evaluated (SSTI)")

        # Check 4: Content-Type header — XSS in HTML is more dangerous
        content_type = result.response_headers.get("Content-Type", "")
        if "text/html" in content_type:
            confidence += 0.05

        # Only report if confidence above threshold
        if confidence >= 0.5:
            severity = SeverityLevel.HIGH if confidence >= 0.7 else SeverityLevel.MEDIUM
            return Finding(
                url=result.url,
                parameter=result.parameter,
                payload=payload,
                vuln_type=VulnerabilityType.XSS_REFLECTED,
                severity=severity,
                evidence="; ".join(evidence_parts)[:500],
                confidence=min(confidence, 1.0),
                description=f"Reflected XSS detected in parameter '{result.parameter}'. "
                            f"The injected payload was reflected in the response without proper sanitisation.",
                recommendation="Sanitise and encode all user input before rendering in HTML. "
                               "Implement Content-Security-Policy headers. Use framework auto-escaping.",
            )
        return None
