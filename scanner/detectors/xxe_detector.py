"""
XXE (XML External Entity) Detector
Analyses fuzzing responses or specific XML payload injections
for signs of insecure XML parsing vulnerabilities.
"""
import re
import logging
from typing import List, Optional
from scanner.fuzzer import FuzzResult
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# Patterns that suggest successful local file read or XXE error
XXE_ERROR_PATTERNS = [
    (r"XML parser error", "Generic XML parser error"),
    (r"SAXParseException", "Java SAX XML Parser Exception"),
    (r"EntityRef: expecting ';'", "XML Entity syntax error"),
    (r"Warning: DOMDocument::loadXML", "PHP DOMDocument warning"),
    (r"libxml2", "libxml2 error"),
    (r"DOCTYPE is improperly defined", "Improper DOCTYPE error")
]

XXE_SUCCESS_PATTERNS = [
    (r"root:.*?:0:0:", "Unix /etc/passwd content leaked via XXE"),
    (r"\[extensions\]", "Windows win.ini content leaked via XXE"),
    (r"root:x:0:0:root", "Unix /etc/passwd content leaked via XXE")
]

class XXEDetector:
    """Detects XXE vulnerabilities from fuzz results."""

    def __init__(self):
        self._compiled_error_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in XXE_ERROR_PATTERNS
        ]
        self._compiled_success_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in XXE_SUCCESS_PATTERNS
        ]

    def analyse(self, fuzz_results: List[FuzzResult]) -> List[Finding]:
        """Analyse fuzz results for XXE indicators."""
        findings = []
        for result in fuzz_results:
            finding = self._check_xxe(result)
            if finding:
                findings.append(finding)
        return findings

    def _check_xxe(self, result: FuzzResult) -> Optional[Finding]:
        """Check a single fuzz result for XXE indicators."""
        if not result.response_body:
            return None

        body = result.response_body
        payload = result.payload

        # Only check XXE-relevant payloads
        xxe_indicators = ['<!ENTITY', 'SYSTEM', 'DOCTYPE', 'file://', 'http://']
        if not any(ind.lower() in payload.lower() for ind in xxe_indicators):
            return None

        confidence = 0.0
        evidence_parts = []

        # Check 1: XML error messages in response
        for pattern, description in self._compiled_error_patterns:
            match = pattern.search(body)
            if match:
                confidence += 0.5
                context = body[max(0, match.start() - 30):match.end() + 30]
                evidence_parts.append(f"{description}: ...{context}...")
                break

        # Check 2: Successful local file read indicators
        for pattern, description in self._compiled_success_patterns:
            if pattern.search(body):
                confidence += 0.9  # Direct file leak is near certainty
                evidence_parts.append(description)
                break

        if confidence >= 0.5:
            severity = SeverityLevel.CRITICAL if confidence >= 0.8 else SeverityLevel.HIGH
            return Finding(
                url=result.url,
                parameter=result.parameter,
                payload=payload,
                vuln_type=VulnerabilityType.XXE_INJECTION,
                severity=severity,
                evidence="; ".join(evidence_parts)[:500],
                confidence=min(confidence, 1.0),
                description=f"XML External Entity (XXE) Injection detected in parameter '{result.parameter}'. "
                            f"The server's XML parser is insecurely configured and processing external entities.",
                recommendation="Disable external entity parsing and DTD processing in your XML parser. "
                               "If parsing XML is required, strictly use modern, hardened libraries."
            )
        return None
