"""
Input Validation Detector
Analyses fuzzing responses for signs of missing input validation,
such as application crashes, stack traces, or unhandled exceptions
caused by massive strings or unexpected special characters.
"""
import re
import logging
from typing import List, Optional
from scanner.fuzzer import FuzzResult
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# Patterns that suggest the application crashed or leaked a stack trace
STACK_TRACE_PATTERNS = [
    (r"at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.java:[0-9]+\)", "Java Stack Trace"),
    (r"Traceback \(most recent call last\):", "Python Traceback"),
    (r"Fatal error: Uncaught", "PHP Fatal Error"),
    (r"System\.NullReferenceException", "C# NullReferenceException"),
    (r"Server Error in '/' Application", "ASP.NET Server Error"),
    (r"UnhandledPromiseRejectionWarning", "Node.js Unhandled Exception"),
    (r"TypeError: Cannot read property", "JavaScript TypeError")
]

class InputValidationDetector:
    """Detects missing input validation and unhandled exceptions."""

    def __init__(self):
        self._compiled_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in STACK_TRACE_PATTERNS
        ]

    def analyse(self, fuzz_results: List[FuzzResult]) -> List[Finding]:
        """Analyse fuzz results for input validation failures."""
        findings = []
        for result in fuzz_results:
            finding = self._check_validation_failure(result)
            if finding:
                findings.append(finding)
        return findings

    def _check_validation_failure(self, result: FuzzResult) -> Optional[Finding]:
        """Check a single fuzz result for crashes or stack traces."""
        if not result.response_body:
            return None

        body = result.response_body
        payload = result.payload

        confidence = 0.0
        evidence_parts = []

        # Check 1: Did the server crash with a 500 error?
        if result.response_status == 500:
            confidence += 0.4
            evidence_parts.append("Server crashed with HTTP 500 Internal Server Error")

        # Check 2: Did it leak a stack trace?
        for pattern, description in self._compiled_patterns:
            match = pattern.search(body)
            if match:
                confidence += 0.5
                context = body[max(0, match.start() - 30):match.end() + 30]
                evidence_parts.append(f"{description} leaked: ...{context}...")
                break

        # Check 3: Did a massive payload cause a drastic response length change?
        if len(payload) > 1000 and result.baseline_length > 0:
            ratio = len(body) / max(result.baseline_length, 1)
            if ratio < 0.1:  # Server returned almost nothing, likely crashed quietly
                confidence += 0.3
                evidence_parts.append("Massive payload caused server to drop the response body (potential buffer issue).")

        if confidence >= 0.5:
            severity = SeverityLevel.MEDIUM if confidence < 0.9 else SeverityLevel.HIGH
            return Finding(
                url=result.url,
                parameter=result.parameter,
                payload=payload,
                vuln_type=VulnerabilityType.INVALID_INPUT,
                severity=severity,
                evidence="; ".join(evidence_parts)[:500],
                confidence=min(confidence, 1.0),
                description=f"Missing Input Validation detected in parameter '{result.parameter}'. "
                            f"The application failed to gracefully handle unexpected input, resulting in an unhandled exception or crash.",
                recommendation="Implement strict input validation on the server side using allow-lists. "
                               "Catch all exceptions globally and return generic error messages to the user to prevent stack trace leaks."
            )
        return None
