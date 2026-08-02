"""
Path Traversal Detector
Analyses fuzzing responses for signs of Local File Inclusion / directory traversal.
"""
import re
import logging
from typing import List, Optional
from scanner.fuzzer import FuzzResult
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# Patterns that indicate successful file read
FILE_CONTENT_PATTERNS = [
    # Unix
    (r"root:.*?:0:0:", "Unix /etc/passwd content detected"),
    (r"daemon:.*?:/usr/sbin", "Unix /etc/passwd daemon entry"),
    (r"bin:.*?:/bin", "Unix /etc/passwd bin entry"),
    (r"nobody:.*?:/nonexistent", "Unix /etc/passwd nobody entry"),
    (r"\[boot loader\]", "Windows boot.ini content detected"),
    (r"\[fonts\]", "Windows win.ini content detected"),
    (r"\[extensions\]", "Windows win.ini/system.ini content"),
    # Windows
    (r"# Copyright.*?Microsoft", "Windows system file content"),
    (r"127\.0\.0\.1\s+localhost", "Hosts file content detected"),
    (r"\[boot loader\][\s\S]*?timeout", "Windows boot.ini detected"),
    # Generic sensitive file content
    (r"DB_PASSWORD\s*=", "Database credentials in config file"),
    (r"SECRET_KEY\s*=", "Secret key in config file"),
    (r"-----BEGIN.*?PRIVATE KEY-----", "Private key file detected"),
    (r"<\?php", "PHP source code disclosed"),
]


class PathTraversalDetector:
    """Detects path traversal / LFI vulnerabilities from fuzz results."""

    def __init__(self):
        self._compiled = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in FILE_CONTENT_PATTERNS
        ]

    def analyse(self, fuzz_results: List[FuzzResult]) -> List[Finding]:
        """Analyse fuzz results for path traversal indicators."""
        findings = []
        for result in fuzz_results:
            finding = self._check_traversal(result)
            if finding:
                findings.append(finding)
        return findings

    def _check_traversal(self, result: FuzzResult) -> Optional[Finding]:
        """Check a single fuzz result for path traversal indicators."""
        if not result.response_body:
            return None

        payload = result.payload
        traversal_indicators = ['../', '..\\', '%2F', '%5C', '%252F', '%c0%af',
                                'etc/passwd', 'win.ini', 'boot.ini', 'hosts']
        if not any(ind.lower() in payload.lower() for ind in traversal_indicators):
            return None

        body = result.response_body
        confidence = 0.0
        evidence_parts = []

        # Check for file content patterns
        for pattern, description in self._compiled:
            match = pattern.search(body)
            if match:
                confidence += 0.65
                ctx = body[max(0, match.start() - 20):match.end() + 50]
                evidence_parts.append(f"{description}: ...{ctx[:200]}...")
                break

        # Check for response anomaly (file contents usually differ from normal)
        if result.baseline_length > 0:
            current_len = len(body)
            if current_len > result.baseline_length * 1.5 and current_len != result.baseline_length:
                confidence += 0.15
                evidence_parts.append(
                    f"Response size anomaly ({current_len} vs baseline {result.baseline_length})"
                )

        # Check for content type change (might serve plaintext instead of HTML)
        content_type = result.response_headers.get("Content-Type", "")
        if "text/plain" in content_type or "application/octet-stream" in content_type:
            confidence += 0.1
            evidence_parts.append(f"Unusual Content-Type: {content_type}")

        if confidence >= 0.5:
            return Finding(
                url=result.url,
                parameter=result.parameter,
                payload=payload,
                vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                severity=SeverityLevel.HIGH,
                evidence="; ".join(evidence_parts)[:500],
                confidence=min(confidence, 1.0),
                description=f"Path traversal vulnerability in parameter '{result.parameter}'. "
                            f"An attacker could read arbitrary files from the server filesystem.",
                recommendation="Validate and sanitise file path inputs. Use a whitelist of allowed files. "
                               "Avoid using user input to construct file paths. "
                               "Implement chroot or sandboxing for file access.",
            )
        return None
