"""
SSRF Detector
Detects Server-Side Request Forgery via internal port mapping and Out-of-Band (OOB) DNS/HTTP callbacks using interact.sh.
"""
import logging
import time
import requests
import uuid
import re
from typing import List
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

class SSRFDetector:
    """Detects SSRF vulnerabilities using internal mappings and OOB listeners."""

    # Parameters highly susceptible to SSRF
    TARGET_PARAMS = ["url", "redirect", "webhook", "api", "path", "dest", "uri", "endpoint"]

    # Internal payloads for mapping
    INTERNAL_PAYLOADS = [
        "http://127.0.0.1:80",
        "http://localhost:22",
        "http://169.254.169.254/latest/meta-data/"
    ]

    # Signatures that indicate a successful internal routing
    INTERNAL_SIGNATURES = [
        "OpenSSH",         # Port 22
        "ami-id",          # AWS Metadata
        "instance-id",
        "Index of /",      # Local web server
    ]

    def __init__(self):
        self.interactsh_server = "interact.sh"
        self.correlation_id = str(uuid.uuid4()).replace("-", "")[:20]
        # Example URL: 1234567890abcdef.interact.sh
        self.oob_payload = f"http://{self.correlation_id}.{self.interactsh_server}"

    def analyse(self, fuzz_results: List[any]) -> List[Finding]:
        """Analyze fuzzing results for SSRF signatures and trigger OOB checks."""
        findings = []
        oob_injected = False
        
        for result in fuzz_results:
            param = getattr(result, "parameter", "").lower()
            payload = getattr(result, "payload", "")
            
            # Check internal mappings
            if any(p in payload for p in self.INTERNAL_PAYLOADS):
                body_lower = getattr(result, "response_body", "").lower()
                for sig in self.INTERNAL_SIGNATURES:
                    if sig.lower() in body_lower:
                        findings.append(Finding(
                            url=getattr(result, "url", ""),
                            parameter=getattr(result, "parameter", "Unknown"),
                            payload=payload,
                            vuln_type=VulnerabilityType.SSRF,
                            severity=SeverityLevel.CRITICAL,
                            evidence=f"Successfully routed request to internal network. Response revealed internal service signature: '{sig}'.",
                            confidence=0.99,
                            description="Server-Side Request Forgery (SSRF) detected. The server accepts user-supplied URLs and fetches them without validation, allowing access to internal services or cloud metadata.",
                            recommendation="Implement a strict whitelist of allowed domains or IP addresses. Never trust user-supplied input for backend HTTP requests. Disable following redirects on backend HTTP clients."
                        ))
                        break
                        
            # Check if our OOB payload was injected
            if self.correlation_id in payload:
                oob_injected = True

        # If we injected OOB payloads during the fuzzing phase, we poll the listener now
        if oob_injected:
            oob_finding = self._poll_interactsh()
            if oob_finding:
                # We can't perfectly map the OOB ping back to the exact URL/param in this simple async flow without caching the exact request context, 
                # so we report a general high severity finding for the domain.
                findings.append(Finding(
                    url="Multiple endpoints (OOB Ping)",
                    parameter="Unknown",
                    payload=self.oob_payload,
                    vuln_type=VulnerabilityType.SSRF,
                    severity=SeverityLevel.HIGH,
                    evidence=f"Received out-of-band (OOB) HTTP/DNS interaction from target server to {self.oob_payload}.",
                    confidence=0.95,
                    description="Blind Server-Side Request Forgery (SSRF) detected via Out-of-Band (OOB) callback. The server successfully resolved and initiated an HTTP request to our external listener.",
                    recommendation="Implement a strict whitelist of allowed domains or IP addresses. Never trust user-supplied input for backend HTTP requests. Disable following redirects on backend HTTP clients."
                ))

        return findings

    def _poll_interactsh(self):
        """Mock polling of an interact.sh server. 
        In a full implementation, this uses polling via the interact.sh API with an AES decryption key.
        """
        logger.info(f"Polling OOB listener for interactions with {self.correlation_id}.{self.interactsh_server}")
        # Note: Since integrating the actual interact.sh API requires async polling and AES crypto,
        # we are outlining the integration point here for the professional grade engine.
        # This will return False in the mock environment unless we hardcode a hit.
        return False
