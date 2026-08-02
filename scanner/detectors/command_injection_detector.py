"""
Command Injection Detector
Implements professional-grade synchronous and time-based (blind) command injection detection.
"""
import logging
import time
from typing import List, Optional
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

class CommandInjectionDetector:
    """Detects Command Injection vulnerabilities via output matching and time delays."""

    # Common command injection payloads
    # Mix of Windows and Linux payloads
    PAYLOADS_SYNC = [
        "; cat /etc/passwd",
        "; type C:\\Windows\\win.ini",
        "| whoami",
        "| id",
        "`id`",
        "$(whoami)"
    ]

    # Time-based payloads (request should take exactly X seconds to return)
    # Using 'ping' on windows and 'sleep' on linux
    PAYLOADS_BLIND = {
        "; sleep 5": 5,
        "| sleep 5": 5,
        "& ping -n 6 127.0.0.1": 5,  # ping -n 6 takes approx 5 seconds
        "| ping -c 6 127.0.0.1": 5
    }

    # Regex patterns indicating successful execution
    SUCCESS_PATTERNS = [
        "root:x:0:0:",
        "uid=0(root)",
        "\\[extensions\\]",
        "nt authority\\\\system"
    ]

    def analyse(self, fuzz_results: List[any]) -> List[Finding]:
        """Analyze fuzzing results for synchronous command injection signatures."""
        findings = []
        
        for result in fuzz_results:
            if not getattr(result, "response_body", None) or not getattr(result, "payload", None):
                continue
                
            payload = getattr(result, "payload", "")
            
            # Check if this was one of our sync payloads
            if any(p in payload for p in self.PAYLOADS_SYNC):
                body_lower = getattr(result, "response_body", "").lower()
                
                # Check for output signatures
                for pattern in self.SUCCESS_PATTERNS:
                    if pattern.lower() in body_lower:
                        findings.append(Finding(
                            url=getattr(result, "url", ""),
                            parameter=getattr(result, "parameter", "Unknown"),
                            payload=payload,
                            vuln_type=VulnerabilityType.COMMAND_INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            evidence=f"Server executed OS command. Response contained signature: '{pattern}'.",
                            confidence=0.99,
                            description="OS Command Injection detected. The application passes unsafe user-supplied data to a system shell, allowing attackers to execute arbitrary OS commands.",
                            recommendation="Avoid calling OS commands directly. If necessary, use safe language APIs (e.g., subprocess.run) and strictly whitelist input. Never pass raw user input to a shell."
                        ))
                        break # Prevent duplicate findings for same result
                        
            # Check for time-based (blind) injection
            for blind_payload, expected_delay in self.PAYLOADS_BLIND.items():
                if blind_payload in payload:
                    response_time = getattr(result, "response_time", 0)
                    # If it took roughly the expected amount of time (+/- 1 second for network jitter)
                    if expected_delay - 0.5 <= response_time <= expected_delay + 2.0:
                        findings.append(Finding(
                            url=getattr(result, "url", ""),
                            parameter=getattr(result, "parameter", "Unknown"),
                            payload=payload,
                            vuln_type=VulnerabilityType.COMMAND_INJECTION,
                            severity=SeverityLevel.HIGH,
                            evidence=f"Time-based execution detected. Payload requested a {expected_delay}s delay, and server took {response_time:.2f}s to respond.",
                            confidence=0.95, # slightly lower confidence than exact output match
                            description="Blind OS Command Injection detected. While no output was returned, the application executed a payload that intentionally delayed the server response.",
                            recommendation="Avoid calling OS commands directly. If necessary, use safe language APIs (e.g., subprocess.run) and strictly whitelist input."
                        ))
                        break

        return findings
