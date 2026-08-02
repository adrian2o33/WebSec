"""
ML Feature Extractor
Extracts numerical/categorical features from Finding objects
for use in ML classification and false-positive prediction.
"""
import re
import logging
from typing import List, Dict, Any
import numpy as np

from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# One-hot encoding order for vulnerability types
VULN_TYPE_ORDER = [
    VulnerabilityType.XSS_REFLECTED,
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.PATH_TRAVERSAL,
    VulnerabilityType.COMMAND_INJECTION,
    VulnerabilityType.MISSING_HTTPS,
    VulnerabilityType.INSECURE_CERTIFICATE,
    VulnerabilityType.MISSING_SECURITY_HEADER,
    VulnerabilityType.INSECURE_COOKIE,
    VulnerabilityType.MALICIOUS_SCRIPT,
    VulnerabilityType.SUSPICIOUS_IFRAME,
    VulnerabilityType.MALICIOUS_REDIRECT,
    VulnerabilityType.MALWARE_DOWNLOAD,
    VulnerabilityType.OBFUSCATED_CODE,
    VulnerabilityType.CRYPTO_MINER,
    VulnerabilityType.PHISHING_INDICATOR,
    VulnerabilityType.INFORMATION_DISCLOSURE,
    VulnerabilityType.OTHER,
]

# Keywords that indicate high risk
HIGH_RISK_KEYWORDS = [
    "admin", "login", "password", "auth", "session", "token",
    "api", "upload", "delete", "exec", "eval", "system",
]

LOW_RISK_KEYWORDS = [
    "search", "comment", "feedback", "contact", "newsletter",
    "subscribe", "filter", "sort", "page",
]


class FeatureExtractor:
    """Extracts ML features from scan findings."""

    def extract(self, finding: Finding) -> np.ndarray:
        """Extract feature vector from a single finding."""
        features = []

        # Feature 1: Vulnerability type (one-hot encoded)
        vuln_one_hot = [0.0] * len(VULN_TYPE_ORDER)
        try:
            idx = VULN_TYPE_ORDER.index(finding.vuln_type)
            vuln_one_hot[idx] = 1.0
        except ValueError:
            pass
        features.extend(vuln_one_hot)

        # Feature 2: Original confidence score
        features.append(finding.confidence)

        # Feature 3: Evidence length (normalised)
        features.append(min(len(finding.evidence) / 500.0, 1.0))

        # Feature 4: Payload length (normalised)
        features.append(min(len(finding.payload) / 200.0, 1.0) if finding.payload else 0.0)

        # Feature 5: Parameter name risk score
        param_risk = self._param_risk_score(finding.parameter)
        features.append(param_risk)

        # Feature 6: URL path depth
        path_depth = finding.url.count('/') - 2  # subtract scheme://
        features.append(min(path_depth / 10.0, 1.0))

        # Feature 7: Is the URL path an admin/sensitive area?
        is_sensitive = 1.0 if any(kw in finding.url.lower() for kw in
                                  ["admin", "api", "config", "settings", "manage",
                                   "dashboard", "internal", "private"]) else 0.0
        features.append(is_sensitive)

        # Feature 8: Number of high-risk keywords in evidence
        evidence_lower = finding.evidence.lower()
        hrk_count = sum(1 for kw in HIGH_RISK_KEYWORDS if kw in evidence_lower)
        features.append(min(hrk_count / 5.0, 1.0))

        # Feature 9: Has the finding a non-empty payload?
        features.append(1.0 if finding.payload else 0.0)

        # Feature 10: Severity ordinal (for FP filter - original severity as feature)
        severity_map = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.6,
            SeverityLevel.LOW: 0.4,
            SeverityLevel.INFO: 0.2,
        }
        features.append(severity_map.get(finding.severity, 0.5))

        # Feature 11: URL length (normalised)
        features.append(min(len(finding.url) / 200.0, 1.0))

        # Feature 12: Special character count in parameter and payload
        combined_text = (finding.parameter or "") + (finding.payload or "")
        special_chars = sum(1 for c in combined_text if c in "<>\"'%;()&+=")
        features.append(min(special_chars / 20.0, 1.0))

        return np.array(features, dtype=np.float64)

    def extract_batch(self, findings: List[Finding]) -> np.ndarray:
        """Extract features for a batch of findings."""
        if not findings:
            return np.array([])
        return np.array([self.extract(f) for f in findings])

    @staticmethod
    def feature_names() -> List[str]:
        """Return ordered list of feature names (for interpretability)."""
        names = [f"vuln_type_{vt.value}" for vt in VULN_TYPE_ORDER]
        names.extend([
            "confidence", "evidence_length", "payload_length",
            "param_risk_score", "url_depth", "is_sensitive_path",
            "high_risk_keyword_count", "has_payload", "severity_ordinal",
            "url_length", "special_char_count",
        ])
        return names

    @staticmethod
    def _param_risk_score(parameter: str) -> float:
        """Score how risky a parameter name is (higher = more risky)."""
        if not parameter:
            return 0.5
        param_lower = parameter.lower()
        if any(kw in param_lower for kw in HIGH_RISK_KEYWORDS):
            return 0.9
        if any(kw in param_lower for kw in LOW_RISK_KEYWORDS):
            return 0.3
        return 0.5
