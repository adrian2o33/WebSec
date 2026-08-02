"""
ML Pipeline 1: Vulnerability Classification & Prioritisation
Predicts severity and risk score for each finding, then sorts by priority.
Uses a trained Random Forest or falls back to rule-based classification.
"""
import os
import logging
from typing import List, Optional

import numpy as np

from scanner.models import Finding, SeverityLevel, VulnerabilityType
from ml.feature_extractor import FeatureExtractor
from config import MLConfig

logger = logging.getLogger(__name__)


# Rule-based severity mapping (fallback when no trained model is available)
SEVERITY_RULES = {
    VulnerabilityType.SQL_INJECTION: SeverityLevel.CRITICAL,
    VulnerabilityType.COMMAND_INJECTION: SeverityLevel.CRITICAL,
    VulnerabilityType.CRYPTO_MINER: SeverityLevel.CRITICAL,
    VulnerabilityType.MALICIOUS_SCRIPT: SeverityLevel.CRITICAL,
    VulnerabilityType.PHISHING_INDICATOR: SeverityLevel.CRITICAL,
    VulnerabilityType.XSS_REFLECTED: SeverityLevel.HIGH,
    VulnerabilityType.XSS_STORED: SeverityLevel.HIGH,
    VulnerabilityType.PATH_TRAVERSAL: SeverityLevel.HIGH,
    VulnerabilityType.MALWARE_DOWNLOAD: SeverityLevel.HIGH,
    VulnerabilityType.INSECURE_CERTIFICATE: SeverityLevel.HIGH,
    VulnerabilityType.MISSING_HTTPS: SeverityLevel.MEDIUM,
    VulnerabilityType.SUSPICIOUS_IFRAME: SeverityLevel.MEDIUM,
    VulnerabilityType.MALICIOUS_REDIRECT: SeverityLevel.MEDIUM,
    VulnerabilityType.OBFUSCATED_CODE: SeverityLevel.MEDIUM,
    VulnerabilityType.INSECURE_COOKIE: SeverityLevel.MEDIUM,
    VulnerabilityType.MISSING_SECURITY_HEADER: SeverityLevel.LOW,
    VulnerabilityType.INFORMATION_DISCLOSURE: SeverityLevel.INFO,
    VulnerabilityType.OTHER: SeverityLevel.LOW,
}

# Risk multipliers based on context
CONTEXT_MULTIPLIERS = {
    "admin": 1.5,
    "login": 1.4,
    "api": 1.3,
    "auth": 1.4,
    "payment": 1.5,
    "upload": 1.3,
    "config": 1.2,
    "password": 1.5,
}


class Prioritiser:
    """
    Classifies and prioritises vulnerability findings.
    Uses a trained ML model if available, otherwise falls back to rules.
    """

    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self._load_model()

    def _load_model(self):
        """Try to load a pre-trained model."""
        model_path = os.path.join(MLConfig.MODEL_DIR, "prioritiser_model.pkl")
        if os.path.exists(model_path):
            try:
                import joblib
                self.model = joblib.load(model_path)
                logger.info("Loaded trained prioritisation model")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}, using rule-based fallback")
                self.model = None

    def prioritise(self, findings: List[Finding]) -> List[Finding]:
        """Classify severity and sort findings by priority."""
        if not findings:
            return findings

        if self.model:
            return self._ml_prioritise(findings)
        else:
            return self._rule_based_prioritise(findings)

    def _ml_prioritise(self, findings: List[Finding]) -> List[Finding]:
        """Use trained ML model for prioritisation."""
        features = self.feature_extractor.extract_batch(findings)
        predictions = self.model.predict(features)

        severity_map = {
            0: SeverityLevel.CRITICAL,
            1: SeverityLevel.HIGH,
            2: SeverityLevel.MEDIUM,
            3: SeverityLevel.LOW,
            4: SeverityLevel.INFO,
        }

        for finding, pred in zip(findings, predictions):
            finding.ml_severity = severity_map.get(int(pred), SeverityLevel.MEDIUM)

        # Sort by ML-predicted severity, then confidence
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        findings.sort(key=lambda f: (
            severity_order.get(f.ml_severity or f.severity, 5),
            -f.confidence
        ))

        return findings

    def _rule_based_prioritise(self, findings: List[Finding]) -> List[Finding]:
        """Use rule-based logic for prioritisation (fallback)."""
        for finding in findings:
            # Base severity from rules
            base_severity = SEVERITY_RULES.get(finding.vuln_type, SeverityLevel.MEDIUM)

            # Calculate risk score
            risk_score = self._calculate_risk_score(finding)

            # Adjust severity based on risk score
            if risk_score >= 0.9 and base_severity != SeverityLevel.CRITICAL:
                # Upgrade one level
                adjusted = self._upgrade_severity(base_severity)
            elif risk_score <= 0.3 and base_severity not in (SeverityLevel.LOW, SeverityLevel.INFO):
                adjusted = self._downgrade_severity(base_severity)
            else:
                adjusted = base_severity

            finding.ml_severity = adjusted

        # Sort
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        findings.sort(key=lambda f: (
            severity_order.get(f.ml_severity or f.severity, 5),
            -f.confidence
        ))

        logger.info(f"Rule-based prioritisation complete for {len(findings)} findings")
        return findings

    def _calculate_risk_score(self, finding: Finding) -> float:
        """Calculate a 0-1 risk score based on multiple factors."""
        score = finding.confidence

        # Context multiplier from URL/parameter
        url_lower = finding.url.lower()
        param_lower = finding.parameter.lower() if finding.parameter else ""
        max_mult = 1.0
        for keyword, mult in CONTEXT_MULTIPLIERS.items():
            if keyword in url_lower or keyword in param_lower:
                max_mult = max(max_mult, mult)
        score *= max_mult

        # Boost for injection vulns with high confidence
        if finding.vuln_type in (VulnerabilityType.SQL_INJECTION, VulnerabilityType.COMMAND_INJECTION):
            score *= 1.2

        return min(score, 1.0)

    @staticmethod
    def _upgrade_severity(severity: SeverityLevel) -> SeverityLevel:
        order = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM,
                 SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        idx = order.index(severity)
        return order[min(idx + 1, len(order) - 1)]

    @staticmethod
    def _downgrade_severity(severity: SeverityLevel) -> SeverityLevel:
        order = [SeverityLevel.INFO, SeverityLevel.LOW, SeverityLevel.MEDIUM,
                 SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        idx = order.index(severity)
        return order[max(idx - 1, 0)]

    def train(self, findings: List[Finding], labels: List[int]):
        """Train the prioritisation model on labeled data."""
        from sklearn.ensemble import RandomForestClassifier
        import joblib

        features = self.feature_extractor.extract_batch(findings)
        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        model.fit(features, labels)

        os.makedirs(MLConfig.MODEL_DIR, exist_ok=True)
        model_path = os.path.join(MLConfig.MODEL_DIR, "prioritiser_model.pkl")
        joblib.dump(model, model_path)
        self.model = model
        logger.info(f"Prioritisation model trained and saved to {model_path}")
