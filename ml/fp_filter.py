"""
ML Pipeline 2: False Positive Suppression
Predicts the probability that each finding is a true positive,
filtering out likely false alarms.
"""
import os
import logging
from typing import List

import numpy as np

from scanner.models import Finding, VulnerabilityType, SeverityLevel
from ml.feature_extractor import FeatureExtractor
from config import MLConfig

logger = logging.getLogger(__name__)

# Heuristic rules for known false positive patterns (fallback)
FP_HEURISTIC_RULES = [
    {
        "condition": lambda f: (
            f.vuln_type == VulnerabilityType.SQL_INJECTION and
            f.confidence < 0.6 and
            "Invalid" in f.evidence and
            "syntax error" not in f.evidence.lower()
        ),
        "reason": "Generic 'Invalid' message without SQL error pattern — likely false positive",
    },
    {
        "condition": lambda f: (
            f.vuln_type == VulnerabilityType.XSS_REFLECTED and
            f.confidence < 0.6 and
            "{{" in f.payload and
            "49" not in f.evidence
        ),
        "reason": "SSTI payload not evaluated — template injection not confirmed",
    },
    {
        "condition": lambda f: (
            f.vuln_type == VulnerabilityType.PATH_TRAVERSAL and
            f.confidence < 0.6 and
            "root:" not in f.evidence and
            "[fonts]" not in f.evidence.lower() and
            "localhost" not in f.evidence
        ),
        "reason": "Path traversal without file content confirmation — likely false positive",
    },
    {
        "condition": lambda f: (
            f.vuln_type == VulnerabilityType.MALICIOUS_REDIRECT and
            f.confidence < 0.6
        ),
        "reason": "Low-confidence redirect detection — may be legitimate navigation",
    },
    {
        "condition": lambda f: (
            f.vuln_type == VulnerabilityType.OBFUSCATED_CODE and
            f.confidence < 0.6
        ),
        "reason": "Low-confidence obfuscation detection — may be minified JS",
    },
]


class FalsePositiveFilter:
    """
    Filters likely false positive findings using ML or heuristic rules.
    Assigns a true-positive probability to each finding.
    """

    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.threshold = MLConfig.FP_FILTER_THRESHOLD
        self._load_model()

    def _load_model(self):
        """Try to load a pre-trained false-positive detection model."""
        model_path = os.path.join(MLConfig.MODEL_DIR, "fp_filter_model.pkl")
        if os.path.exists(model_path):
            try:
                import joblib
                self.model = joblib.load(model_path)
                logger.info("Loaded trained false-positive filter model")
            except Exception as e:
                logger.warning(f"Failed to load FP model: {e}, using heuristic fallback")
                self.model = None

    def filter(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings, removing likely false positives."""
        if not findings:
            return findings

        if self.model:
            return self._ml_filter(findings)
        else:
            return self._heuristic_filter(findings)

    def _ml_filter(self, findings: List[Finding]) -> List[Finding]:
        """Use trained ML model to filter false positives."""
        features = self.feature_extractor.extract_batch(findings)

        # Get probability of being a true positive
        probabilities = self.model.predict_proba(features)
        # Assume class 1 = true positive
        tp_probs = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]

        filtered = []
        suppressed = 0
        for finding, prob in zip(findings, tp_probs):
            finding.ml_is_true_positive = float(prob)
            if prob >= self.threshold:
                filtered.append(finding)
            else:
                suppressed += 1
                logger.debug(f"FP suppressed: {finding.vuln_type.value} at {finding.url} "
                             f"(TP prob: {prob:.2f})")

        logger.info(f"ML FP filter: {suppressed} findings suppressed, "
                    f"{len(filtered)} retained (threshold: {self.threshold})")
        return filtered

    def _heuristic_filter(self, findings: List[Finding]) -> List[Finding]:
        """Use heuristic rules to filter false positives (fallback)."""
        filtered = []
        suppressed = 0

        for finding in findings:
            is_fp = False
            for rule in FP_HEURISTIC_RULES:
                try:
                    if rule["condition"](finding):
                        is_fp = True
                        logger.debug(f"Heuristic FP: {finding.vuln_type.value} at {finding.url} — "
                                     f"{rule['reason']}")
                        break
                except Exception:
                    continue

            if is_fp:
                finding.ml_is_true_positive = 0.3
                suppressed += 1
            else:
                finding.ml_is_true_positive = 0.8
                filtered.append(finding)

        logger.info(f"Heuristic FP filter: {suppressed} findings suppressed, "
                    f"{len(filtered)} retained")
        return filtered

    def train(self, findings: List[Finding], labels: List[int]):
        """
        Train the false-positive filter model.
        Labels: 1 = true positive, 0 = false positive
        """
        from sklearn.ensemble import RandomForestClassifier
        import joblib

        features = self.feature_extractor.extract_batch(findings)
        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=8)
        model.fit(features, labels)

        os.makedirs(MLConfig.MODEL_DIR, exist_ok=True)
        model_path = os.path.join(MLConfig.MODEL_DIR, "fp_filter_model.pkl")
        joblib.dump(model, model_path)
        self.model = model
        logger.info(f"FP filter model trained and saved to {model_path}")
