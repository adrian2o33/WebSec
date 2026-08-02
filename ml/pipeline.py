"""
ML Pipeline Integration
Combines false-positive filtering and vulnerability prioritisation
into a single post-scan processing pipeline.
"""
import logging
from typing import List

from scanner.models import Finding
from ml.fp_filter import FalsePositiveFilter
from ml.prioritiser import Prioritiser

logger = logging.getLogger(__name__)


class MLPipeline:
    """
    Combined ML post-processing pipeline.
    1. Filter false positives (Pipeline 2)
    2. Classify and prioritise remaining findings (Pipeline 1)
    """

    def __init__(self):
        self.fp_filter = FalsePositiveFilter()
        self.prioritiser = Prioritiser()

    def process(self, findings: List[Finding]) -> List[Finding]:
        """
        Run the full ML pipeline on scan findings.
        Returns filtered and prioritised findings.
        """
        if not findings:
            return findings

        original_count = len(findings)
        logger.info(f"ML Pipeline: Processing {original_count} findings...")

        # Step 1: False positive suppression
        findings = self.fp_filter.filter(findings)
        after_fp = len(findings)
        logger.info(f"  After FP filter: {after_fp} findings ({original_count - after_fp} removed)")

        # Step 2: Classification and prioritisation
        findings = self.prioritiser.prioritise(findings)
        logger.info(f"  After prioritisation: {len(findings)} findings sorted by risk")

        return findings
