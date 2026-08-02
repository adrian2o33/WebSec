import os
import logging
from typing import List

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from scanner.models import Finding, VulnerabilityType, SeverityLevel
from scanner.file_scanner import FileThreat
from config import VirusScanConfig

logger = logging.getLogger(__name__)

class YaraScanner:

    def __init__(self, rules_dir=None):
        self.rules_dir = rules_dir or VirusScanConfig.YARA_RULES_DIR
        self.web_rules = None
        self.file_rules = None
        self._load_rules()

    def _load_rules(self):
        if not YARA_AVAILABLE:
            logger.warning("yara-python is not installed. YARA scanning will be disabled.")
            return

        if not os.path.isdir(self.rules_dir):
            logger.warning(f"YARA rules directory {self.rules_dir} not found.")
            return

        web_rules_path = os.path.join(self.rules_dir, "malware_web.yar")
        file_rules_path = os.path.join(self.rules_dir, "malware_file.yar")

        try:
            if os.path.isfile(web_rules_path):
                self.web_rules = yara.compile(filepath=web_rules_path)
                logger.info("Loaded YARA web rules.")
            else:
                logger.warning(f"YARA web rules file {web_rules_path} not found.")
        except yara.Error as e:
            logger.error(f"Error compiling YARA web rules: {e}")

        try:
            if os.path.isfile(file_rules_path):
                self.file_rules = yara.compile(filepath=file_rules_path)
                logger.info("Loaded YARA file rules.")
            else:
                logger.warning(f"YARA file rules file {file_rules_path} not found.")
        except yara.Error as e:
            logger.error(f"Error compiling YARA file rules: {e}")

    def _map_severity(self, sev_str: str) -> SeverityLevel:
        sev_str = sev_str.upper()
        if sev_str == "CRITICAL":
            return SeverityLevel.CRITICAL
        elif sev_str == "HIGH":
            return SeverityLevel.HIGH
        elif sev_str == "MEDIUM":
            return SeverityLevel.MEDIUM
        elif sev_str == "LOW":
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def scan_content(self, content: str, source_url: str = "") -> List[Finding]:
        """Scan string content (e.g. web page HTML/JS) against web rules."""
        findings = []
        if not self.web_rules or not content:
            return findings

        try:
            matches = self.web_rules.match(data=content)
            for match in matches:
                meta = match.meta
                severity_str = meta.get("severity", "Medium")
                severity = self._map_severity(severity_str)
                description = meta.get("description", f"YARA rule {match.rule} matched.")
                confidence = float(meta.get("confidence", 0.5))
                vuln_type_str = meta.get("vuln_type", "Malware")
                
                finding = Finding(
                    url=source_url,
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.MALWARE_INFECTION if vuln_type_str == "Malware" else VulnerabilityType.UNKNOWN,
                    severity=severity,
                    evidence=f"Matched YARA rule: {match.rule}",
                    confidence=confidence,
                    description=description,
                    recommendation="Review the content for malicious code and remove it."
                )
                findings.append(finding)
        except Exception as e:
            logger.error(f"Error during YARA web scan: {e}")

        return findings

    def scan_file_content(self, content: bytes, filename: str = "") -> List[FileThreat]:
        """Scan raw bytes against file rules."""
        threats = []
        if not self.file_rules or not content:
            return threats

        try:
            matches = self.file_rules.match(data=content)
            for match in matches:
                meta = match.meta
                category = meta.get("category", "Malicious File")
                description = meta.get("description", f"YARA rule {match.rule} matched.")
                severity_str = meta.get("severity", "Medium")
                confidence = float(meta.get("confidence", 0.5))
                
                threat = FileThreat(
                    category=category,
                    description=description,
                    severity=severity_str.capitalize(),
                    evidence=f"Matched YARA rule: {match.rule}",
                    confidence=confidence
                )
                threats.append(threat)
        except Exception as e:
            logger.error(f"Error during YARA file scan: {e}")

        return threats
