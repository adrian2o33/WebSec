"""
Data models for the Automated Web Security Scanner.
Defines the core data structures used across all modules.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any


class SeverityLevel(Enum):
    """Severity classification for findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    def __lt__(self, other):
        order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
        return order.index(self) < order.index(other)


class VulnerabilityType(Enum):
    """Types of vulnerabilities the scanner can detect."""
    # Injection vulnerabilities
    XSS_REFLECTED = "Reflected XSS"
    XSS_STORED = "Stored XSS"
    SQL_INJECTION = "SQL Injection"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    OPEN_REDIRECT = "Open Redirect"
    DIRECTORY_LISTING = "Directory Listing"
    XXE_INJECTION = "XML External Entity (XXE) Injection"
    INVALID_INPUT = "Invalid Input / Fuzzing Exception"
    BROKEN_ACCESS_CONTROL = "Broken Access Control (IDOR)"
    MISSING_RATE_LIMIT = "Missing Rate Limiting"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    
    # Configuration vulnerabilities
    MISSING_HTTPS = "Missing HTTPS"
    INSECURE_CERTIFICATE = "Insecure Certificate"
    MISSING_SECURITY_HEADER = "Missing Security Header"
    INSECURE_COOKIE = "Insecure Cookie"
    
    # Malware / Virus findings
    MALICIOUS_SCRIPT = "Malicious Script Detected"
    SUSPICIOUS_IFRAME = "Suspicious Iframe"
    MALICIOUS_REDIRECT = "Malicious Redirect"
    MALWARE_DOWNLOAD = "Malware Download Link"
    OBFUSCATED_CODE = "Obfuscated Malicious Code"
    CRYPTO_MINER = "Cryptocurrency Miner"
    PHISHING_INDICATOR = "Phishing Indicator"
    EXPOSED_SUBDOMAIN = "Exposed Subdomain"
    
    # General
    INFORMATION_DISCLOSURE = "Information Disclosure"
    MALWARE_INFECTION = "Malware Infection"
    UNKNOWN = "Unknown"
    OTHER = "Other"


class ScanStatus(Enum):
    """Status of a scan operation."""
    PENDING = "Pending"
    RECONNAISSANCE = "Reconnaissance"
    CRAWLING = "Crawling"
    FUZZING = "Fuzzing"
    VIRUS_SCANNING = "Virus Scanning"
    ML_PROCESSING = "ML Processing"
    REPORTING = "Generating Report"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


@dataclass
class FormField:
    """Represents an HTML form field."""
    name: str
    field_type: str          # text, password, hidden, etc.
    value: str = ""          # Default value if any


@dataclass
class FormData:
    """Represents an HTML form found during crawling."""
    action: str              # Form action URL
    method: str              # GET or POST
    fields: List[FormField] = field(default_factory=list)
    page_url: str = ""       # The page this form was found on


@dataclass
class CrawlResult:
    """Result of crawling a single page."""
    url: str
    status_code: int
    content_type: str = ""
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    links: List[str] = field(default_factory=list)
    forms: List[FormData] = field(default_factory=list)
    cookies: Dict[str, Any] = field(default_factory=dict)
    is_https: bool = False
    error: Optional[str] = None


@dataclass
class Finding:
    """A single security finding (vulnerability or malware detection)."""
    url: str
    parameter: str
    payload: str
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    evidence: str
    confidence: float = 0.8
    description: str = ""
    recommendation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ml_severity: Optional[SeverityLevel] = None    # ML-predicted severity
    ml_is_true_positive: Optional[float] = None     # ML-predicted TP probability
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat(),
            "ml_severity": self.ml_severity.value if self.ml_severity else None,
            "ml_is_true_positive": self.ml_is_true_positive,
        }


@dataclass
class ScanProgress:
    """Tracks the progress of an ongoing scan."""
    total_urls: int = 0
    crawled_urls: int = 0
    total_forms: int = 0
    tested_forms: int = 0
    total_payloads_sent: int = 0
    findings_count: int = 0
    current_url: str = ""
    current_action: str = ""
    status: ScanStatus = ScanStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)
    latest_findings: List[Dict[str, Any]] = field(default_factory=list)
    _progress_percent: float = 0.0
    
    @property
    def progress_percent(self) -> float:
        return self._progress_percent
    
    @progress_percent.setter
    def progress_percent(self, value: float):
        self._progress_percent = min(max(value, 0.0), 100.0)
    
    @property
    def elapsed_seconds(self) -> float:
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert progress to dictionary for serialization."""
        return {
            "status": self.status.value if hasattr(self.status, 'value') else self.status,
            "current_action": self.current_action,
            "crawled_urls": self.crawled_urls,
            "total_urls": self.total_urls,
            "tested_forms": self.tested_forms,
            "total_forms": self.total_forms,
            "total_payloads_sent": self.total_payloads_sent,
            "findings_count": self.findings_count,
            "progress_percent": self.progress_percent,
            "elapsed_seconds": self.elapsed_seconds,
            "errors": self.errors[-5:] if self.errors else [],
            "latest_findings": self.latest_findings,
            "completed": self.status.value == "Completed" if hasattr(self.status, 'value') else self.status == "Completed"
        }


@dataclass
class ScanResult:
    """Complete result of a scan operation."""
    scan_id: str
    target_url: str
    findings: List[Finding] = field(default_factory=list)
    progress: ScanProgress = field(default_factory=ScanProgress)
    pages_crawled: int = 0
    forms_found: int = 0
    total_requests: int = 0
    scan_duration_seconds: float = 0.0
    scanner_version: str = "1.0.0"
    ml_enabled: bool = False
    virus_scan_enabled: bool = True
    
    @property
    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Group findings by severity level."""
        grouped = {}
        for f in self.findings:
            sev = f.severity.value
            if sev not in grouped:
                grouped[sev] = []
            grouped[sev].append(f)
        return grouped
    
    @property
    def findings_by_type(self) -> Dict[str, List[Finding]]:
        """Group findings by vulnerability type."""
        grouped = {}
        for f in self.findings:
            vtype = f.vuln_type.value
            if vtype not in grouped:
                grouped[vtype] = []
            grouped[vtype].append(f)
        return grouped
    
    @property
    def severity_summary(self) -> Dict[str, int]:
        """Count findings per severity level."""
        summary = {level.value: 0 for level in SeverityLevel}
        for f in self.findings:
            summary[f.severity.value] += 1
        return summary
    
    @property
    def security_score(self) -> int:
        """Calculate a 0-100 security score based on real-world impact."""
        score = 100
        
        # Specific deductions for real-world risk
        for f in self.findings:
            v_type = f.vuln_type.value
            if v_type in [VulnerabilityType.SQL_INJECTION.value, VulnerabilityType.COMMAND_INJECTION.value, VulnerabilityType.MALWARE_INFECTION.value]:
                score -= 50
            elif v_type in [VulnerabilityType.XSS_STORED.value, VulnerabilityType.CRYPTO_MINER.value]:
                score -= 40
            elif v_type in [VulnerabilityType.XSS_REFLECTED.value, VulnerabilityType.PATH_TRAVERSAL.value, VulnerabilityType.MALICIOUS_SCRIPT.value, VulnerabilityType.PHISHING_INDICATOR.value]:
                score -= 30
            elif v_type == VulnerabilityType.OPEN_REDIRECT.value:
                score -= 15
            elif v_type in [VulnerabilityType.DIRECTORY_LISTING.value, VulnerabilityType.INFORMATION_DISCLOSURE.value]:
                score -= 10
            elif v_type == VulnerabilityType.MISSING_SECURITY_HEADER.value:
                # Differentiate between headers
                if 'Content-Security-Policy' in f.evidence:
                    score -= 10
                elif 'Strict-Transport-Security' in f.evidence:
                    score -= 5 # Highly situational, minimal point deduction
                else:
                    score -= 2 # Minor headers like X-Content-Type-Options
            elif v_type == VulnerabilityType.INSECURE_COOKIE.value:
                score -= 5
            else:
                # Fallback based on severity
                if f.severity == SeverityLevel.CRITICAL: score -= 40
                elif f.severity == SeverityLevel.HIGH: score -= 20
                elif f.severity == SeverityLevel.MEDIUM: score -= 10
                elif f.severity == SeverityLevel.LOW: score -= 2
                
        return max(0, score)

    @property
    def security_grade(self) -> str:
        """Calculate overall security grade (A+ to F) based on complex score."""
        score = self.security_score
        if score >= 95: return "A+"
        if score >= 90: return "A-"
        if score >= 80: return "B+"
        if score >= 70: return "B"
        if score >= 60: return "C"
        if score >= 50: return "D"
        return "F"

    @property
    def bottom_line(self) -> str:
        """Provide a human-readable bottom line summary based on score."""
        grade = self.security_grade
        if grade == "F":
            return "CRITICAL RISK: The site has severe vulnerabilities (like SQLi or Stored XSS) that can be immediately exploited. Do not use this site for sensitive data until fixed."
        elif grade == "D":
            return "HIGH RISK: The site has major security flaws. It is vulnerable to significant attacks and data breaches."
        elif grade == "C":
            return "MODERATE RISK: The site lacks important security controls (like CSP or secure cookies) or has multiple moderate issues. It is vulnerable to common web attacks."
        elif grade in ["B+", "B"]:
            return "GENERALLY SAFE: The site has good overall security but is missing some best practices or contains lower-impact vulnerabilities. Safe for general use."
        else:
            return "EXCELLENT: The site follows strict security practices and has no detectable vulnerabilities."

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "findings": [f.to_dict() for f in self.findings],
            "pages_crawled": self.pages_crawled,
            "forms_found": self.forms_found,
            "total_requests": self.total_requests,
            "scan_duration_seconds": self.scan_duration_seconds,
            "scanner_version": self.scanner_version,
            "ml_enabled": self.ml_enabled,
            "virus_scan_enabled": self.virus_scan_enabled,
            "severity_summary": self.severity_summary,
            "security_grade": self.security_grade,
            "bottom_line": self.bottom_line,
        }
