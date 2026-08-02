"""
Configuration module for the Automated Web Security Scanner.
Centralises all configurable parameters.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# === Scanner Configuration ===
class ScannerConfig:
    # Crawler settings
    MAX_DEPTH = 5                    # Maximum crawl depth
    MAX_PAGES = 100                  # Maximum pages to crawl
    REQUEST_DELAY = 0.5              # Seconds between requests (rate limiting)
    REQUEST_TIMEOUT = 10             # Seconds before request timeout
    USER_AGENT = "WebSecScanner/1.0 (Academic Research Project)"
    
    # Fuzzer settings
    MAX_PAYLOADS_PER_PARAM = 100      # Limit payloads per parameter
    FOLLOW_REDIRECTS = True
    
    # Detection thresholds
    CONFIDENCE_THRESHOLD = 0.5       # Minimum confidence to report a finding
    RESPONSE_SIZE_ANOMALY_RATIO = 2.0  # Flag if response is 2x normal size
    
    # Rate limiting
    MAX_CONCURRENT_REQUESTS = 5
    
    # Scan scope
    SCAN_EXTERNAL_LINKS = False      # Stay within target domain


# === Flask / Web UI Configuration ===
class WebConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = "sqlite:///scan_history.db"
    DEBUG = True
    HOST = "127.0.0.1"
    PORT = 5000


# === ML Pipeline Configuration ===
class MLConfig:
    ENABLE_ML = True                  # Master toggle for ML pipelines
    FP_FILTER_THRESHOLD = 0.5         # Probability threshold for false positive filter
    MODEL_DIR = os.path.join(os.path.dirname(__file__), "ml", "models")
    TRAINING_DATA_DIR = os.path.join(os.path.dirname(__file__), "ml", "training_data")


# === Virus Scanner Configuration ===
class VirusScanConfig:
    ENABLE_VIRUS_SCAN = True
    # Known malicious patterns / signatures
    MALICIOUS_JS_PATTERNS = [
        r'eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)',
        r'document\.write\s*\(\s*(?:unescape|decodeURIComponent)',
        r'<iframe[^>]+(?:style\s*=\s*["\']?\s*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0))',
        r'<script[^>]*src\s*=\s*["\'](?:https?:)?//(?!(?:cdn\.|ajax\.|code\.))',
        r'window\.location\s*=\s*["\'](?:https?:)?//',
        r'document\.cookie',
        r'\.exe["\'\s>]',
        r'powershell|cmd\.exe|/bin/(?:sh|bash)',
    ]
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta',
        '.scr', '.pif', '.com', '.msi', '.dll', '.jar',
    ]
    MAX_FILE_SIZE_MB = 50             # Max file size to scan
    YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "scanner", "yara_rules")


# === VirusTotal API Configuration ===
class VirusTotalConfig:
    API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
    ENABLED = True
    RATE_LIMIT_PER_MINUTE = 4
    CACHE_RESULTS = True


# === Report Configuration ===
class ReportConfig:
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "reports")
    INCLUDE_EVIDENCE = True
    MAX_EVIDENCE_LENGTH = 500         # Characters of response to include as evidence
