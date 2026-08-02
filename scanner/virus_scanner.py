"""
Web Malware / Virus Scanner Module
Scans web pages for malicious scripts, suspicious iframes, crypto miners,
phishing indicators, obfuscated code, and malware download links.
"""
import re
import logging
import hashlib
from typing import List, Optional
from urllib.parse import urlparse

from scanner.models import Finding, VulnerabilityType, SeverityLevel, CrawlResult
from scanner.yara_scanner import YaraScanner
from scanner.virustotal import VirusTotalClient
from config import VirusScanConfig, VirusTotalConfig

logger = logging.getLogger(__name__)

# Known malicious script patterns
MALICIOUS_PATTERNS = [
    # Obfuscated JavaScript execution
    {
        "pattern": r'eval\s*\(\s*(?:atob|unescape|String\.fromCharCode|decodeURIComponent)\s*\(',
        "type": VulnerabilityType.OBFUSCATED_CODE,
        "severity": SeverityLevel.HIGH,
        "description": "Obfuscated JavaScript using eval() with encoding functions. "
                       "This is a common technique to hide malicious code.",
        "recommendation": "Review the decoded content of the eval() call. Remove if malicious.",
    },
    {
        "pattern": r'document\.write\s*\(\s*(?:unescape|decodeURIComponent)\s*\(',
        "type": VulnerabilityType.OBFUSCATED_CODE,
        "severity": SeverityLevel.HIGH,
        "description": "document.write() with encoded content, often used to inject hidden content.",
        "recommendation": "Inspect the decoded output. Replace document.write with safe DOM methods.",
    },
    # Suspicious iframes
    {
        "pattern": r'<iframe[^>]+(?:style\s*=\s*["\']?\s*(?:display\s*:\s*none|visibility\s*:\s*hidden|'
                   r'width\s*:\s*0|height\s*:\s*0|position\s*:\s*absolute\s*;\s*(?:left|top)\s*:\s*-\d+))',
        "type": VulnerabilityType.SUSPICIOUS_IFRAME,
        "severity": SeverityLevel.HIGH,
        "description": "Hidden iframe detected. Attackers use invisible iframes to load "
                       "malicious content from external sites without the user's knowledge.",
        "recommendation": "Remove any unrecognised hidden iframes. Implement CSP frame-ancestors directive.",
    },
    {
        "pattern": r'<iframe[^>]+src\s*=\s*["\'](?:https?:)?//(?!(?:www\.youtube\.com|'
                   r'player\.vimeo\.com|maps\.google\.com|www\.google\.com/maps))[^"\']+["\'][^>]*'
                   r'(?:width\s*=\s*["\']?[01]["\']?|height\s*=\s*["\']?[01]["\']?)',
        "type": VulnerabilityType.SUSPICIOUS_IFRAME,
        "severity": SeverityLevel.MEDIUM,
        "description": "Small or zero-size iframe loading external content.",
        "recommendation": "Verify the iframe source is legitimate. Remove if suspicious.",
    },
    # Malicious redirects
    {
        "pattern": r'(?:window\.location|document\.location|location\.href)\s*=\s*["\']'
                   r'(?:https?:)?//[^"\']+["\']',
        "type": VulnerabilityType.MALICIOUS_REDIRECT,
        "severity": SeverityLevel.MEDIUM,
        "description": "JavaScript-based redirect to external URL detected.",
        "recommendation": "Verify the redirect destination is legitimate. Use server-side redirects instead.",
    },
    {
        "pattern": r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+url\s*=\s*(?:https?:)?//[^"\'>\s]+',
        "type": VulnerabilityType.MALICIOUS_REDIRECT,
        "severity": SeverityLevel.MEDIUM,
        "description": "Meta refresh redirect to external URL.",
        "recommendation": "Verify the redirect target. Use HTTP 301/302 redirects for legitimate redirections.",
    },
    # Cryptocurrency miners
    {
        "pattern": r'(?:coinhive|cryptoloot|deepminer|coin-hive|jsecoin|cryptonight|'
                   r'minero\.cc|webminerpool|miner\.start|CryptoNoter)',
        "type": VulnerabilityType.CRYPTO_MINER,
        "severity": SeverityLevel.CRITICAL,
        "description": "Cryptocurrency mining script detected. This uses visitors' CPU to mine crypto.",
        "recommendation": "Remove the mining script immediately. This is considered malware.",
    },
    {
        "pattern": r'(?:WebAssembly|wasm).*?(?:mine|hash|crypto)',
        "type": VulnerabilityType.CRYPTO_MINER,
        "severity": SeverityLevel.HIGH,
        "description": "Potential WebAssembly-based cryptocurrency miner.",
        "recommendation": "Investigate the WebAssembly module purpose. Remove if crypto mining.",
    },
    # Cookie/credential theft
    {
        "pattern": r'(?:new\s+Image\(\)|document\.createElement\s*\(\s*["\']img["\']\s*\))'
                   r'[^;]*\.src\s*=.*?document\.cookie',
        "type": VulnerabilityType.MALICIOUS_SCRIPT,
        "severity": SeverityLevel.CRITICAL,
        "description": "Cookie exfiltration via image beacon detected.",
        "recommendation": "Remove the malicious script. Set HttpOnly flag on sensitive cookies.",
    },
    {
        "pattern": r'(?:XMLHttpRequest|fetch)\s*[\(.].*?document\.cookie',
        "type": VulnerabilityType.MALICIOUS_SCRIPT,
        "severity": SeverityLevel.CRITICAL,
        "description": "Cookie exfiltration via AJAX request detected.",
        "recommendation": "Remove the malicious script. Set HttpOnly flag on all session cookies.",
    },
    # Keyloggers
    {
        "pattern": r'(?:addEventListener|attachEvent)\s*\(\s*["\']key(?:press|down|up)["\']'
                   r'[^)]*\)\s*[^;]*(?:XMLHttpRequest|fetch|new\s+Image|\.src\s*=)',
        "type": VulnerabilityType.MALICIOUS_SCRIPT,
        "severity": SeverityLevel.CRITICAL,
        "description": "Potential keylogger detected — keystroke events being sent to a remote server.",
        "recommendation": "Remove the malicious script immediately. Audit all JavaScript files.",
    },
    # Phishing indicators
    {
        "pattern": r'<form[^>]+action\s*=\s*["\'](?:https?:)?//(?!(?:.*?'
                   r'\.paypal\.com|.*?\.google\.com|.*?\.microsoft\.com))[^"\']+["\']'
                   r'[^>]*>[\s\S]*?(?:password|passwd|card|cvv|ssn|social)',
        "type": VulnerabilityType.PHISHING_INDICATOR,
        "severity": SeverityLevel.CRITICAL,
        "description": "Form collecting sensitive data (passwords, cards) submitting to external domain.",
        "recommendation": "Verify the form action URL is the legitimate domain. This may be a phishing page.",
    },
    # Malware download links
    {
        "pattern": r'<a[^>]+href\s*=\s*["\'][^"\']*\.(?:exe|bat|cmd|ps1|vbs|scr|pif|msi|dll|hta)'
                   r'(?:\?[^"\']*)?["\']',
        "type": VulnerabilityType.MALWARE_DOWNLOAD,
        "severity": SeverityLevel.HIGH,
        "description": "Link to potentially dangerous executable file detected.",
        "recommendation": "Verify the download is legitimate. Scan the file with antivirus software.",
    },
    # Base64-encoded script blocks (often used to hide malicious payloads)
    {
        "pattern": r'<script[^>]*>[\s\S]*?(?:atob|btoa)\s*\(\s*["\'][A-Za-z0-9+/=]{50,}["\']',
        "type": VulnerabilityType.OBFUSCATED_CODE,
        "severity": SeverityLevel.MEDIUM,
        "description": "Large Base64-encoded string in script block, possibly hiding malicious code.",
        "recommendation": "Decode and review the Base64 content. Remove if malicious.",
    },
    # Shell command execution in JavaScript
    {
        "pattern": r'(?:require\s*\(\s*["\']child_process["\']|exec\s*\(\s*["\'](?:cmd|bash|sh|powershell))',
        "type": VulnerabilityType.MALICIOUS_SCRIPT,
        "severity": SeverityLevel.CRITICAL,
        "description": "Server-side code executing shell commands detected in client-facing response.",
        "recommendation": "Remove command execution code from client responses. Review server code.",
    },
]

# Known malicious domains (small sample for demonstration)
KNOWN_MALICIOUS_DOMAINS = [
    "evil.com", "malware-distribution.net", "phishing-site.com",
    "coinhive.com", "cryptoloot.pro", "minero.cc",
    "jsecoin.com", "webminerpool.com",
]


class VirusScanner:
    """
    Scans web pages for malware, malicious scripts, phishing indicators,
    crypto miners, and other threats.
    """

    def __init__(self, enable_vt: bool = True):
        self._compiled_patterns = []
        for entry in MALICIOUS_PATTERNS:
            try:
                compiled = re.compile(entry["pattern"], re.IGNORECASE | re.DOTALL)
                self._compiled_patterns.append({
                    "regex": compiled,
                    "type": entry["type"],
                    "severity": entry["severity"],
                    "description": entry["description"],
                    "recommendation": entry["recommendation"],
                })
            except re.error as e:
                logger.error(f"Failed to compile regex pattern: {e}")

        self.yara_scanner = YaraScanner()
        self.vt_client = VirusTotalClient(VirusTotalConfig.API_KEY) if (enable_vt and VirusTotalConfig.ENABLED) else None

    def analyse(self, crawl_results: List[CrawlResult]) -> List[Finding]:
        """Scan all crawled pages for malware indicators."""
        findings = []

        # VirusTotal Domain Reputation Check
        if crawl_results and self.vt_client:
            try:
                target_domain = urlparse(crawl_results[0].url).netloc
                vt_res = self.vt_client.check_domain(target_domain)
                if vt_res and vt_res.get('malicious'):
                    findings.append(Finding(
                        url=f"https://{target_domain}",
                        parameter="",
                        payload="",
                        vuln_type=VulnerabilityType.MALWARE_INFECTION if hasattr(VulnerabilityType, 'MALWARE_INFECTION') else VulnerabilityType.MALICIOUS_SCRIPT,
                        severity=SeverityLevel.CRITICAL,
                        evidence=f"Domain {target_domain} flagged as malicious by VirusTotal. Reputation: {vt_res.get('reputation', 0)}",
                        confidence=0.9,
                        description=f"The domain {target_domain} is flagged as malicious by VirusTotal.",
                        recommendation="Investigate the domain reputation immediately."
                    ))
            except Exception as e:
                logger.error(f"VirusTotal domain check failed: {e}")

        for result in crawl_results:
            if result.response_body:
                findings.extend(self._scan_page(result))
        
        # Deduplicate by (url, vuln_type) to avoid flooding
        seen = set()
        unique = []
        for f in findings:
            key = (f.url, f.vuln_type.value, f.evidence[:100])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        return unique

    def _scan_page(self, result: CrawlResult) -> List[Finding]:
        """Scan a single page for malware patterns."""
        findings = []
        body = result.response_body

        # Pattern-based scanning
        for entry in self._compiled_patterns:
            match = entry["regex"].search(body)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(body), match.end() + 30)
                evidence_snippet = body[start:end].replace("\n", " ").strip()

                findings.append(Finding(
                    url=result.url,
                    parameter="",
                    payload="",
                    vuln_type=entry["type"],
                    severity=entry["severity"],
                    evidence=f"Pattern match: ...{evidence_snippet[:400]}...",
                    confidence=0.75,
                    description=entry["description"],
                    recommendation=entry["recommendation"],
                ))

        # Check for external script loading from suspicious domains
        findings.extend(self._check_external_scripts(result))

        # Check for data exfiltration patterns
        findings.extend(self._check_data_exfiltration(result))

        # Check inline script entropy (high entropy = likely obfuscated)
        findings.extend(self._check_script_entropy(result))

        # YARA web content scan
        try:
            yara_findings = self.yara_scanner.scan_content(body, result.url)
            findings.extend(yara_findings)
        except Exception as e:
            logger.error(f"YARA scan failed for {result.url}: {e}")

        return findings

    def _check_external_scripts(self, result: CrawlResult) -> List[Finding]:
        """Check for scripts loaded from known malicious or suspicious domains."""
        findings = []
        if not result.response_body:
            return findings

        script_srcs = re.findall(
            r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
            result.response_body, re.IGNORECASE
        )

        target_domain = urlparse(result.url).netloc
        for src in script_srcs:
            parsed = urlparse(src)
            if parsed.netloc and parsed.netloc != target_domain:
                # Check against known malicious domains
                for mal_domain in KNOWN_MALICIOUS_DOMAINS:
                    if mal_domain in parsed.netloc:
                        findings.append(Finding(
                            url=result.url,
                            parameter="",
                            payload=src,
                            vuln_type=VulnerabilityType.MALICIOUS_SCRIPT,
                            severity=SeverityLevel.CRITICAL,
                            evidence=f"Script loaded from known malicious domain: {src}",
                            confidence=0.95,
                            description="External script loaded from a known malicious domain.",
                            recommendation="Remove the malicious script reference immediately.",
                        ))
                        break

        return findings

    def _check_data_exfiltration(self, result: CrawlResult) -> List[Finding]:
        """Check for patterns that suggest data theft."""
        findings = []
        body = result.response_body
        if not body:
            return findings

        # Check for sending data to external URLs via various methods
        exfil_patterns = [
            (r'new\s+WebSocket\s*\(\s*["\']wss?://[^"\']+["\']', "WebSocket to external server"),
            (r'navigator\.sendBeacon\s*\(\s*["\']https?://[^"\']+["\']', "Beacon API data exfiltration"),
            (r'(?:localStorage|sessionStorage)\.getItem.*?(?:fetch|XMLHttpRequest|Image)',
             "Local storage data being sent externally"),
        ]

        for pattern, desc in exfil_patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE | re.DOTALL):
                context = body[max(0, match.start() - 50):match.end() + 150]
                
                # Exclude trusted analytics and tracking scripts (common false positives)
                context_lower = context.lower()
                trusted_keywords = [
                    'gtag', 'googleanalytics', 'google-analytics.com', 'googletagmanager',
                    'clarity', 'microsoft.com', 'bing.com',
                    'fbq', 'facebook.net/en_us/fbevents.js', 'facebook.com/tr',
                    'hotjar', 'hotjar.com',
                    'segment.com', 'analytics.js',
                    'mixpanel', 'amplitude',
                    'tiktok.com', 'ttq',
                    'sentry.io', 'datadoghq', 'newrelic',
                    'matomo', 'piwik',
                    'hubspot', 'intercom'
                ]
                if any(x in context_lower for x in trusted_keywords):
                    continue

                findings.append(Finding(
                    url=result.url,
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.MALICIOUS_SCRIPT,
                    severity=SeverityLevel.HIGH,
                    evidence=f"{desc}: ...{context[:300]}...",
                    confidence=0.65,
                    description=f"Potential data exfiltration detected: {desc}",
                    recommendation="Review the script. Ensure data is only sent to trusted endpoints.",
                ))
                break # Only report once per pattern per page to avoid flooding

        return findings

    def _check_script_entropy(self, result: CrawlResult) -> List[Finding]:
        """Check for highly obfuscated inline scripts (high character entropy)."""
        findings = []
        body = result.response_body
        if not body:
            return findings

        # Extract inline scripts
        scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', body, re.IGNORECASE)
        for script in scripts:
            script = script.strip()
            if len(script) < 200:
                continue

            # Calculate character entropy
            entropy = self._calculate_entropy(script)
            # Normal JS typically has entropy 4-5; obfuscated code often >5.5
            if entropy > 5.5 and len(script) > 500:
                findings.append(Finding(
                    url=result.url,
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.OBFUSCATED_CODE,
                    severity=SeverityLevel.MEDIUM,
                    evidence=f"High entropy inline script (entropy={entropy:.2f}, "
                             f"length={len(script)}): {script[:150]}...",
                    confidence=0.55,
                    description="Inline script with unusually high character entropy detected. "
                                "This may indicate obfuscated malicious code.",
                    recommendation="Review the script content. Deobfuscate if needed to verify intent.",
                ))

        return findings

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
