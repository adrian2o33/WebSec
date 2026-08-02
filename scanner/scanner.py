"""
Scanner Orchestrator
Coordinates crawling, fuzzing, detection, virus scanning, and ML post-processing
into a unified scan pipeline.
"""
import logging
import time
import uuid
from datetime import datetime
from typing import List, Optional, Callable

import requests
import urllib3
from urllib.parse import urlparse, parse_qs

from scanner.crawler import Crawler
from scanner.fuzzer import Fuzzer
from scanner.models import (
    Finding, ScanResult, ScanProgress, ScanStatus,
    CrawlResult, SeverityLevel, VulnerabilityType
)
from scanner.detectors.xss_detector import XSSDetector
from scanner.detectors.sqli_detector import SQLiDetector
from scanner.detectors.path_traversal_detector import PathTraversalDetector
from scanner.detectors.https_checker import HTTPSChecker
from scanner.detectors.header_checker import HeaderChecker
from scanner.detectors.cookie_checker import CookieChecker
from scanner.detectors.open_redirect_detector import OpenRedirectDetector
from scanner.detectors.idor_detector import IDORDetector
from scanner.detectors.rate_limit_detector import RateLimitDetector
from scanner.detectors.directory_listing_detector import DirectoryListingDetector
from scanner.detectors.xxe_detector import XXEDetector
from scanner.detectors.input_validator import InputValidationDetector
from scanner.detectors.command_injection_detector import CommandInjectionDetector
from scanner.detectors.cors_detector import CORSDetector
from scanner.detectors.csrf_detector import CSRFDetector
from scanner.detectors.ssrf_detector import SSRFDetector
from scanner.virus_scanner import VirusScanner
from scanner.dom_verifier import DOMVerifier
from scanner.subdomain_enumerator import SubdomainEnumerator
from config import ScannerConfig, MLConfig, VirusScanConfig

# Suppress SSL warnings for scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class Scanner:
    """
    Main scanner orchestrator that coordinates all scanning phases:
    1. Crawling — discover pages and forms
    2. Fuzzing — inject payloads into inputs
    3. Detection — analyse responses for vulnerabilities
    4. Virus Scan — check pages for malware
    5. ML Post-Processing — classify, prioritise, filter false positives
    6. Reporting — generate findings report
    """

    def __init__(self, target_url: str, max_depth: int = None, max_pages: int = None,
                 request_delay: float = None, enable_ml: bool = None,
                 enable_virus_scan: bool = None, enable_vt: bool = None,
                 enable_miner_scan: bool = None, enable_subdomain_enum: bool = None,
                 enable_rate_limit: bool = True, auth_cookies: dict = None):
        self.target_url = target_url
        self.scan_id = str(uuid.uuid4())[:8]
        self.max_depth = max_depth or ScannerConfig.MAX_DEPTH
        self.max_pages = max_pages or ScannerConfig.MAX_PAGES
        self.request_delay = request_delay if request_delay is not None else ScannerConfig.REQUEST_DELAY
        self.enable_ml = enable_ml if enable_ml is not None else MLConfig.ENABLE_ML
        self.enable_virus_scan = enable_virus_scan if enable_virus_scan is not None else VirusScanConfig.ENABLE_VIRUS_SCAN
        self.enable_vt = enable_vt if enable_vt is not None else True
        self.enable_miner_scan = enable_miner_scan if enable_miner_scan is not None else False
        self.enable_subdomain_enum = enable_subdomain_enum if enable_subdomain_enum is not None else False
        self.enable_rate_limit = enable_rate_limit
        self.auth_cookies = auth_cookies

        # Progress tracking
        self.progress = ScanProgress()
        self._progress_callback: Optional[Callable] = None

        # Initialise components
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": ScannerConfig.USER_AGENT})
        self.session.verify = False

        self.crawler = Crawler(
            target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
            request_delay=self.request_delay,
            auth_cookies=self.auth_cookies
        )
        self.fuzzer = Fuzzer(
            session=self.session,
            request_delay=self.request_delay,
        )

        # Detectors
        self.xss_detector = XSSDetector()
        self.sqli_detector = SQLiDetector()
        self.path_traversal_detector = PathTraversalDetector()
        self.https_checker = HTTPSChecker()
        self.header_checker = HeaderChecker()
        self.cookie_checker = CookieChecker()
        self.open_redirect_detector = OpenRedirectDetector()
        self.idor_detector = IDORDetector()
        self.rate_limit_detector = RateLimitDetector()
        self.xxe_detector = XXEDetector()
        self.input_validator = InputValidationDetector()
        self.directory_listing_detector = DirectoryListingDetector()
        self.command_injection_detector = CommandInjectionDetector()
        self.cors_detector = CORSDetector()
        self.csrf_detector = CSRFDetector()
        self.ssrf_detector = SSRFDetector()
        self.virus_scanner = VirusScanner(enable_vt=self.enable_vt)
        self.dom_verifier = DOMVerifier()
        self.subdomain_enumerator = SubdomainEnumerator()

    def set_progress_callback(self, callback: Callable):
        """Set a callback function to receive progress updates."""
        self._progress_callback = callback

    def _update_progress(self, **kwargs):
        """Update progress and notify callback."""
        for key, value in kwargs.items():
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)
        if self._progress_callback:
            self._progress_callback(self.progress)

    def scan(self) -> ScanResult:
        """Execute the full scanning pipeline."""
        logger.info(f"=== Starting scan {self.scan_id} on {self.target_url} ===")
        self.progress.start_time = datetime.now()
        all_findings: List[Finding] = []

        result = ScanResult(
            scan_id=self.scan_id,
            target_url=self.target_url,
            ml_enabled=self.enable_ml,
            virus_scan_enabled=self.enable_virus_scan,
        )

        try:
            # === Phase 0: Reconnaissance (0-2%) ===
            if self.enable_subdomain_enum:
                self._update_progress(status=ScanStatus.RECONNAISSANCE, current_action="Enumerating active subdomains...")
                self.progress.progress_percent = 1
                logger.info("Phase 0: Reconnaissance (Subdomain Enumeration)...")
                subdomain_findings = self.subdomain_enumerator.enumerate(self.target_url)
                all_findings.extend(subdomain_findings)
                self.progress.findings_count = len(all_findings)
                self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]

            # === Phase 1: Crawling (2–40%) ===
            self._update_progress(status=ScanStatus.CRAWLING, current_action="Crawling website...")
            self.progress.progress_percent = 2
            logger.info("Phase 1: Crawling...")
            crawl_results = self._run_crawl()
            result.pages_crawled = len(crawl_results)
            result.forms_found = sum(len(r.forms) for r in crawl_results)
            self.progress.progress_percent = 40

            # === Phase 2: Passive checks (40–50%) ===
            self._update_progress(current_action="Checking HTTPS, headers, and cookies...")
            self.progress.progress_percent = 42
            logger.info("Phase 2: Passive security checks...")
            all_findings.extend(self.https_checker.analyse(self.target_url, crawl_results))
            self.progress.progress_percent = 44
            all_findings.extend(self.header_checker.analyse(crawl_results))
            self.progress.progress_percent = 47
            all_findings.extend(self.cookie_checker.analyse(
                self.target_url, session=self.session, crawl_results=crawl_results
            ))
            self.progress.progress_percent = 47
            all_findings.extend(self.directory_listing_detector.analyse(crawl_results))
            self.progress.progress_percent = 48
            all_findings.extend(self.cors_detector.analyse(crawl_results))
            self.progress.progress_percent = 49
            all_findings.extend(self.csrf_detector.analyse(crawl_results, self.auth_cookies))
            self.progress.progress_percent = 50

            # === Phase 3: Fuzzing (50–80%) ===
            self._update_progress(status=ScanStatus.FUZZING, current_action="Fuzzing forms and parameters...")
            logger.info("Phase 3: Fuzzing forms and URL parameters...")
            fuzz_results = self._run_fuzz(crawl_results)
            result.total_requests = len(fuzz_results) + len(crawl_results)
            self.progress.progress_percent = 75

            # === Phase 4: Active vulnerability detection (75–80%) ===
            logger.info("Phase 4: Analysing fuzz results for vulnerabilities...")
            
            xss_findings = self.xss_detector.analyse(fuzz_results)
            if xss_findings:
                logger.info("DOM-verifying XSS findings...")
                xss_findings = self.dom_verifier.verify_findings_sync(xss_findings)
            all_findings.extend(xss_findings)
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            
            self.progress.progress_percent = 77
            
            all_findings.extend(self.sqli_detector.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            self.progress.progress_percent = 78
            
            all_findings.extend(self.path_traversal_detector.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            self.progress.progress_percent = 79
            
            all_findings.extend(self.open_redirect_detector.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            self.progress.progress_percent = 80
            
            all_findings.extend(self.xxe_detector.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            
            all_findings.extend(self.command_injection_detector.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            
            all_findings.extend(self.ssrf_detector.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            
            all_findings.extend(self.input_validator.analyse(fuzz_results))
            self.progress.findings_count = len(all_findings)
            self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            
            # === Phase 4.5: Auth & Rate Limiting ===
            if self.auth_cookies:
                self._update_progress(current_action="Checking for Broken Access Control & IDOR...")
                logger.info("Phase 4.5: Broken Access Control & IDOR verification...")
                crawled_urls = [res.url for res in crawl_results]
                all_findings.extend(self.idor_detector.analyze_urls(crawled_urls, self.auth_cookies))
                self.progress.findings_count = len(all_findings)
                self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            
            if self.enable_rate_limit:
                self._update_progress(current_action="Checking for Missing Rate Limits...")
                logger.info("Phase 4.5: Rate Limit burst testing...")
                
                # Prioritize endpoints with forms (like /login) for rate limit testing
                form_urls = [res.url for res in crawl_results if res.forms]
                other_urls = [res.url for res in crawl_results if not res.forms]
                target_urls = (form_urls + other_urls)[:1] # Limit to 1 to prevent duplicate findings
                
                all_findings.extend(self.rate_limit_detector.analyze_urls(target_urls, burst_size=50))
                self.progress.findings_count = len(all_findings)
                self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]

            # === Phase 5: Virus/Malware scanning (80–90%) ===
            if self.enable_virus_scan:
                self._update_progress(status=ScanStatus.VIRUS_SCANNING,
                                      current_action="Scanning for malware and malicious scripts...")
                self.progress.progress_percent = 82
                logger.info("Phase 5: Virus/malware scanning...")
                all_findings.extend(self.virus_scanner.analyse(crawl_results))
                self.progress.findings_count = len(all_findings)
                self.progress.latest_findings = [f.to_dict() for f in all_findings[-3:]]
            self.progress.progress_percent = 90

            # === Phase 5.5: Dynamic Crypto Miner Verification ===
            if self.enable_miner_scan:
                self._update_progress(status=ScanStatus.VIRUS_SCANNING,
                                      current_action="Dynamic crypto miner verification...")
                logger.info("Phase 5.5: DOM-verifying Cryptocurrency Miner findings...")
                for finding in all_findings:
                    if getattr(finding, "vuln_type", None) == VulnerabilityType.CRYPTO_MINER:
                        url = getattr(finding, "url", "")
                        if url:
                            confirmed, evidence = self.dom_verifier.verify_malware_sync(url)
                            if confirmed:
                                finding.confidence = 1.0
                                finding.evidence += f"\n\n[Dynamic Verification] {evidence}"
                                logger.info(f"  ✓ Confirmed Crypto Miner: {url}")
                            else:
                                finding.confidence = 0.3
                                logger.info(f"  ✗ False Positive Crypto Miner (Filtered out): {url}")

            # === Phase 6: ML Post-Processing (90–95%) ===
            if self.enable_ml and all_findings:
                self._update_progress(status=ScanStatus.ML_PROCESSING,
                                      current_action="Running ML analysis...")
                self.progress.progress_percent = 92
                logger.info("Phase 6: ML post-processing...")
                all_findings = self._run_ml_pipelines(all_findings)
            self.progress.progress_percent = 95

            # === Finalise (95–100%) ===
            # Filter out findings that failed verification (confidence < 0.5)
            all_findings = [f for f in all_findings if getattr(f, 'confidence', 1.0) >= 0.5]
            
            # Sort findings by severity
            severity_order = {
                SeverityLevel.CRITICAL: 0,
                SeverityLevel.HIGH: 1,
                SeverityLevel.MEDIUM: 2,
                SeverityLevel.LOW: 3,
                SeverityLevel.INFO: 4,
            }
            all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -getattr(f, 'confidence', 0)))

            result.findings = all_findings
            self.progress.end_time = datetime.now()
            result.scan_duration_seconds = self.progress.elapsed_seconds
            self.progress.progress_percent = 100

            self._update_progress(
                status=ScanStatus.COMPLETED,
                current_action="Scan complete",
                findings_count=len(all_findings),
            )

            logger.info(f"=== Scan {self.scan_id} complete: {len(all_findings)} findings in "
                        f"{result.scan_duration_seconds:.1f}s ===")

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            self._update_progress(status=ScanStatus.FAILED, current_action=f"Error: {str(e)}")
            self.progress.errors.append(str(e))
            result.findings = all_findings  # Return partial results

        return result

    def _run_crawl(self) -> List[CrawlResult]:
        """Execute the crawling phase."""
        def on_page(result: CrawlResult):
            crawled = len(self.crawler.results)
            total = max(self.progress.total_urls, crawled, 1)
            # Spread crawling across 2–40%
            self.progress.progress_percent = 2 + (crawled / total) * 38
            self._update_progress(
                crawled_urls=crawled,
                total_urls=total,
                current_url=result.url,
                current_action=f"Crawled: {result.url}",
            )

        self.crawler.set_callbacks(on_page_crawled=on_page)
        return self.crawler.crawl()

    def _run_fuzz(self, crawl_results: List[CrawlResult]) -> list:
        """Execute the fuzzing phase."""
        all_fuzz_results = []
        total_forms = sum(len(r.forms) for r in crawl_results)
        tested = 0

        def on_fuzz(url, param, payload):
            nonlocal tested
            self._update_progress(
                current_action=f"Fuzzing: {url} [{param}]",
                total_payloads_sent=self.progress.total_payloads_sent + 1,
            )

        self.fuzzer.set_callbacks(on_fuzz_test=on_fuzz)

        for crawl_result in crawl_results:
            # Fuzz forms
            for form in crawl_result.forms:
                tested += 1
                # Spread fuzzing across 50–75%
                if total_forms > 0:
                    self.progress.progress_percent = 50 + (tested / total_forms) * 25
                self._update_progress(
                    tested_forms=tested,
                    total_forms=total_forms,
                    current_action=f"Fuzzing form on {crawl_result.url} ({tested}/{total_forms})",
                )
                fuzz_results = self.fuzzer.fuzz_form(form, crawl_result.response_body)
                all_fuzz_results.extend(fuzz_results)

            # Fuzz URL parameters
            parsed = urlparse(crawl_result.url)
            if parsed.query:
                fuzz_results = self.fuzzer.fuzz_url_params(crawl_result.url)
                all_fuzz_results.extend(fuzz_results)

        logger.info(f"Fuzzing complete: {len(all_fuzz_results)} test cases executed")
        return all_fuzz_results

    def _run_ml_pipelines(self, findings: List[Finding]) -> List[Finding]:
        """Run ML post-processing pipelines."""
        try:
            from ml.pipeline import MLPipeline
            pipeline = MLPipeline()
            findings = pipeline.process(findings)
            logger.info(f"ML processing complete: {len(findings)} findings after filtering")
        except ImportError:
            logger.warning("ML pipeline not available, skipping ML processing")
        except Exception as e:
            logger.error(f"ML pipeline error: {e}")
        return findings
