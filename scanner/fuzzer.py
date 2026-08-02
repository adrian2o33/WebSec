"""
Fuzzer Module
Injects test payloads into discovered form fields and URL parameters
to probe for security vulnerabilities.
"""
import logging
import os
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from scanner.models import FormData, FormField
from config import ScannerConfig

logger = logging.getLogger(__name__)

# Directory containing payload files
PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "payloads")


class FuzzResult:
    """Result of a single fuzz test."""

    def __init__(self, url: str, parameter: str, payload: str,
                 method: str, response_status: int, response_body: str,
                 response_headers: Dict[str, str], response_time: float,
                 baseline_length: int = 0, baseline_time: float = 0.0):
        self.url = url
        self.parameter = parameter
        self.payload = payload
        self.method = method
        self.response_status = response_status
        self.response_body = response_body
        self.response_headers = response_headers
        self.response_time = response_time
        self.baseline_length = baseline_length
        self.baseline_time = baseline_time  # Average response time for non-payload requests


class Fuzzer:
    """
    Injects payloads into form fields and URL query parameters.
    Produces FuzzResult objects for each test case.
    """

    def __init__(self, session: requests.Session = None,
                 request_delay: float = None, timeout: int = None):
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", ScannerConfig.USER_AGENT)
        self.request_delay = request_delay if request_delay is not None else ScannerConfig.REQUEST_DELAY
        self.timeout = timeout or ScannerConfig.REQUEST_TIMEOUT
        self.payloads = self._load_payloads()

        # Progress callback
        self._on_fuzz_test = None

    def set_callbacks(self, on_fuzz_test=None):
        self._on_fuzz_test = on_fuzz_test

    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load payload files from the payloads directory."""
        payloads = {}
        if not os.path.isdir(PAYLOADS_DIR):
            logger.warning(f"Payloads directory not found: {PAYLOADS_DIR}")
            return self._default_payloads()

        for filename in os.listdir(PAYLOADS_DIR):
            if filename.endswith(".txt"):
                category = filename.replace(".txt", "")
                filepath = os.path.join(PAYLOADS_DIR, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                        payloads[category] = lines[:ScannerConfig.MAX_PAYLOADS_PER_PARAM]
                except Exception as e:
                    logger.error(f"Error loading payload file {filename}: {e}")

        if not payloads:
            return self._default_payloads()

        logger.info(f"Loaded payloads: {', '.join(f'{k}({len(v)})' for k, v in payloads.items())}")
        return payloads

    @staticmethod
    def _default_payloads() -> Dict[str, List[str]]:
        """Fallback payloads if files are not available."""
        return {
            "xss": [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "';alert('XSS')//",
                '<img src=x onerror=alert("XSS")>',
                '<svg/onload=alert("XSS")>',
                '" onfocus="alert(1)" autofocus="',
                "javascript:alert('XSS')",
                '<body onload=alert("XSS")>',
                '{{73*73}}',
                '${73*73}',
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "1' ORDER BY 1--",
                "1' UNION SELECT NULL--",
                "1 OR 1=1",
                "' UNION SELECT 1,2,3--",
                "admin'--",
                "1; DROP TABLE users--",
                "' AND 1=CONVERT(int, @@version)--",
                "1' AND SLEEP(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
            ],
            "path_traversal": [
                "../../etc/passwd",
                "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//etc/passwd",
                "..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252Fetc%252Fpasswd",
                "/etc/passwd%00",
                "....\\\\....\\\\windows\\\\win.ini",
            ],
            "command_injection": [
                "; ls -la",
                "| cat /etc/passwd",
                "`id`",
                "$(id)",
                "; whoami",
                "| dir",
                "& ipconfig",
                "|| ping -c 1 127.0.0.1",
            ],
        }

    def _measure_baseline_time(self, url: str, method: str = "GET",
                                data: Dict = None, num_samples: int = 3) -> float:
        """Measure average baseline response time for a URL."""
        times = []
        for _ in range(num_samples):
            try:
                start = time.time()
                if method == "POST" and data:
                    self.session.post(url, data=data, timeout=self.timeout,
                                     allow_redirects=True, verify=False)
                else:
                    self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, verify=False)
                elapsed = time.time() - start
                times.append(elapsed)
            except Exception:
                times.append(self.timeout)
            if self.request_delay > 0:
                time.sleep(self.request_delay)
        return sum(times) / len(times) if times else 1.0

    def fuzz_form(self, form: FormData, baseline_response: str = "") -> List[FuzzResult]:
        """
        Fuzz all fields in a form with all payload categories.
        Tests one field at a time while keeping others at default values.
        Measures baseline response time for time-based blind detection.
        """
        results = []
        baseline_len = len(baseline_response)

        # Measure baseline timing for this form's target URL
        default_data = {}
        for field_obj in form.fields:
            default_data[field_obj.name] = field_obj.value or "test"
        baseline_time = self._measure_baseline_time(
            form.action, method=form.method, data=default_data
        )
        logger.info(f"Baseline response time for {form.action}: {baseline_time:.3f}s")

        for field_obj in form.fields:
            # Skip submit buttons and hidden fields with CSRF tokens
            if field_obj.field_type in ("submit", "button", "image", "reset"):
                continue
            if field_obj.field_type == "hidden" and any(
                tok in field_obj.name.lower() for tok in ["csrf", "token", "_token", "nonce"]
            ):
                continue

            for category, payload_list in self.payloads.items():
                for payload in payload_list:
                    result = self._send_fuzz_request(
                        form, field_obj, payload, category, baseline_len,
                        baseline_time=baseline_time
                    )
                    if result:
                        results.append(result)

                    if self._on_fuzz_test:
                        self._on_fuzz_test(form.action, field_obj.name, payload)

                    if self.request_delay > 0:
                        time.sleep(self.request_delay)

        return results

    def fuzz_url_params(self, url: str) -> List[FuzzResult]:
        """
        Fuzz URL query parameters with all payload categories.
        Measures baseline response time for time-based blind detection.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return []

        # Measure baseline timing for this URL
        baseline_time = self._measure_baseline_time(url)
        logger.info(f"Baseline response time for {url}: {baseline_time:.3f}s")

        results = []
        for param_name in params:
            for category, payload_list in self.payloads.items():
                for payload in payload_list:
                    result = self._send_param_fuzz(
                        url, param_name, payload, category,
                        baseline_time=baseline_time
                    )
                    if result:
                        results.append(result)

                    if self._on_fuzz_test:
                        self._on_fuzz_test(url, param_name, payload)

                    if self.request_delay > 0:
                        time.sleep(self.request_delay)

        return results

    def _send_fuzz_request(self, form: FormData, target_field: FormField,
                           payload: str, category: str,
                           baseline_len: int,
                           baseline_time: float = 0.0) -> Optional[FuzzResult]:
        """Send a single fuzzing request targeting one form field."""
        # Build form data with normal values + payload in target field
        data = {}
        for field_obj in form.fields:
            if field_obj.name == target_field.name:
                data[field_obj.name] = payload
            else:
                data[field_obj.name] = field_obj.value or "test"

        try:
            start = time.time()
            if form.method == "POST":
                resp = self.session.post(
                    form.action, data=data, timeout=self.timeout,
                    allow_redirects=False, verify=False
                )
            else:
                resp = self.session.get(
                    form.action, params=data, timeout=self.timeout,
                    allow_redirects=False, verify=False
                )
            elapsed = time.time() - start

            return FuzzResult(
                url=form.action,
                parameter=target_field.name,
                payload=payload,
                method=form.method,
                response_status=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                response_time=elapsed,
                baseline_length=baseline_len,
                baseline_time=baseline_time,
            )

        except requests.exceptions.Timeout:
            # Timeout might indicate a time-based injection success
            return FuzzResult(
                url=form.action,
                parameter=target_field.name,
                payload=payload,
                method=form.method,
                response_status=0,
                response_body="",
                response_headers={},
                response_time=self.timeout,
                baseline_length=baseline_len,
                baseline_time=baseline_time,
            )
        except Exception as e:
            logger.debug(f"Fuzz request failed: {form.action} [{target_field.name}={payload}] — {e}")
            return None

    def _send_param_fuzz(self, url: str, param_name: str,
                         payload: str, category: str,
                         baseline_time: float = 0.0) -> Optional[FuzzResult]:
        """Send a fuzz request to URL query parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Replace target param with payload
        params[param_name] = [payload]
        # Flatten to single values
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}

        try:
            start = time.time()
            resp = self.session.get(
                url.split("?")[0], params=flat, timeout=self.timeout,
                allow_redirects=False, verify=False
            )
            elapsed = time.time() - start

            return FuzzResult(
                url=url,
                parameter=param_name,
                payload=payload,
                method="GET",
                response_status=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                response_time=elapsed,
                baseline_time=baseline_time,
            )
        except requests.exceptions.Timeout:
            return FuzzResult(
                url=url, parameter=param_name, payload=payload,
                method="GET", response_status=0, response_body="",
                response_headers={}, response_time=self.timeout,
                baseline_time=baseline_time,
            )
        except Exception as e:
            logger.debug(f"Param fuzz failed: {url} [{param_name}={payload}] — {e}")
            return None
