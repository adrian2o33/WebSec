"""
DOM-based XSS Verification Module.

Uses Playwright to verify XSS findings by actually rendering pages in a
headless Chromium browser and checking if injected payloads execute
JavaScript. This dramatically reduces false positives by confirming that
a reflected payload truly achieves code execution in a real browser engine.
"""
import logging
import re
import urllib.parse
from typing import List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
import sys
import asyncio

from playwright.async_api import async_playwright, Browser, Page

from scanner.models import VulnerabilityType, Finding
from scanner.crypto_detector import CryptoDetector

logger = logging.getLogger(__name__)

# Indicators that suggest XSS execution occurred in console output
_XSS_CONSOLE_INDICATORS = frozenset({
    "xss", "alert", "document.cookie", "document.domain",
    "onerror", "onload", "javascript:",
})

# Maximum number of findings to verify (to bound total run time)
_MAX_VERIFY = 20

# Seconds to wait for JS execution after page load
_JS_WAIT_TIMEOUT = 5_000  # milliseconds


class DOMVerifier:
    """Verifies XSS vulnerabilities using headless Chromium via Playwright.

    Renders pages with injected payloads and checks if JavaScript executes.
    Each verification runs in a fresh incognito browser context with external
    resource loading blocked (except the target domain) for safety.
    """

    def __init__(self):
        self._browser = None
        self._playwright = None
        self._available = True  # Set to False if playwright install fails

    # ------------------------------------------------------------------
    # Browser lifecycle
    # ------------------------------------------------------------------

    async def _ensure_browser(self):
        """Lazily initialize the Chromium browser on first use."""
        if self._browser is not None:
            return

        try:
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            logger.info("Playwright Chromium browser launched for DOM verification")
        except Exception as e:
            logger.warning(f"Playwright browser launch failed: {e}")
            self._available = False

    # ------------------------------------------------------------------
    # Single-finding verification
    # ------------------------------------------------------------------

    async def verify_xss(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str = "GET",
    ) -> Tuple[bool, str]:
        """Verify whether an XSS payload actually executes in a browser.

        Args:
            url: The target URL (may already contain query parameters).
            parameter: The vulnerable parameter name.
            payload: The XSS payload string.
            method: HTTP method used in the original request (GET or POST).

        Returns:
            A ``(confirmed, evidence)`` tuple.  *confirmed* is ``True`` when
            JavaScript execution was observed; *evidence* contains a
            human-readable description of what fired.
        """
        await self._ensure_browser()
        if not self._available or self._browser is None:
            return False, ""

        # -- State captured by event handlers --
        alert_fired = False
        alert_text = ""
        console_xss = False
        console_messages: List[str] = []

        context = None
        try:
            # Fresh incognito context for isolation
            target_origin = urlparse(url).netloc
            context = await self._browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            page = await context.new_page()

            # Block requests to external domains for safety
            async def _route_handler(route):
                req_host = urlparse(route.request.url).netloc
                if req_host and req_host != target_origin:
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", _route_handler)

            # --- Dialog handler (alert / confirm / prompt) ---
            async def handle_dialog(dialog):
                nonlocal alert_fired, alert_text
                alert_fired = True
                alert_text = dialog.message
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # --- Console handler ---
            def handle_console(msg):
                nonlocal console_xss
                text = msg.text.lower()
                console_messages.append(msg.text)
                if any(ind in text for ind in _XSS_CONSOLE_INDICATORS):
                    console_xss = True

            page.on("console", handle_console)

            # --- Navigate / submit ---
            if method.upper() == "POST":
                await self._navigate_post(page, url, parameter, payload)
            else:
                target_url = self._build_get_url(url, parameter, payload)
                await page.goto(target_url, wait_until="load", timeout=15_000)

            # Wait for any asynchronous JS to fire
            await page.wait_for_timeout(_JS_WAIT_TIMEOUT)

            # --- Evaluate result ---
            if alert_fired:
                evidence = f"Dialog fired with message: {alert_text!r}"
                logger.info(f"XSS confirmed (dialog): {url} [{parameter}]")
                return True, evidence

            if console_xss:
                relevant = [m for m in console_messages
                            if any(i in m.lower() for i in _XSS_CONSOLE_INDICATORS)]
                evidence = f"Console XSS indicator detected: {'; '.join(relevant[:5])}"
                logger.info(f"XSS confirmed (console): {url} [{parameter}]")
                return True, evidence

            return False, ""

        except Exception as e:
            logger.debug(f"DOM verification error for {url} [{parameter}]: {e}")
            return False, ""
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Helpers for URL / form construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_get_url(url: str, parameter: str, payload: str) -> str:
        """Inject *payload* into *parameter* within the URL query string."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Replace (or add) the target parameter
        params[parameter] = [payload]
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_query = urlencode(flat, safe="")
        return parsed._replace(query=new_query).geturl()

    @staticmethod
    async def _navigate_post(page, url: str, parameter: str, payload: str):
        """Create a temporary form and POST the payload via Playwright."""
        # Navigate to about:blank first, then inject a form pointing at url
        await page.goto("about:blank")
        await page.evaluate(
            """([action, paramName, paramValue]) => {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = action;
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = paramName;
                input.value = paramValue;
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
            }""",
            [url, parameter, payload],
        )
        # Wait for navigation triggered by the form submission
        try:
            await page.wait_for_load_state("load", timeout=15_000)
        except Exception:
            pass  # Timeout is acceptable; payload may still have fired

    # ------------------------------------------------------------------
    # Malware verification
    # ------------------------------------------------------------------
    async def verify_malware(self, url: str) -> Tuple[bool, str]:
        """Verify whether a page attempts to connect to a known crypto mining pool.

        Args:
            url: The target URL to test.

        Returns:
            A tuple (confirmed, evidence).
        """
        await self._ensure_browser()
        if not self._available or self._browser is None:
            return False, ""

        mining_detected = False
        evidence_msg = ""
        detector = CryptoDetector()

        async def route_handler(route):
            nonlocal mining_detected, evidence_msg
            request = route.request
            
            if detector.is_mining_domain(request.url):
                mining_detected = True
                evidence_msg = f"Intercepted request to known mining pool: {request.url}"
                logger.warning(f"[Dynamic Malware] {evidence_msg}")
                await route.abort()
                return
            await route.continue_()

        def ws_handler(ws):
            nonlocal mining_detected, evidence_msg
            if detector.is_mining_domain(ws.url):
                mining_detected = True
                evidence_msg = f"Intercepted WebSocket connection to known mining pool: {ws.url}"
                logger.warning(f"[Dynamic Malware] {evidence_msg}")

        context = None
        try:
            context = await self._browser.new_context()
            page = await context.new_page()
            
            await page.route("**/*", route_handler)
            page.on("websocket", ws_handler)

            # Navigate to the target URL and wait for scripts to execute
            try:
                await page.goto(url, wait_until="networkidle", timeout=15_000)
            except Exception as e:
                logger.debug(f"Page load timeout/error for {url}, proceeding to check findings: {e}")
            
            # Wait an additional moment for WASM modules to initialize and dial out
            await page.wait_for_timeout(5000)

            return mining_detected, evidence_msg

        except Exception as e:
            logger.debug(f"Dynamic malware verification error for {url}: {e}")
            return False, ""
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Batch verification
    # ------------------------------------------------------------------

    async def verify_findings(self, findings: list) -> list:
        """Batch-verify a list of potential XSS findings.

        Only findings whose ``vuln_type`` has value ``"Reflected XSS"``
        (i.e. ``VulnerabilityType.XSS_REFLECTED``) are considered.

        * If confirmed → ``confidence`` set to **1.0** and evidence updated.
        * If not confirmed → ``confidence`` reduced by **0.2**
          (clamped to 0.0).

        At most :data:`_MAX_VERIFY` findings are verified (sorted by
        confidence ascending so the *least* confident are checked first).

        Args:
            findings: A plain ``list`` of ``Finding`` objects.

        Returns:
            The same list, with confidence / evidence fields updated.
        """
        await self._ensure_browser()
        if not self._available or self._browser is None:
            logger.warning(
                "Playwright unavailable — skipping DOM XSS verification"
            )
            return findings

        # Filter to XSS_REFLECTED findings only
        xss_findings = []
        for f in findings:
            if not hasattr(f, "vuln_type"):
                continue
            vtype = f.vuln_type
            # Support both enum and raw string comparison
            type_value = vtype.value if hasattr(vtype, "value") else str(vtype)
            if type_value == "Reflected XSS":
                xss_findings.append(f)

        if not xss_findings:
            logger.debug("No reflected XSS findings to verify via DOM")
            return findings

        # Sort by confidence ascending → verify least-confident first
        xss_findings.sort(key=lambda f: getattr(f, "confidence", 0.8))
        to_verify = xss_findings[:_MAX_VERIFY]

        logger.info(
            f"DOM-verifying {len(to_verify)} / {len(xss_findings)} "
            f"reflected XSS findings"
        )

        for finding in to_verify:
            url = getattr(finding, "url", "")
            parameter = getattr(finding, "parameter", "")
            payload = getattr(finding, "payload", "")

            if not url or not parameter or not payload:
                continue

            # Guess the HTTP method from existing evidence or default to GET
            method = "GET"
            existing_evidence = getattr(finding, "evidence", "")
            if "POST" in existing_evidence.upper():
                method = "POST"

            confirmed, evidence = await self.verify_xss(
                url, parameter, payload, method
            )

            if confirmed:
                finding.confidence = 1.0
                # Append DOM-verification evidence
                prev = getattr(finding, "evidence", "")
                sep = " | " if prev else ""
                finding.evidence = (
                    f"{prev}{sep}[DOM-Verified] {evidence}"
                )
                logger.info(
                    f"  ✓ Confirmed: {url} [{parameter}] — {evidence}"
                )
            else:
                old_conf = getattr(finding, "confidence", 0.8)
                # If DOM verification ran but failed to execute the JS, it's highly likely a false positive (e.g. JSON reflection)
                # Drop confidence below 0.5 so it gets filtered out by the ML post-processor
                finding.confidence = 0.3
                logger.debug(
                    f"  ✗ Not confirmed: {url} [{parameter}] "
                    f"(confidence {old_conf:.1f} → {finding.confidence:.1f})"
                )

        return findings

    # ------------------------------------------------------------------
    # Synchronous wrapper
    # ------------------------------------------------------------------

    def verify_findings_sync(self, findings: list) -> list:
        """Synchronous wrapper around :meth:`verify_findings`.

        Creates a fresh event loop, runs verification to completion,
        and then cleans up.  Safe to call from non-async code.
        """
        async def _run():
            verifier = DOMVerifier()
            try:
                return await verifier.verify_findings(findings)
            finally:
                await verifier.close()
                if sys.platform == 'win32':
                    import asyncio
                    await asyncio.sleep(0.1)

        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()

    def verify_malware_sync(self, url: str) -> Tuple[bool, str]:
        """Synchronous wrapper around :meth:`verify_malware`."""
        async def _run():
            verifier = DOMVerifier()
            try:
                return await verifier.verify_malware(url)
            finally:
                await verifier.close()
                if sys.platform == 'win32':
                    import asyncio
                    await asyncio.sleep(0.1)

        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_run())
        finally:
            loop.close()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def close(self):
        """Release browser resources."""
        if self._browser is not None:
            try:
                await self._browser.close()
                logger.debug("Playwright browser closed")
            except Exception as e:
                logger.debug(f"Error closing browser: {e}")
            self._browser = None

        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
