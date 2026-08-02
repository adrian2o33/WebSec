"""
Rate Limit Detector
Performs concurrent burst testing to detect Missing Rate Limiting and
potential Application-layer DoS vulnerabilities.
"""
import logging
import asyncio
import aiohttp
from typing import List, Optional
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

class RateLimitDetector:
    """Fires an async burst of identical requests to test for HTTP 429 Too Many Requests."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def _fetch(self, session: aiohttp.ClientSession, url: str) -> int:
        """Fetch a URL and return the status code."""
        try:
            async with session.get(url, timeout=self.timeout) as response:
                # We just need the status code, no need to read the full body
                return response.status
        except Exception:
            return 0

    async def check_rate_limiting(self, target_url: str, burst_size: int = 50) -> Optional[Finding]:
        "Fires a burst of async requests to test for HTTP 429."
        async with aiohttp.ClientSession() as session:
            tasks = [self._fetch(session, target_url) for _ in range(burst_size)]
            
            # Fire 50 requests simultaneously
            statuses = await asyncio.gather(*tasks)

        has_200 = False
        has_429 = False

        for status in statuses:
            if status == 200:
                has_200 = True
            elif status == 429:
                has_429 = True

        if has_200 and not has_429:
            # Server responded successfully to some, but never rate limited
            # If we got 50 successes, it definitively proves no rate limiting
            success_count = statuses.count(200)
            if success_count > (burst_size * 0.8): # If 80%+ succeeded without 429
                logger.warning(f"[RATE LIMIT] No rate limiting detected on {target_url}")
                return self._flag_rate_limit_vulnerability(target_url, success_count, burst_size)

        return None

    def _flag_rate_limit_vulnerability(self, url: str, success_count: int, total: int) -> Finding:
        """Helper to construct the Rate Limit Finding object."""
        return Finding(
            url=url,
            parameter="",
            payload=f"Burst of {total} concurrent requests",
            vuln_type=VulnerabilityType.MISSING_RATE_LIMIT,
            severity=SeverityLevel.HIGH,
            evidence=f"Server returned {success_count} successful HTTP 200 responses and 0 HTTP 429 Too Many Requests errors during an instant async burst of {total} requests.",
            confidence=0.95,
            description=f"Missing Rate Limiting detected at {url}. "
                        f"The server failed to block a rapid burst of identical requests, making it highly vulnerable to brute-forcing and Application-layer DoS.",
            recommendation="Implement IP-based and Session-based rate limiting on sensitive endpoints. "
                           "Return HTTP 429 Too Many Requests when limits are exceeded."
        )

    def analyze_urls(self, urls: List[str], burst_size: int = 50) -> List[Finding]:
        """Synchronous wrapper to run the async rate limit checks over multiple URLs."""
        findings = []
        if not urls:
            return findings

        async def _run_all():
            tasks = [self.check_rate_limiting(url, burst_size) for url in urls]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None]

        try:
            loop = asyncio.new_event_loop()
            findings = loop.run_until_complete(_run_all())
            loop.close()
        except Exception as e:
            logger.error(f"Error executing rate limit checks: {e}")

        return findings
