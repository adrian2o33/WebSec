"""
IDOR Detector
Implements professional-grade Insecure Direct Object Reference (IDOR) detection.
Features:
- Dual-session fuzzy matching (structural similarity).
- Active ID mutation (Numeric, UUID, Base64).
- Parameter & Path fuzzing.
"""
import logging
import asyncio
import aiohttp
import re
import base64
import difflib
from typing import List, Optional, Set
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# Patterns for IDs
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)

class IDORDetector:
    """Detects IDOR vulnerabilities by fuzzy-matching responses and actively fuzzing identifiers."""

    def __init__(self, timeout: int = 10, similarity_threshold: float = 0.90):
        self.timeout = timeout
        self.similarity_threshold = similarity_threshold

    async def _fetch(self, session: aiohttp.ClientSession, url: str, cookies: dict) -> tuple[int, str]:
        """Fetch a URL with specific cookies."""
        try:
            async with session.get(url, cookies=cookies, timeout=self.timeout, allow_redirects=False) as response:
                text = await response.text()
                return response.status, text
        except Exception as e:
            logger.warning(f"Error fetching {url} in IDOR check: {e}")
            return 0, ""

    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate structural similarity using SequenceMatcher to ignore dynamic CSRF/timestamps."""
        if not text1 or not text2:
            return 0.0
        # Truncate to 50k chars to prevent CPU spikes on massive pages
        matcher = difflib.SequenceMatcher(None, text1[:50000], text2[:50000])
        return matcher.quick_ratio()

    def generate_mutations(self, url: str) -> Set[str]:
        """Generate a list of mutated URLs by manipulating numeric, UUID, or Base64 IDs in paths and query params."""
        mutated_urls = set()
        parsed = urlparse(url)
        
        # Mutate query params
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        for i, (k, v) in enumerate(query_params):
            mutated_values = self._mutate_value(v)
            for mv in mutated_values:
                new_q = query_params[:]
                new_q[i] = (k, mv)
                mutated_urls.add(urlunparse(parsed._replace(query=urlencode(new_q))))

        # Mutate path segments
        path_segments = parsed.path.split('/')
        for i, seg in enumerate(path_segments):
            if not seg: 
                continue
            mutated_values = self._mutate_value(seg)
            for mv in mutated_values:
                new_path = path_segments[:]
                new_path[i] = mv
                mutated_urls.add(urlunparse(parsed._replace(path='/'.join(new_path))))

        return mutated_urls

    def _mutate_value(self, val: str) -> List[str]:
        """Identify value format (Numeric, UUID, Base64) and mutate accordingly."""
        mutations = set()
        
        if not val:
            return []

        # 1. Numeric Fuzzing
        if val.isdigit():
            num = int(val)
            mutations.add(str(num + 1))
            if num > 0:
                mutations.add(str(num - 1))
            return list(mutations)
            
        # 2. UUID Fuzzing
        if UUID_PATTERN.match(val):
            # Replace with a zeroed UUID
            mutations.add('00000000-0000-0000-0000-000000000000')
            # Flip the last character
            last_char = val[-1]
            new_char = '1' if last_char == '0' else '0'
            mutations.add(val[:-1] + new_char)
            return list(mutations)
            
        # 3. Base64 Numeric Fuzzing
        try:
            # Add padding if needed
            padded = val + '=' * (-len(val) % 4)
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', padded):
                decoded = base64.b64decode(padded).decode('utf-8')
                if decoded.isdigit():
                    num = int(decoded)
                    # Re-encode mutated values
                    mutations.add(base64.b64encode(str(num + 1).encode()).decode().rstrip('='))
                    if num > 0:
                        mutations.add(base64.b64encode(str(num - 1).encode()).decode().rstrip('='))
        except:
            pass
            
        return list(mutations)

    async def check_idor(self, target_url: str, auth_cookies: dict) -> Optional[Finding]:
        """Perform comprehensive Broken Access Control & IDOR analysis on a specific endpoint."""
        if not auth_cookies:
            return None

        async with aiohttp.ClientSession() as session:
            # Baseline: Fetch as Authenticated
            auth_status, auth_text = await self._fetch(session, target_url, auth_cookies)
            # Baseline: Fetch as Unauthenticated
            unauth_status, unauth_text = await self._fetch(session, target_url, {})

            # --- PHASE 1: Broken Access Control (Unauthenticated Access) ---
            if auth_status == 200 and unauth_status == 200 and len(auth_text) > 0:
                similarity = self.calculate_similarity(auth_text, unauth_text)
                if similarity >= self.similarity_threshold:
                    logger.info(f"[BAC] Detected unauthenticated access to authenticated endpoint at {target_url} (Similarity: {similarity:.2f})")
                    return self._flag_idor_vulnerability(
                        url=target_url, 
                        payload="No Cookies Sent", 
                        evidence=f"Unauthenticated session accessed the exact same object as the Authenticated session with {similarity*100:.1f}% structural similarity (bypassing dynamic tokens)."
                    )

            # --- PHASE 2: Active Mutation Fuzzing (Cross-Object IDOR) ---
            mutated_urls = self.generate_mutations(target_url)
            for m_url in mutated_urls:
                # Fetch mutated URL as authenticated
                m_auth_status, m_auth_text = await self._fetch(session, m_url, auth_cookies)
                
                # If we successfully accessed a mutated object
                if m_auth_status == 200 and len(m_auth_text) > 0:
                    
                    # Ensure it's not just returning the exact same page as baseline (e.g. ignoring the ID param entirely)
                    baseline_sim = self.calculate_similarity(m_auth_text, auth_text)
                    
                    if baseline_sim < 0.95:
                        logger.info(f"[IDOR] Detected active mutation IDOR at {m_url}")
                        return self._flag_idor_vulnerability(
                            url=target_url, 
                            payload=f"Mutated URL: {m_url}", 
                            evidence=f"Successfully brute-forced ID parameter. Authenticated session accessed an adjacent object with a different data structure."
                        )
                            
        return None

    def _flag_idor_vulnerability(self, url: str, payload: str, evidence: str) -> Finding:
        """Helper to construct the IDOR Finding object."""
        return Finding(
            url=url,
            parameter="Path/Query ID",
            payload=payload,
            vuln_type=VulnerabilityType.BROKEN_ACCESS_CONTROL,
            severity=SeverityLevel.HIGH,
            evidence=evidence,
            confidence=0.95,
            description=f"Insecure Direct Object Reference (IDOR) detected. "
                        f"The server failed to enforce authorization checks, allowing access to unauthorized horizontal/vertical resources.",
            recommendation="Implement strict Role-Based Access Control (RBAC) and object-level authorization on every endpoint. "
                           "Verify that the currently authenticated user owns or has explicit permission to access the requested object ID."
        )

    def analyze_urls(self, urls: List[str], auth_cookies: dict) -> List[Finding]:
        """Synchronous wrapper to run the async IDOR checks over multiple URLs."""
        findings = []
        if not auth_cookies:
            return findings

        async def _run_all():
            # Throttle concurrency to prevent flooding
            sem = asyncio.Semaphore(5)
            async def _bounded_check(url):
                async with sem:
                    return await self.check_idor(url, auth_cookies)

            tasks = [_bounded_check(url) for url in urls]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None]

        try:
            loop = asyncio.new_event_loop()
            findings = loop.run_until_complete(_run_all())
            loop.close()
        except Exception as e:
            logger.error(f"Error executing IDOR dual-session checks: {e}")

        return findings
