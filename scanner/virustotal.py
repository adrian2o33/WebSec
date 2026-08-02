"""
VirusTotal API v3 Client Module.

Provides a high-level interface for querying the VirusTotal v3 REST API
to look up file hashes, scan URLs, and check domain reputation.

Features:
    - Automatic rate-limiting for free-tier accounts (4 req/min).
    - In-memory result caching to avoid redundant API calls.
    - Retry logic for HTTP 429 (Too Many Requests) responses.
    - Comprehensive logging of every API interaction.

Usage example::

    from scanner.virustotal import VirusTotalClient

    client = VirusTotalClient()
    result = client.scan_hash("44d88612fea8a8f36de82e1278abb02f")
    if result:
        print(result["detection_ratio"])

References:
    https://docs.virustotal.com/reference/overview
"""

import logging
import time
from typing import Dict, List, Optional
from urllib.parse import quote_plus

import requests

from config import VirusTotalConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_BASE_URL = "https://www.virustotal.com/api/v3"
_DEFAULT_TIMEOUT = 15  # seconds
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 15  # seconds – base wait on 429


class VirusTotalClient:
    """Client for the VirusTotal v3 REST API.

    Parameters
    ----------
    api_key : str, optional
        VirusTotal API key.  When *None*, the key is read from
        ``VirusTotalConfig.API_KEY``.

    Attributes
    ----------
    _cache : dict
        In-memory cache mapping request keys to parsed results.
    _last_request_time : float
        Epoch timestamp of the most recent API call (used for throttling).
    _min_interval : float
        Minimum number of seconds between consecutive API calls, derived
        from ``VirusTotalConfig.RATE_LIMIT_PER_MINUTE``.
    """

    # ------------------------------------------------------------------ #
    #  Initialisation
    # ------------------------------------------------------------------ #
    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialise the VirusTotal client.

        Parameters
        ----------
        api_key : str, optional
            If not supplied the key is taken from
            ``VirusTotalConfig.API_KEY``.
        """
        self._api_key: str = api_key or VirusTotalConfig.API_KEY
        if not self._api_key:
            logger.error("No VirusTotal API key configured – all lookups will fail.")

        self._headers: Dict[str, str] = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
        }

        # Rate-limiting state
        rate_limit = getattr(VirusTotalConfig, "RATE_LIMIT_PER_MINUTE", 4)
        self._min_interval: float = 60.0 / rate_limit  # seconds between calls
        self._last_request_time: float = 0.0

        # Result cache: key → parsed dict
        self._cache: Dict[str, Optional[dict]] = {}
        self._cache_enabled: bool = getattr(VirusTotalConfig, "CACHE_RESULTS", True)

        logger.info(
            "VirusTotalClient initialised (rate_limit=%d req/min, cache=%s)",
            rate_limit,
            "on" if self._cache_enabled else "off",
        )

    # ------------------------------------------------------------------ #
    #  Internal helpers
    # ------------------------------------------------------------------ #
    def _throttle(self) -> None:
        """Block until enough time has elapsed since the last API call."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            wait = self._min_interval - elapsed
            logger.debug("Rate-limit throttle: sleeping %.1f s", wait)
            time.sleep(wait)

    def _request(
        self,
        method: str,
        url: str,
        *,
        data: Optional[dict] = None,
    ) -> Optional[requests.Response]:
        """Send an HTTP request with throttling and retry-on-429 logic.

        Parameters
        ----------
        method : str
            HTTP method (``"GET"`` or ``"POST"``).
        url : str
            Fully-qualified URL.
        data : dict, optional
            Form data payload (used for POST requests).

        Returns
        -------
        requests.Response or None
            The response object, or *None* if the request ultimately failed.
        """
        for attempt in range(1, _MAX_RETRIES + 1):
            self._throttle()
            self._last_request_time = time.time()

            try:
                logger.debug(
                    "VT API %s %s (attempt %d/%d)", method, url, attempt, _MAX_RETRIES
                )
                if method.upper() == "POST":
                    resp = requests.post(
                        url,
                        headers=self._headers,
                        data=data,
                        timeout=_DEFAULT_TIMEOUT,
                    )
                else:
                    resp = requests.get(
                        url,
                        headers=self._headers,
                        timeout=_DEFAULT_TIMEOUT,
                    )

                # ----- Rate-limited → back off and retry ---------------
                if resp.status_code == 429:
                    backoff = _RETRY_BACKOFF_BASE * attempt
                    logger.warning(
                        "VT API rate-limited (429). Retrying in %d s …", backoff
                    )
                    time.sleep(backoff)
                    continue

                return resp

            except requests.RequestException as exc:
                logger.error(
                    "VT API request error on attempt %d/%d: %s",
                    attempt,
                    _MAX_RETRIES,
                    exc,
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(2 * attempt)

        logger.error("VT API request failed after %d attempts: %s", _MAX_RETRIES, url)
        return None

    # ------------------------------------------------------------------ #
    #  Public API – File hash lookup
    # ------------------------------------------------------------------ #
    def scan_hash(self, file_hash: str) -> Optional[dict]:
        """Look up a file by its hash (MD5, SHA-1, or SHA-256).

        Uses ``GET /api/v3/files/{hash}``.

        Parameters
        ----------
        file_hash : str
            The file hash to query.

        Returns
        -------
        dict or None
            A normalised result dict with keys:

            - **detected** (*bool*) – ``True`` if at least one engine
              flagged the file.
            - **detection_ratio** (*str*) – e.g. ``"45/72"``.
            - **scan_results** (*list[dict]*) – per-engine verdicts.
            - **permalink** (*str*) – link to the VT report.

            Returns ``None`` when the hash is unknown (404) or on error.
        """
        file_hash = file_hash.strip().lower()
        cache_key = f"hash:{file_hash}"

        if self._cache_enabled and cache_key in self._cache:
            logger.debug("Cache hit for hash %s", file_hash)
            return self._cache[cache_key]

        logger.info("Looking up file hash: %s", file_hash)
        url = f"{_BASE_URL}/files/{file_hash}"
        resp = self._request("GET", url)

        if resp is None:
            return self._store(cache_key, None)

        if resp.status_code == 404:
            logger.info("Hash %s not found in VirusTotal database.", file_hash)
            return self._store(cache_key, None)

        if resp.status_code != 200:
            logger.error(
                "VT hash lookup failed (HTTP %d): %s",
                resp.status_code,
                resp.text[:300],
            )
            return self._store(cache_key, None)

        try:
            body = resp.json()
            attrs = body["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values())

            scan_results = self._parse_last_analysis(attrs.get("last_analysis_results", {}))

            result: dict = {
                "detected": malicious > 0,
                "detection_ratio": f"{malicious}/{total}",
                "scan_results": scan_results,
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }

            logger.info(
                "Hash %s — detection ratio %s", file_hash, result["detection_ratio"]
            )
            return self._store(cache_key, result)

        except (KeyError, ValueError) as exc:
            logger.error("Failed to parse VT hash response: %s", exc)
            return self._store(cache_key, None)

    # ------------------------------------------------------------------ #
    #  Public API – URL scan
    # ------------------------------------------------------------------ #
    def scan_url(self, url: str) -> Optional[dict]:
        """Submit a URL for scanning and retrieve the analysis results.

        Workflow:
            1. ``POST /api/v3/urls`` to submit the URL.
            2. ``GET /api/v3/analyses/{id}`` to poll for results.

        Parameters
        ----------
        url : str
            The URL to scan.

        Returns
        -------
        dict or None
            A normalised result dict with keys:

            - **detected** (*bool*) – ``True`` if at least one engine
              flagged the URL.
            - **positives** (*int*) – number of engines that flagged it.
            - **total** (*int*) – total number of engines.
            - **scan_results** (*list[dict]*) – per-engine verdicts.
            - **permalink** (*str*) – link to the VT report.

            Returns ``None`` on error.
        """
        cache_key = f"url:{url}"
        if self._cache_enabled and cache_key in self._cache:
            logger.debug("Cache hit for URL %s", url)
            return self._cache[cache_key]

        logger.info("Submitting URL for scan: %s", url)

        # Step 1 – submit the URL
        submit_resp = self._request(
            "POST",
            f"{_BASE_URL}/urls",
            data={"url": url},
        )

        if submit_resp is None or submit_resp.status_code not in (200, 201):
            status = submit_resp.status_code if submit_resp else "N/A"
            logger.error("VT URL submission failed (HTTP %s)", status)
            return self._store(cache_key, None)

        try:
            analysis_id = submit_resp.json()["data"]["id"]
        except (KeyError, ValueError) as exc:
            logger.error("Cannot extract analysis ID from VT response: %s", exc)
            return self._store(cache_key, None)

        # Step 2 – poll for the analysis result (up to 5 attempts)
        analysis_url = f"{_BASE_URL}/analyses/{analysis_id}"
        for poll in range(1, 6):
            logger.debug("Polling analysis %s (attempt %d/5)", analysis_id, poll)
            analysis_resp = self._request("GET", analysis_url)

            if analysis_resp is None or analysis_resp.status_code != 200:
                logger.warning("Poll attempt %d failed for analysis %s", poll, analysis_id)
                time.sleep(5 * poll)
                continue

            try:
                body = analysis_resp.json()
                attrs = body["data"]["attributes"]
                status = attrs.get("status", "")

                if status == "completed":
                    stats = attrs.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    positives = malicious + suspicious
                    total = sum(stats.values())

                    results_map = attrs.get("results", {})
                    scan_results = self._parse_last_analysis(results_map)

                    # Build a deterministic URL-id for the permalink
                    import base64
                    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

                    result: dict = {
                        "detected": positives > 0,
                        "positives": positives,
                        "total": total,
                        "scan_results": scan_results,
                        "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                    }

                    logger.info(
                        "URL %s — %d/%d engines flagged", url, positives, total
                    )
                    return self._store(cache_key, result)

                elif status == "queued":
                    logger.debug("Analysis %s still queued, waiting …", analysis_id)
                    time.sleep(10)
                    continue
                else:
                    logger.debug(
                        "Analysis %s status: %s, waiting …", analysis_id, status
                    )
                    time.sleep(5 * poll)
                    continue

            except (KeyError, ValueError) as exc:
                logger.error("Failed to parse VT analysis response: %s", exc)
                time.sleep(5)
                continue

        logger.error("VT URL analysis timed out for %s", url)
        return self._store(cache_key, None)

    # ------------------------------------------------------------------ #
    #  Public API – Domain lookup
    # ------------------------------------------------------------------ #
    def check_domain(self, domain: str) -> Optional[dict]:
        """Check a domain's reputation and categorisation.

        Uses ``GET /api/v3/domains/{domain}``.

        Parameters
        ----------
        domain : str
            The domain name to query (e.g. ``"example.com"``).

        Returns
        -------
        dict or None
            A normalised result dict with keys:

            - **malicious** (*bool*) – ``True`` when VT considers the
              domain malicious (reputation < 0 *or* malicious analysis
              count > 0).
            - **reputation** (*int*) – community reputation score.
            - **categories** (*dict*) – engine → category mappings.
            - **last_analysis_stats** (*dict*) – breakdown by verdict
              (harmless, malicious, suspicious, undetected, timeout).

            Returns ``None`` on error or if the domain is unknown.
        """
        domain = domain.strip().lower()
        cache_key = f"domain:{domain}"

        if self._cache_enabled and cache_key in self._cache:
            logger.debug("Cache hit for domain %s", domain)
            return self._cache[cache_key]

        logger.info("Checking domain reputation: %s", domain)
        url = f"{_BASE_URL}/domains/{domain}"
        resp = self._request("GET", url)

        if resp is None:
            return self._store(cache_key, None)

        if resp.status_code == 404:
            logger.info("Domain %s not found in VirusTotal database.", domain)
            return self._store(cache_key, None)

        if resp.status_code != 200:
            logger.error(
                "VT domain lookup failed (HTTP %d): %s",
                resp.status_code,
                resp.text[:300],
            )
            return self._store(cache_key, None)

        try:
            body = resp.json()
            attrs = body["data"]["attributes"]
            reputation = attrs.get("reputation", 0)
            categories = attrs.get("categories", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            result: dict = {
                "malicious": malicious_count > 0 or reputation < 0,
                "reputation": reputation,
                "categories": categories,
                "last_analysis_stats": stats,
            }

            logger.info(
                "Domain %s — reputation=%d, malicious_engines=%d",
                domain,
                reputation,
                malicious_count,
            )
            return self._store(cache_key, result)

        except (KeyError, ValueError) as exc:
            logger.error("Failed to parse VT domain response: %s", exc)
            return self._store(cache_key, None)

    # ------------------------------------------------------------------ #
    #  Private helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_last_analysis(results: dict) -> List[dict]:
        """Convert VT ``last_analysis_results`` map to a flat list.

        Each entry in the returned list is a dict with:

        - **engine** (*str*) – AV engine name.
        - **result** (*str | None*) – detection label or ``None``.
        - **detected** (*bool*) – whether this engine flagged the item.

        Parameters
        ----------
        results : dict
            The ``last_analysis_results`` (or ``results``) mapping from the
            VT API response.

        Returns
        -------
        list[dict]
        """
        parsed: List[dict] = []
        for engine_name, detail in results.items():
            category = detail.get("category", "undetected")
            result_label = detail.get("result")
            parsed.append(
                {
                    "engine": engine_name,
                    "result": result_label,
                    "detected": category in ("malicious", "suspicious"),
                }
            )
        return parsed

    def _store(self, key: str, value: Optional[dict]) -> Optional[dict]:
        """Optionally cache *value* under *key* and return it.

        Parameters
        ----------
        key : str
            Cache key.
        value : dict or None
            The value to store.

        Returns
        -------
        dict or None
            *value*, unchanged.
        """
        if self._cache_enabled:
            self._cache[key] = value
        return value

    # ------------------------------------------------------------------ #
    #  Utility / introspection
    # ------------------------------------------------------------------ #
    def clear_cache(self) -> None:
        """Remove all cached results."""
        self._cache.clear()
        logger.info("VirusTotal result cache cleared.")

    @property
    def cache_size(self) -> int:
        """Return the number of cached entries."""
        return len(self._cache)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<VirusTotalClient cache={self.cache_size} "
            f"rate_limit={60 / self._min_interval:.0f}req/min>"
        )
