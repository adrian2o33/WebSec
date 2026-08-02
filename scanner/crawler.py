"""
Web Crawler Module
Systematically discovers pages, forms, and input vectors on a target website.
Uses BFS traversal with domain scoping, depth limiting, and deduplication.
"""
import logging
import time
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from typing import Set, List, Tuple, Optional
from collections import deque

import requests
from bs4 import BeautifulSoup

from scanner.models import CrawlResult, FormData, FormField
from config import ScannerConfig

logger = logging.getLogger(__name__)


class Crawler:
    """
    BFS web crawler that discovers internal pages, forms, and links
    within the scope of a target domain.
    """

    def __init__(self, base_url: str, max_depth: int = None, max_pages: int = None,
                 request_delay: float = None, timeout: int = None, auth_cookies: dict = None):
        self.base_url = self._normalize_url(base_url)
        parsed = urlparse(self.base_url)
        self.target_domain = parsed.netloc
        self.scheme = parsed.scheme

        self.max_depth = max_depth or ScannerConfig.MAX_DEPTH
        self.max_pages = max_pages or ScannerConfig.MAX_PAGES
        self.request_delay = request_delay if request_delay is not None else ScannerConfig.REQUEST_DELAY
        self.timeout = timeout or ScannerConfig.REQUEST_TIMEOUT

        self.visited: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.session = requests.Session()
        
        if auth_cookies:
            self.session.cookies.update(auth_cookies)
            logger.info(f"Loaded {len(auth_cookies)} authentication cookies into Crawler session.")

        self.session.headers.update({
            "User-Agent": ScannerConfig.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        # Progress tracking callbacks
        self._on_page_crawled = None
        self._on_progress = None

    def set_callbacks(self, on_page_crawled=None, on_progress=None):
        """Set callback functions for progress tracking."""
        self._on_page_crawled = on_page_crawled
        self._on_progress = on_progress

    def crawl(self) -> List[CrawlResult]:
        """
        Perform BFS crawl starting from base_url.
        Returns list of CrawlResult for each page visited.
        """
        queue: deque = deque()
        queue.append((self.base_url, 0))  # (url, depth)
        self.visited.clear()
        self.results.clear()

        logger.info(f"Starting crawl of {self.base_url} (max_depth={self.max_depth}, max_pages={self.max_pages})")

        while queue and len(self.results) < self.max_pages:
            url, depth = queue.popleft()

            # Normalize and deduplicate
            normalized = self._normalize_url(url)
            if normalized in self.visited:
                continue
            if depth > self.max_depth:
                continue

            self.visited.add(normalized)
            result = self._fetch_page(normalized)

            if result:
                self.results.append(result)

                if self._on_page_crawled:
                    self._on_page_crawled(result)

                # Enqueue discovered links
                if depth < self.max_depth:
                    for link in result.links:
                        link_normalized = self._normalize_url(link)
                        if link_normalized not in self.visited and self._is_in_scope(link_normalized):
                            queue.append((link_normalized, depth + 1))

                if self._on_progress:
                    self._on_progress(len(self.results), len(self.visited) + len(queue))

            # Rate limiting
            if self.request_delay > 0:
                time.sleep(self.request_delay)

        logger.info(f"Crawl complete. Visited {len(self.results)} pages, found {sum(len(r.forms) for r in self.results)} forms.")
        return self.results

    def _fetch_page(self, url: str) -> Optional[CrawlResult]:
        """Fetch a single page and extract links and forms."""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            content_type = response.headers.get("Content-Type", "")

            # Skip non-HTML content
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                logger.debug(f"Skipping non-HTML: {url} ({content_type})")
                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=content_type,
                    response_headers=dict(response.headers),
                    is_https=url.startswith("https"),
                )

            soup = BeautifulSoup(response.text, "lxml")
            links = self._extract_links(soup, url)
            forms = self._extract_forms(soup, url)
            cookies = {c.name: c.value for c in self.session.cookies}

            result = CrawlResult(
                url=url,
                status_code=response.status_code,
                content_type=content_type,
                response_body=response.text,
                response_headers=dict(response.headers),
                links=links,
                forms=forms,
                cookies=cookies,
                is_https=url.startswith("https"),
            )

            logger.info(f"[{response.status_code}] {url} — {len(links)} links, {len(forms)} forms")
            return result

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {url}")
            return CrawlResult(url=url, status_code=0, error="Timeout")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for {url}")
            return CrawlResult(url=url, status_code=0, error="Connection Error")
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return CrawlResult(url=url, status_code=0, error=str(e))

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> List[str]:
        """Extract and normalise all internal hyperlinks from a page."""
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            # Skip anchors, javascript, mailto, tel
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(page_url, href)
            # Remove fragments
            parsed = urlparse(absolute)
            clean = urlunparse(parsed._replace(fragment=""))
            if self._is_in_scope(clean):
                links.append(clean)
        return list(set(links))

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[FormData]:
        """Extract all HTML forms and their fields from a page."""
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            if action:
                action = urljoin(page_url, action)
            else:
                action = page_url

            method = form_tag.get("method", "GET").upper()
            fields = []

            # Input fields
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                field_type = inp.get("type", "text")
                value = inp.get("value", "")
                fields.append(FormField(name=name, field_type=field_type, value=value))

            if fields:
                forms.append(FormData(
                    action=action,
                    method=method,
                    fields=fields,
                    page_url=page_url,
                ))

        return forms

    def _is_in_scope(self, url: str) -> bool:
        """Check if a URL belongs to the target domain."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        return parsed.netloc == self.target_domain

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL by removing trailing slashes and sorting query params."""
        parsed = urlparse(url)
        # Sort query parameters for consistent dedup
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(sorted(params.items()), doseq=True)
            parsed = parsed._replace(query=sorted_query)
        # Remove trailing slash (except for root)
        path = parsed.path.rstrip("/") or "/"
        parsed = parsed._replace(path=path, fragment="")
        return urlunparse(parsed)
