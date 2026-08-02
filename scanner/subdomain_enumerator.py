import requests
import socket
import logging
import urllib.parse
from typing import List
from scanner.models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)

class SubdomainEnumerator:
    """
    Actively hunts for forgotten and hidden subdomains using public Certificate 
    Transparency Logs (crt.sh) and verifies their existence via DNS resolution.
    """

    def __init__(self):
        self.crt_sh_url = "https://crt.sh/"

    def extract_base_domain(self, target_url: str) -> str:
        """Extracts the base domain from a full URL."""
        parsed = urllib.parse.urlparse(target_url)
        netloc = parsed.netloc.split(":")[0]  # Remove port if present
        
        # If it's just an IP address, we can't do subdomain enumeration
        try:
            socket.inet_aton(netloc)
            return ""  # It's an IP
        except socket.error:
            pass

        # Strip www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
            
        return netloc

    def enumerate(self, target_url: str) -> List[Finding]:
        """
        Discovers active subdomains for the target URL.
        Returns a list of Findings containing the live subdomains.
        """
        domain = self.extract_base_domain(target_url)
        if not domain:
            logger.info("Target is an IP address or invalid domain; skipping Subdomain Enumeration.")
            return []

        logger.info(f"[Reconnaissance] Starting Subdomain Enumeration for: {domain}")
        subdomains = set()

        # 1. Query crt.sh API
        try:
            params = {
                "q": f"%.{domain}",
                "output": "json"
            }
            # Add a reasonable timeout, crt.sh can sometimes be slow or down
            response = requests.get(self.crt_sh_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    
                    # since crt.sh api can give domains mashed together with newlines => split
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        
                        # throw away any shortcut certs and won't need to scan the base domain again
                        if sub and not sub.startswith("*.") and sub != domain and sub.endswith(f".{domain}"):
                            subdomains.add(sub)
            else:
                logger.warning(f"crt.sh API returned status code {response.status_code}")
        except Exception as e:
            logger.error(f"Error querying crt.sh for subdomains: {e}")

        # 2. Verify active subdomains via DNS resolution
        findings = []
        live_count = 0
        
        for sub in subdomains:
            try:
                # If it resolves to an IP, it's alive
                ip_address = socket.gethostbyname(sub)
                live_count += 1
                
                finding = Finding(
                    url=f"https://{sub}",
                    parameter="",
                    payload="",
                    vuln_type=VulnerabilityType.EXPOSED_SUBDOMAIN,
                    severity=SeverityLevel.INFO,
                    description=f"Discovered an active, potentially undocumented subdomain: {sub}",
                    evidence=f"Resolves to IP: {ip_address}",
                    confidence=1.0,
                    recommendation="Ensure this subdomain is intended to be public, is actively maintained, and is within the scope of your security monitoring."
                )
                findings.append(finding)
            except socket.gaierror:
                # Domain does not resolve (dead/offline)
                pass
            except Exception as e:
                logger.debug(f"Unexpected error resolving {sub}: {e}")

        logger.info(f"[Reconnaissance] Found {live_count} active subdomains out of {len(subdomains)} logged certificates.")
        return findings
