import requests
import logging

logger = logging.getLogger(__name__)

class CryptoDetector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CryptoDetector, cls).__new__(cls)
            cls._instance.mining_domains = set()
            cls._instance._load_domains()
        return cls._instance

    def _load_domains(self):
        "Prigent-Crypto list"
        url = "https://v.firebog.net/hosts/Prigent-Crypto.txt"
        
        # Backup list
        fallback = [
            "coinhive.com", "coin-hive.com", "authedmine.com",
            "supportxmr.com", "moneroocean.stream", "xmrpool.eu",
            "pool.minexmr.com", "cnhv.co"
        ]

        try:
            logger.info(f"Fetching live crypto blocklist from {url}...")
            # Timeout is strictly set so we don't hang scanner startup
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Some lists have format "0.0.0.0 domain.com", others just "domain.com"
                parts = line.split()
                if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = parts[1]
                else:
                    domain = parts[0]
                self.mining_domains.add(domain.lower())
                
            logger.info(f"Successfully loaded {len(self.mining_domains)} crypto mining domains.")
        except Exception as e:
            logger.error(f"Failed to fetch live crypto blocklist: {e}. Using fallback list.")
            self.mining_domains.update(fallback)

    def is_mining_domain(self, target_url: str) -> bool:
        """Check if a URL belongs to a known mining domain."""
        target_url = target_url.lower()
        
        try:
            from urllib.parse import urlparse
            # Handle wss:// and file:// etc
            if not target_url.startswith(('http://', 'https://', 'ws://', 'wss://')):
                # If it's just a domain or malformed, try to parse it by prepending scheme
                parsed = urlparse('http://' + target_url)
            else:
                parsed = urlparse(target_url)
                
            host = parsed.hostname
            if host:
                if host in self.mining_domains:
                    return True
                # Check for subdomains (e.g. pool.supportxmr.com matches supportxmr.com)
                parts = host.split('.')
                for i in range(len(parts) - 1):
                    sub = '.'.join(parts[i:])
                    if sub in self.mining_domains:
                        return True
        except Exception:
            pass
            
        return False
