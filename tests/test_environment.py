import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestEnvironment(unittest.TestCase):
    """
    Installation & Environment Tests.
    Ensures all critical dependencies and configurations are properly installed.
    """

    def test_yara_installed(self):
        """Verify yara-python is installed and can compile a basic rule."""
        try:
            import yara
            rule = yara.compile(source='rule dummy { condition: true }')
            self.assertIsNotNone(rule, "YARA failed to compile a dummy rule.")
        except ImportError:
            self.fail("yara-python is not installed.")
        except Exception as e:
            self.fail(f"YARA failed with exception: {e}")

    def test_oletools_installed(self):
        """Verify oletools is installed for Macro parsing."""
        try:
            from oletools.olevba import VBA_Parser
            self.assertTrue(True)
        except ImportError:
            self.fail("oletools is not installed. File scanner won't catch macros.")

    def test_pefile_installed(self):
        """Verify pefile is installed for Windows executable parsing."""
        try:
            import pefile
            self.assertTrue(True)
        except ImportError:
            self.fail("pefile is not installed. File scanner won't analyze executables deeply.")

    def test_playwright_installed(self):
        """Verify Playwright API is importable."""
        try:
            from playwright.sync_api import sync_playwright
            self.assertTrue(True)
        except ImportError:
            self.fail("playwright is not installed. DOM Verification will fail.")

    def test_virustotal_config(self):
        """Verify VirusTotal API key is configured."""
        try:
            from config import VirusTotalConfig
            self.assertTrue(hasattr(VirusTotalConfig, 'API_KEY'), "API_KEY missing in VirusTotalConfig.")
            self.assertNotEqual(VirusTotalConfig.API_KEY, "", "VirusTotal API key is empty.")
            self.assertNotEqual(VirusTotalConfig.API_KEY, "YOUR_API_KEY_HERE", "VirusTotal API key is set to default placeholder.")
        except ImportError:
            self.fail("Failed to import config.VirusTotalConfig.")

    def test_crypto_blocklist_reachable(self):
        """Verify the Crypto Miner blocklist is reachable."""
        from scanner.crypto_detector import CryptoDetector
        detector = CryptoDetector()
        self.assertGreater(len(detector.mining_domains), 1000, "Failed to load crypto blocklist properly.")
        self.assertTrue(detector.is_mining_domain("wss://supportxmr.com/"), "Failed to detect known mining pool in blocklist.")

if __name__ == '__main__':
    unittest.main()
