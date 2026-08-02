import unittest
import sys
import os
import tempfile
import random
import string

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.file_scanner import FileScanner, ThreatLevel

class TestFileScanner(unittest.TestCase):
    """
    Accuracy Tests for the File Virus Scanner.
    Implements a Positive/Negative testing methodology.
    """

    @classmethod
    def setUpClass(cls):
        cls.scanner = FileScanner()
        cls.test_dir = tempfile.mkdtemp()

    # --- YARA & SIGNATURE TESTS ---
    def test_eicar_positive(self):
        """Positive Test: EICAR test string MUST be flagged as Malicious."""
        file_path = os.path.join(self.test_dir, "eicar.com")
        with open(file_path, "w") as f:
            f.write(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        
        result = self.scanner.scan_file(file_path)
        self.assertEqual(result.threat_level, ThreatLevel.MALICIOUS, "Failed to detect EICAR signature.")
        self.assertGreater(result.threats[0].confidence, 0.9)

    def test_eicar_negative(self):
        """Negative Test: Normal text file MUST NOT be flagged."""
        file_path = os.path.join(self.test_dir, "normal.txt")
        with open(file_path, "w") as f:
            f.write("This is just a regular text file with completely benign content.")
            
        result = self.scanner.scan_file(file_path)
        self.assertEqual(result.threat_level, ThreatLevel.CLEAN, "False positive triggered on normal text file.")

    # --- MACRO / SCRIPT TESTS ---
    def test_vbs_macro_positive(self):
        """Positive Test: Malicious VBScript dropping a shell MUST be flagged."""
        file_path = os.path.join(self.test_dir, "dropper.vbs")
        with open(file_path, "w") as f:
            f.write('Set objShell = CreateObject("WScript.Shell")\n')
            f.write('objShell.Run "cmd.exe /c calc.exe", 0, True\n')
            
        result = self.scanner.scan_file(file_path)
        self.assertIn(result.threat_level, [ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS], "Failed to detect malicious VBScript pattern.")

    def test_vbs_macro_negative(self):
        """Negative Test: Benign VBScript doing basic logic MUST NOT be flagged."""
        file_path = os.path.join(self.test_dir, "hello.vbs")
        with open(file_path, "w") as f:
            f.write('WScript.Echo "Hello, this is just a normal message."\n')
            
        result = self.scanner.scan_file(file_path)
        
        # It's a .vbs file so it gets a "Suspicious Extension" warning, but we must ensure it's not flagged for actual VBScript content
        malicious_vbs_flagged = any("VBScript Threat" in t.category for t in result.threats)
        self.assertFalse(malicious_vbs_flagged, "False positive triggered on benign VBScript content.")

    # --- PE / ENTROPY TESTS ---
    def test_high_entropy_positive(self):
        """Positive Test: Very high entropy file (packed/encrypted payload simulation) MUST be flagged as Suspicious."""
        file_path = os.path.join(self.test_dir, "packed.bin")
        with open(file_path, "wb") as f:
            f.write(os.urandom(1024 * 50)) # 50 KB of pure random data (entropy ~ 7.99)
            
        result = self.scanner.scan_file(file_path)
        # Should flag for entropy
        entropy_flagged = any("Entropy" in t.category for t in result.threats)
        self.assertTrue(entropy_flagged, "Failed to flag high entropy (packed) file.")

    def test_low_entropy_negative(self):
        """Negative Test: Low entropy text file MUST NOT be flagged for entropy."""
        file_path = os.path.join(self.test_dir, "low_entropy.txt")
        with open(file_path, "w") as f:
            f.write("A" * 50000) # 50 KB of same character (entropy ~ 0.0)
            
        result = self.scanner.scan_file(file_path)
        entropy_flagged = any("Entropy" in t.category for t in result.threats)
        self.assertFalse(entropy_flagged, "False positive triggered on low entropy file.")

    # --- ARCHIVE BOMB TESTS ---
    def test_archive_bomb_positive(self):
        """Positive Test: Simulate a highly compressed archive bomb structure."""
        file_path = os.path.join(self.test_dir, "bomb.zip")
        with open(file_path, "wb") as f:
            import struct
            # Fake a ZIP local file header with extreme compression ratio
            header = b"PK\x03\x04" + (b"\x00" * 14) 
            compressed = 10     # 10 bytes compressed
            uncompressed = 1000000000  # 1GB uncompressed (ratio 100M:1)
            header += struct.pack("<I", compressed)
            header += struct.pack("<I", uncompressed)
            header += (b"\x00" * 4) # Name len, extra len
            f.write(header)
            # Add padding data so len(content) > 30 bytes
            f.write(b"Z" * 100)
            
        result = self.scanner.scan_file(file_path)
        bomb_flagged = any("Archive Bomb" in t.category for t in result.threats)
        self.assertTrue(bomb_flagged, "Failed to detect archive bomb structure.")

if __name__ == '__main__':
    unittest.main()
