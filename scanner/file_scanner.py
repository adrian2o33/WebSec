"""
File Virus Scanner Module
Scans uploaded files for malware indicators using:
- Signature/hash matching
- Dangerous file extension detection
- Content pattern analysis (scripts, macros, shellcode)
- Entropy analysis (packed/encrypted malware)
- Embedded URL/IP extraction
- PE header analysis (executables)
"""
import os
import sys
import hashlib
import re
import struct
import time
import math
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

try:
    import yara
except ImportError:
    yara = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    VBA_Parser = None

logger = logging.getLogger(__name__)

# Try to import ML model
try:
    from scanner.ml_file import predict_threat, extract_features
except ImportError:
    predict_threat = None
    extract_features = None


class ThreatLevel(Enum):
    CLEAN = "Clean"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"


@dataclass
class FileThreat:
    """Represents a single threat indicator found in a file."""
    category: str          # e.g., "Malicious Pattern", "Suspicious Extension"
    description: str
    severity: str          # "Critical", "High", "Medium", "Low", "Info"
    evidence: str = ""
    confidence: float = 0.0


@dataclass
class FileScanResult:
    """Result of scanning a single file."""
    filename: str
    file_size: int
    file_hash_md5: str
    file_hash_sha256: str
    file_type: str
    scan_time: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    threats: List[FileThreat] = field(default_factory=list)
    entropy: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            "filename": self.filename,
            "file_size": self.file_size,
            "file_size_human": self._human_size(self.file_size),
            "file_hash_md5": self.file_hash_md5,
            "file_hash_sha256": self.file_hash_sha256,
            "file_type": self.file_type,
            "scan_time": round(self.scan_time, 3),
            "threat_level": self.threat_level.value,
            "threats": [
                {
                    "category": t.category,
                    "description": t.description,
                    "severity": t.severity,
                    "evidence": t.evidence[:300],
                    "confidence": round(t.confidence, 2),
                }
                for t in self.threats
            ],
            "threat_count": len([t for t in self.threats if t.severity != "Info"]),
            "entropy": round(self.entropy, 2),
            "timestamp": self.timestamp,
        }

    @staticmethod
    def _human_size(size_bytes):
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"


# === Known patterns for malware detection ===

# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    # Executables
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".msi", ".dll",
    ".sys", ".drv", ".cpl", ".ocx",
    # Scripts
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
    ".psd1", ".ps1xml", ".ps2", ".hta",
    # Office macros
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    # Archives (can contain malware)
    ".jar", ".iso", ".img",
    # Shortcuts
    ".lnk", ".url", ".scf",
}

MODERATE_RISK_EXTENSIONS = {
    ".doc", ".xls", ".ppt", ".rtf", ".pdf",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".py", ".rb", ".pl", ".sh", ".bash",
}

# Malicious content patterns (for script/text files)
MALICIOUS_PATTERNS = [
    # PowerShell threats
    {
        "pattern": rb"(?i)(?:\bInvoke-Expression\b|\bIEX\b|\bInvoke-WebRequest\b|\bInvoke-Shellcode\b|"
                   rb"\bStart-Process\b|New-Object\s+Net\.WebClient|\bDownloadString\b|"
                   rb"\bDownloadFile\b|System\.Reflection\.Assembly|"
                   rb"\[System\.Convert\]::FromBase64String)",
        "category": "PowerShell Threat",
        "description": "Suspicious PowerShell command detected (download/execute pattern)",
        "severity": "Critical",
        "confidence": 0.85,
    },
    # VBScript / WScript threats
    {
        "pattern": rb"(?i)(?:WScript\.Shell|Shell\.Application|"
                   rb"Scripting\.FileSystemObject|ADODB\.Stream|"
                   rb"Microsoft\.XMLHTTP|CreateObject\s*\(\s*[\"'](?:WScript|Shell|Scripting))",
        "category": "VBScript Threat",
        "description": "Suspicious VBScript/WScript COM object usage detected",
        "severity": "High",
        "confidence": 0.80,
    },
    # Shell script threats
    {
        "pattern": rb"(?i)(?:curl\s+.*?\|\s*(?:bash|sh)|wget\s+.*?&&\s*(?:chmod|bash|sh)|"
                   rb"base64\s+-d\s*\|\s*(?:bash|sh)|eval\s*\$\(|"
                   rb"/dev/tcp/|nc\s+-[elp]|ncat\s+-|mkfifo\s+/tmp)",
        "category": "Shell Script Threat",
        "description": "Suspicious shell command (remote execution / reverse shell pattern)",
        "severity": "Critical",
        "confidence": 0.85,
    },
    # Batch file threats  
    {
        "pattern": rb"(?i)(?:reg\s+(?:add|delete).*?\\\\Run|"
                   rb"schtasks\s+/create|"
                   rb"bitsadmin\s+/transfer|"
                   rb"certutil\s+-(?:decode|urlcache)|"
                   rb"powershell\s+-(?:enc|e|ep|nop|w\s+hidden))",
        "category": "Batch Script Threat",
        "description": "Suspicious batch commands (persistence/download technique)",
        "severity": "High",
        "confidence": 0.80,
    },
    # JavaScript threats (Node.js / standalone)
    {
        "pattern": rb"(?i)(?:child_process|require\s*\(\s*['\"](?:fs|net|http|child_process)['\"]|"
                   rb"eval\s*\(\s*(?:atob|Buffer\.from|unescape)\s*\(|"
                   rb"new\s+Function\s*\(\s*(?:atob|unescape)|"
                   rb"process\.env|__dirname.*?exec)",
        "category": "JavaScript Threat",
        "description": "Suspicious JavaScript with system access or obfuscated execution",
        "severity": "High",
        "confidence": 0.75,
    },
    # Python threats
    {
        "pattern": rb"(?i)(?:import\s+(?:subprocess|os|socket|ctypes|shutil).*?"
                   rb"(?:subprocess\.(?:call|Popen|run)|os\.system|os\.popen|"
                   rb"socket\.connect|exec\s*\(|eval\s*\(.*?compile))",
        "category": "Python Threat",
        "description": "Python script with suspicious system calls or code execution",
        "severity": "Medium",
        "confidence": 0.60,
    },
    # Macro indicators in Office XML
    {
        "pattern": rb"(?i)(?:AutoOpen|Auto_Open|AutoExec|AutoClose|"
                   rb"Document_Open|Workbook_Open|"
                   rb"Shell\s*\(|CreateObject|GetObject|CallByName)",
        "category": "Office Macro Threat",
        "description": "Suspicious Office macro with auto-execution or shell access",
        "severity": "High",
        "confidence": 0.80,
    },
    # Generic obfuscation
    {
        "pattern": rb"(?:(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)",
        "category": "Obfuscation",
        "description": "Large Base64-encoded block detected (may hide malicious payload)",
        "severity": "Medium",
        "confidence": 0.50,
    },
    # Embedded IP addresses (C2 indicators)
    {
        "pattern": rb"(?:\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
                   rb":(?:4444|1337|31337|8080|8888|9999)\b",
        "category": "Network Indicator",
        "description": "Embedded IP address with suspicious port (potential C2 communication)",
        "severity": "Medium",
        "confidence": 0.65,
    },
    # Suspicious URLs downloading executables/scripts
    {
        "pattern": rb"(?i)https?://[a-z0-9.-]+/[^\s\"'<>]+\.(?:exe|dll|vbs|ps1|bat|sh|bin)\b",
        "category": "Malware Download Link",
        "description": "External URL pointing directly to a potentially malicious payload",
        "severity": "High",
        "confidence": 0.85,
    },
]

# PE (Portable Executable) suspicious characteristics
PE_SUSPICIOUS_SECTIONS = [b".upx", b".aspack", b".petite", b".mew", b".yoda",
                           b".nsp", b".themida", b".vmp"]

# Known malware hashes (small sample for demo — in production use VirusTotal API)
KNOWN_MALWARE_HASHES = {
    # EICAR test file
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad": "EICAR-Test-File (ZIP)",
    "3306db7c1340b35fb33ffca52086ca29": "EICAR-Test-File (ZIP MD5)",
}


class FileScanner:
    """Scans files for malware indicators."""

    def __init__(self):
        self._compiled_patterns = []
        for entry in MALICIOUS_PATTERNS:
            try:
                compiled = re.compile(entry["pattern"], re.DOTALL)
                self._compiled_patterns.append({
                    "regex": compiled,
                    "category": entry["category"],
                    "description": entry["description"],
                    "severity": entry["severity"],
                    "confidence": entry["confidence"],
                })
            except re.error as e:
                logger.error(f"Failed to compile pattern: {e}")
        try:
            from scanner.yara_scanner import YaraScanner
            self.yara_scanner = YaraScanner()
        except Exception as e:
            logger.error(f"Failed to initialize YaraScanner: {e}")
            self.yara_scanner = None

    def scan_file(self, filepath: str, enable_vt: bool = False, enable_ml: bool = False) -> FileScanResult:
        """Scan a single file and return results."""
        import time
        start = time.time()

        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)

        # Read file content
        with open(filepath, "rb") as f:
            content = f.read()

        # Calculate hashes
        md5 = hashlib.md5(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()

        # Determine file type
        file_type = self._detect_file_type(content, filename)

        result = FileScanResult(
            filename=filename,
            file_size=file_size,
            file_hash_md5=md5,
            file_hash_sha256=sha256,
            file_type=file_type,
        )

        # Run all checks
        threats = []
        threats.extend(self._check_known_hashes(md5, sha256))
        threats.extend(self._check_extension(filename))
        threats.extend(self._check_entropy(content, filename))
        threats.extend(self._check_patterns(content, filepath))
        threats.extend(self._check_pe_header(content))
        threats.extend(self._check_embedded_executables(content))
        threats.extend(self._check_archive_bombs(content, file_size))
        threats.extend(self._check_pdf(content, filepath))
        
        # YARA scanning
        if self.yara_scanner:
            try:
                threats.extend(self.yara_scanner.scan_file_content(content, filename))
            except Exception as e:
                logger.debug(f"YARA scan error: {e}")
                
        threats.extend(self._check_macros(content, filepath))

        # Check VirusTotal
        if enable_vt:
            try:
                from scanner.virustotal import VirusTotalClient
                from config import VirusTotalConfig
                if VirusTotalConfig.ENABLED:
                    vt_client = VirusTotalClient(VirusTotalConfig.API_KEY)
                    vt_res = vt_client.scan_hash(sha256)
                    if vt_res and vt_res.get('detected'):
                        threats.append(FileThreat(
                            category="Known Malware (VirusTotal)",
                            description=f"File is flagged by {vt_res.get('detection_ratio')} antivirus engines on VirusTotal.",
                            severity="Critical",
                            evidence=f"VirusTotal Report: {vt_res.get('permalink')}",
                            confidence=0.95
                        ))
            except Exception as e:
                logger.error(f"VirusTotal file scan failed: {e}")

        # ML processing
        is_text_content = self._is_text_content(content)
        if enable_ml and predict_threat and extract_features:
            max_sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            max_sev = max((max_sev_map.get(t.severity, 0) for t in threats), default=0)
            
            printable_char_ratio = sum(1 for b in content[:10000] if 32 <= b <= 126 or b in (9, 10, 13)) / max(len(content[:10000]), 1)
            has_pe_header = content.startswith(b"MZ")
            ext = os.path.splitext(filepath)[1].lower()
            is_office_doc = ext in [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dotm"] or content.startswith((b"\xd0\xcf\x11\xe0", b"PK\x03\x04"))
            
            features = extract_features(file_size, self._calculate_entropy(content), len(threats), max_sev, is_text_content, printable_char_ratio, has_pe_header, is_office_doc)
            is_mal, proba = predict_threat(features)
            if is_mal:
                threats.append(FileThreat(
                    category="Machine Learning Detection",
                    description=f"Our AI model predicts this file behaves like malware based on its structural features.",
                    severity="Critical" if proba > 0.8 else "High",
                    evidence=f"ML Confidence Score: {proba:.2f}",
                    confidence=proba
                ))

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        threats.sort(key=lambda t: (severity_order.get(t.severity, 5), -t.confidence))
        
        result.threats = threats
        result.entropy = self._calculate_entropy(content)
        result.scan_time = time.time() - start

        # Determine overall threat level
        if any(t.severity == "Critical" for t in threats):
            result.threat_level = ThreatLevel.MALICIOUS
        elif any(t.severity in ("High", "Medium") for t in threats):
            if any(t.confidence >= 0.7 for t in threats if t.severity in ("High", "Medium")):
                result.threat_level = ThreatLevel.MALICIOUS
            else:
                result.threat_level = ThreatLevel.SUSPICIOUS
        else:
            result.threat_level = ThreatLevel.CLEAN

        return result

    def _check_known_hashes(self, md5: str, sha256: str) -> List[FileThreat]:
        """Check file hash against known malware database."""
        threats = []
        if md5 in KNOWN_MALWARE_HASHES:
            threats.append(FileThreat(
                category="Known Malware",
                description=f"File matches known malware signature: {KNOWN_MALWARE_HASHES[md5]}",
                severity="Critical",
                evidence=f"MD5: {md5}",
                confidence=1.0,
            ))
        if sha256 in KNOWN_MALWARE_HASHES:
            threats.append(FileThreat(
                category="Known Malware",
                description=f"File matches known malware signature: {KNOWN_MALWARE_HASHES[sha256]}",
                severity="Critical",
                evidence=f"SHA256: {sha256}",
                confidence=1.0,
            ))
        return threats

    def _check_extension(self, filename: str) -> List[FileThreat]:
        """Check file extension for known dangerous types."""
        threats = []
        ext = os.path.splitext(filename)[1].lower()

        # Double extension trick (e.g., document.pdf.exe)
        parts = filename.split(".")
        is_spoofed = False
        if len(parts) > 2:
            real_ext = "." + parts[-1].lower()
            fake_ext = "." + parts[-2].lower()
            if real_ext in DANGEROUS_EXTENSIONS and fake_ext not in DANGEROUS_EXTENSIONS:
                threats.append(FileThreat(
                    category="Extension Spoofing",
                    description=f"File uses double extension trick: appears as {fake_ext} "
                                f"but is actually {real_ext}",
                    severity="Critical",
                    evidence=f"Filename: {filename}",
                    confidence=0.90,
                ))
                is_spoofed = True

        # Only add generic extension alerts if it wasn't already caught as a targeted spoofing attack
        if not is_spoofed:
            if ext in DANGEROUS_EXTENSIONS:
                threats.append(FileThreat(
                    category="Dangerous File Type",
                    description=f"File has a dangerous extension ({ext}). "
                                f"This file type is commonly associated with malware.",
                    severity="High",
                    evidence=f"Extension: {ext}",
                    confidence=0.6,
                ))
            elif ext in MODERATE_RISK_EXTENSIONS:
                threats.append(FileThreat(
                    category="Moderate Risk File Type",
                    description=f"File type ({ext}) can contain embedded malware or macros.",
                    severity="Info",
                    evidence=f"Extension: {ext}",
                    confidence=0.3,
                ))

        return threats

    def _check_entropy(self, content: bytes, filename: str) -> List[FileThreat]:
        """Check file entropy — high entropy suggests encryption/packing."""
        threats = []
        if len(content) < 256:
            return threats

        entropy = self._calculate_entropy(content)

        ext = os.path.splitext(filename)[1].lower()
        # Packed/encrypted executables have very high entropy
        if ext in (".exe", ".dll", ".sys", ".scr") and entropy > 7.2:
            threats.append(FileThreat(
                category="Packed/Encrypted",
                description=f"Executable has unusually high entropy ({entropy:.2f}/8.0), "
                            f"suggesting it may be packed or encrypted to evade detection.",
                severity="High",
                evidence=f"Entropy: {entropy:.2f} (threshold: 7.2)",
                confidence=0.70,
            ))
        elif ext not in (".zip", ".rar", ".7z", ".gz", ".png", ".jpg", ".mp4", ".mp3", ".pdf", ".docx", ".xlsx", ".pptx"):
            # Non-archive, non-media files with high entropy
            if entropy > 7.5:
                threats.append(FileThreat(
                    category="High Entropy",
                    description=f"File has very high entropy ({entropy:.2f}/8.0), "
                                f"possibly encrypted or containing embedded binary data.",
                    severity="Medium",
                    evidence=f"Entropy: {entropy:.2f}",
                    confidence=0.50,
                ))

        return threats

    def _check_patterns(self, content: bytes, filename: str) -> List[FileThreat]:
        """Check file content against malicious patterns."""
        threats = []
        # Only scan text-like content (skip pure binary unless it's small)
        is_text = self._is_text_content(content)
        ext = os.path.splitext(filename)[1].lower() if filename else ""

        for entry in self._compiled_patterns:
            try:
                if entry["category"] == "Obfuscation":
                    if not is_text:
                        continue
                    # HTML/JSON/XML/PDF often have legitimate base64 images or compressed streams
                    if ext in [".html", ".json", ".xml", ".css", ".pdf", ".svg"] and entry["severity"] == "Medium":
                        continue

                if entry["category"] == "Office Macro Threat":
                    if ext not in [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dotm", ".vbs", ".xml"] and filename != "macro.vbs":
                        continue

                matches = entry["regex"].findall(content[:500_000])  # Limit scan size
                if matches:
                    match_sample = matches[0] if isinstance(matches[0], bytes) else matches[0]
                    try:
                        evidence = match_sample[:200].decode("utf-8", errors="replace")
                    except Exception:
                        evidence = str(match_sample[:200])

                    threats.append(FileThreat(
                        category=entry["category"],
                        description=entry["description"],
                        severity=entry["severity"],
                        evidence=f"Match: {evidence}",
                        confidence=entry["confidence"],
                    ))
            except Exception as e:
                logger.debug(f"Pattern check error: {e}")

        return threats

    def _check_pe_header(self, content: bytes) -> List[FileThreat]:
        """Analyse PE (Windows executable) headers for suspicious indicators."""
        threats = []
        if len(content) < 64 or content[:2] != b"MZ":
            return threats

        try:
            # Get PE header offset
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            if pe_offset + 4 > len(content) or content[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return threats

            # Check for suspicious section names (packed)
            # Section table starts after optional header
            coff_header = pe_offset + 4
            num_sections = struct.unpack_from("<H", content, coff_header + 2)[0]
            opt_header_size = struct.unpack_from("<H", content, coff_header + 16)[0]
            section_table = coff_header + 20 + opt_header_size

            for i in range(min(num_sections, 20)):
                sec_offset = section_table + (i * 40)
                if sec_offset + 40 > len(content):
                    break
                sec_name = content[sec_offset:sec_offset + 8].rstrip(b"\x00").lower()

                for suspicious in PE_SUSPICIOUS_SECTIONS:
                    if suspicious in sec_name:
                        threats.append(FileThreat(
                            category="Packed Executable",
                            description=f"PE section '{sec_name.decode('ascii', errors='replace')}' "
                                        f"indicates the executable is packed with a known packer.",
                            severity="High",
                            evidence=f"Section: {sec_name.decode('ascii', errors='replace')}",
                            confidence=0.75,
                        ))
                        break

            # Check for no import table (suspicious for PE files)
            # This is a simplified check
            if b"kernel32.dll" not in content.lower() and b"msvcrt" not in content.lower():
                threats.append(FileThreat(
                    category="Suspicious PE",
                    description="PE file has no standard Windows API imports, possibly packed or obfuscated.",
                    severity="Medium",
                    evidence="Missing kernel32.dll or msvcrt imports",
                    confidence=0.55,
                ))

        except Exception as e:
            logger.debug(f"PE analysis error: {e}")

        return threats

    def _check_macros(self, content: bytes, filepath: str) -> List[FileThreat]:
        """Use oletools to extract and analyze VBA macros."""
        threats = []
        if not VBA_Parser:
            return threats
            
        ext = os.path.splitext(filepath)[1].lower()
        office_exts = [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".dotm"]
        # Only scan if it's an office extension or has OLE/ZIP magic bytes
        if ext not in office_exts and not content.startswith((b"\xd0\xcf\x11\xe0", b"PK\x03\x04")):
            return threats

        try:
            vbaparser = VBA_Parser(filepath, data=content)
            if vbaparser.detect_vba_macros():
                macro_code = ""
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    macro_code += vba_code + "\n"
                
                # Check macro code using the regex engine for better granularity
                # Create a temporary file object or just run patterns
                macro_threats = self._check_patterns(macro_code.encode('utf-8', 'ignore'), "macro.vbs")
                for t in macro_threats:
                    t.category = "Office Macro Threat"
                    t.severity = "Critical" if t.severity in ("High", "Critical") else "High"
                    threats.append(t)
                
                if not threats:
                    # If it has macros but no specific bad patterns matched, still warn
                    threats.append(FileThreat(
                        category="Office Macro Presence",
                        description="File contains VBA macros. While not explicitly malicious, macros are a common vector for malware.",
                        severity="Low",
                        evidence="VBA macros extracted via oletools.",
                        confidence=0.5
                    ))
            vbaparser.close()
        except Exception as e:
            logger.debug(f"VBA macro parsing failed: {e}")

        return threats

    def _check_pdf(self, content: bytes, filepath: str) -> List[FileThreat]:
        """Parse PDF to detect malicious embedded JavaScript or OpenActions."""
        threats = []
        ext = os.path.splitext(filepath)[1].lower()
        if ext != ".pdf" and not content.startswith(b"%PDF"):
            return threats

        # Simple heuristic: scan raw bytes for common malicious keys
        if b"/JavaScript" in content or b"/JS" in content:
            threats.append(FileThreat(
                category="PDF Threat",
                description="PDF contains embedded JavaScript. This is often used in drive-by downloads or malicious phishing.",
                severity="High",
                evidence="Detected /JavaScript or /JS objects within the PDF structure.",
                confidence=0.85
            ))
        
        if b"/OpenAction" in content or b"/AA" in content:
            threats.append(FileThreat(
                category="PDF Threat",
                description="PDF contains automatic execution actions (OpenAction/AA).",
                severity="Medium",
                evidence="Detected /OpenAction or /AA (Additional Actions) elements.",
                confidence=0.75
            ))

        try:
            import PyPDF2
            import io
            
            # Use PyPDF2 to read the PDF stream safely to verify it's a valid PDF
            pdf_file = io.BytesIO(content)
            reader = PyPDF2.PdfReader(pdf_file)
            
            # Additional structural checks could go here using `reader`
            
        except Exception as e:
            logger.debug(f"PDF parsing error: {e}")

        return threats

    def _check_embedded_executables(self, content: bytes) -> List[FileThreat]:
        """Check for executables embedded inside non-executable files."""
        threats = []
        # Look for MZ header inside non-PE files
        if content[:2] != b"MZ":  # Only check if the file itself is not a PE
            pos = 0
            count = 0
            while True:
                idx = content.find(b"MZ", pos + 2)
                if idx == -1 or idx + 64 > len(content):
                    break
                # Verify it's a real PE
                try:
                    pe_offset = struct.unpack_from("<I", content, idx + 0x3C)[0]
                    if (idx + pe_offset + 4 <= len(content) and
                            content[idx + pe_offset:idx + pe_offset + 4] == b"PE\x00\x00"):
                        count += 1
                except Exception:
                    pass
                pos = idx + 2
                if count >= 3:
                    break

            if count > 0:
                threats.append(FileThreat(
                    category="Embedded Executable",
                    description=f"Found {count} embedded PE executable(s) inside this file. "
                                f"This is often used to hide malware inside documents.",
                    severity="Critical" if count > 1 else "High",
                    evidence=f"{count} embedded PE file(s) detected",
                    confidence=0.80,
                ))

        return threats

    def _check_archive_bombs(self, content: bytes, file_size: int) -> List[FileThreat]:
        """Check for zip bomb indicators."""
        threats = []
        if content[:2] == b"PK":
            # Check compression ratio by looking at local file headers
            try:
                pos = 0
                while pos + 30 < len(content) and pos < 10000:
                    if content[pos:pos + 4] != b"PK\x03\x04":
                        break
                    compressed = struct.unpack_from("<I", content, pos + 18)[0]
                    uncompressed = struct.unpack_from("<I", content, pos + 22)[0]
                    if compressed > 0 and uncompressed > 0:
                        ratio = uncompressed / compressed
                        if ratio > 100:
                            threats.append(FileThreat(
                                category="Archive Bomb",
                                description=f"Extreme compression ratio ({ratio:.0f}:1) detected. "
                                            f"This could be a zip bomb designed to crash scanners.",
                                severity="High",
                                evidence=f"Compressed: {compressed} bytes, "
                                         f"Uncompressed: {uncompressed} bytes",
                                confidence=0.70,
                            ))
                            break
                    name_len = struct.unpack_from("<H", content, pos + 26)[0]
                    extra_len = struct.unpack_from("<H", content, pos + 28)[0]
                    pos += 30 + name_len + extra_len + compressed
            except Exception:
                pass

        return threats

    @staticmethod
    def _detect_file_type(content: bytes, filename: str) -> str:
        """Detect file type from magic bytes."""
        magic_bytes = {
            b"MZ": "Windows Executable (PE)",
            b"\x7fELF": "Linux Executable (ELF)",
            b"PK\x03\x04": "ZIP Archive",
            b"PK\x05\x06": "ZIP Archive (empty)",
            b"\x1f\x8b": "GZIP Archive",
            b"Rar!\x1a\x07": "RAR Archive",
            b"7z\xbc\xaf": "7-Zip Archive",
            b"\x89PNG": "PNG Image",
            b"\xff\xd8\xff": "JPEG Image",
            b"GIF87a": "GIF Image",
            b"GIF89a": "GIF Image",
            b"%PDF": "PDF Document",
            b"\xd0\xcf\x11\xe0": "Microsoft Office (OLE2)",
            b"<!DOCTYPE": "HTML Document",
            b"<html": "HTML Document",
            b"<?xml": "XML Document",
            b"#!/": "Script (shebang)",
        }
        for magic, ftype in magic_bytes.items():
            if content[:len(magic)] == magic:
                return ftype

        ext = os.path.splitext(filename)[1].lower()
        ext_types = {
            ".py": "Python Script", ".js": "JavaScript",
            ".ps1": "PowerShell Script", ".bat": "Batch Script",
            ".cmd": "Batch Script", ".vbs": "VBScript",
            ".sh": "Shell Script", ".rb": "Ruby Script",
            ".pl": "Perl Script", ".php": "PHP Script",
            ".txt": "Text File", ".csv": "CSV File",
            ".json": "JSON File", ".xml": "XML File",
            ".html": "HTML Document", ".css": "CSS File",
            ".docx": "Word Document", ".xlsx": "Excel Spreadsheet",
            ".pptx": "PowerPoint", ".iso": "Disk Image",
        }
        return ext_types.get(ext, "Unknown")

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_text_content(content: bytes) -> bool:
        """Check if content appears to be text (not binary)."""
        if len(content) == 0:
            return True
        # Check first 8KB for null bytes
        sample = content[:8192]
        null_ratio = sample.count(0) / len(sample)
        return null_ratio < 0.05
