"""
Advanced PE Static Analyzer
Performs deep structural analysis of Windows PE executables using the pefile library.

Checks performed:
- Packer signature detection (UPX, Themida, VMProtect, etc.)
- Per-section entropy analysis
- Import Address Table inspection for suspicious API combinations
- Authenticode / digital signature verification
- Suspicious resource detection (embedded PEs, high-entropy RCDATA)
- Structural anomaly detection (alignment, timestamps, checksum, etc.)
"""
import pefile
import os
import math
import logging
import time as _time
from datetime import datetime, timezone
from typing import List, Dict, Optional

from scanner.file_scanner import FileThreat

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known packer section names (lowercased for comparison)
# ---------------------------------------------------------------------------
_PACKER_SECTIONS: Dict[str, str] = {
    ".upx":     "UPX",
    "upx0":     "UPX",
    "upx1":     "UPX",
    "upx2":     "UPX",
    ".aspack":  "ASPack",
    ".adata":   "ASPack",
    ".themida": "Themida",
    ".vmp0":    "VMProtect",
    ".vmp1":    "VMProtect",
    ".vmp2":    "VMProtect",
    ".pec":     "PECompact",
    ".pec2":    "PECompact",
    "pec2":     "PECompact",
    ".mpress":  "MPRESS",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".petite":  "Petite",
    ".mew":     "MEW",
    ".nsp0":    "NSPack",
    ".nsp1":    "NSPack",
    ".nsp2":    "NSPack",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
}

# ---------------------------------------------------------------------------
# Suspicious import groups
# ---------------------------------------------------------------------------
_SUSPICIOUS_IMPORT_GROUPS: List[Dict] = [
    {
        "name": "Process Injection",
        "required": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "severity": "Critical",
        "confidence": 0.90,
        "description": (
            "Imports associated with process injection detected "
            "(VirtualAllocEx + WriteProcessMemory + CreateRemoteThread). "
            "This technique is commonly used by malware to execute code "
            "inside another process."
        ),
    },
    {
        "name": "Keylogging",
        "required": set(),
        "any_of": {"GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
                   "SetWindowsHookEx"},
        "severity": "High",
        "confidence": 0.80,
        "description": (
            "Imports commonly used for keylogging detected. "
            "The binary may be capturing keyboard input."
        ),
    },
    {
        "name": "Crypto / Ransomware",
        "required": set(),
        "any_of": {"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
                   "CryptAcquireContextA", "CryptAcquireContextW"},
        "severity": "High",
        "confidence": 0.70,
        "description": (
            "Cryptographic API imports detected. Combined with other "
            "indicators this may suggest ransomware or data-exfiltration "
            "capabilities."
        ),
    },
    {
        "name": "Network Downloader",
        "required": set(),
        "any_of": {"InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
                   "InternetOpenUrlW", "InternetReadFile", "URLDownloadToFileA",
                   "URLDownloadToFileW"},
        "severity": "Medium",
        "confidence": 0.65,
        "description": (
            "WinINet / URLMon download APIs detected. The binary may "
            "download additional payloads from the internet."
        ),
    },
    {
        "name": "Anti-Debug",
        "required": set(),
        "any_of": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                   "NtQueryInformationProcess", "OutputDebugStringA",
                   "OutputDebugStringW"},
        "severity": "Medium",
        "confidence": 0.70,
        "description": (
            "Anti-debugging API imports detected. Malware commonly uses "
            "these to evade analysis environments."
        ),
    },
    {
        "name": "Registry Persistence",
        "required": set(),
        "any_of": {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                   "RegCreateKeyExW"},
        "severity": "Medium",
        "confidence": 0.60,
        "description": (
            "Registry write APIs detected. These can be used to establish "
            "persistence (e.g. adding entries to Run keys)."
        ),
    },
]


class PEAnalyzer:
    """Performs deep static analysis of Windows PE files using *pefile*."""

    def __init__(self):
        pass

    # ===================================================================
    # Public entry point
    # ===================================================================

    def analyze(self, filepath: str, content: bytes = None) -> List[FileThreat]:
        """Perform deep PE analysis and return a list of :class:`FileThreat` findings.

        Parameters
        ----------
        filepath : str
            Path to the PE file on disk.
        content : bytes, optional
            Raw bytes of the file.  If *None* the file is read from *filepath*.

        Returns
        -------
        list[FileThreat]
            Aggregated threat indicators.  Returns an empty list when the file
            is not a valid PE or cannot be parsed.
        """
        try:
            if content is None:
                with open(filepath, "rb") as fh:
                    content = fh.read()

            pe = pefile.PE(data=content, fast_load=False)
        except pefile.PEFormatError:
            logger.debug("File is not a valid PE: %s", filepath)
            return []
        except Exception as exc:
            logger.warning("Failed to parse PE %s: %s", filepath, exc)
            return []

        threats: List[FileThreat] = []

        # Run each analysis pass, catching per-check failures individually
        for check in (
            self._check_packer_signatures,
            self._check_section_entropy,
            self._check_imports,
            lambda p: self._check_authenticode(p, content),
            self._check_suspicious_resources,
            lambda p: self._check_anomalies(p, content),
        ):
            try:
                threats.extend(check(pe))
            except Exception as exc:
                logger.debug("PE check failed for %s: %s", filepath, exc)

        pe.close()
        return threats

    # ===================================================================
    # 1. Packer signature detection
    # ===================================================================

    def _check_packer_signatures(self, pe: pefile.PE) -> List[FileThreat]:
        """Detect known packer section names and suspicious section flags."""
        threats: List[FileThreat] = []

        for section in pe.sections:
            try:
                sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").lower()
            except Exception:
                sec_name = ""

            # --- known packer name match ---
            for pattern, packer in _PACKER_SECTIONS.items():
                if pattern in sec_name:
                    threats.append(FileThreat(
                        category="Packed Executable",
                        description=(
                            f"Section '{sec_name}' matches known packer signature "
                            f"({packer}).  Packed executables are frequently used to "
                            f"evade antivirus detection."
                        ),
                        severity="High",
                        evidence=f"Section: {sec_name} → Packer: {packer}",
                        confidence=0.80,
                    ))
                    break  # one match per section is enough

            # --- unusual characteristics: high entropy + executable ---
            is_executable = bool(
                section.Characteristics
                & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
            )
            if is_executable and section.SizeOfRawData > 0:
                entropy = section.get_entropy()
                if entropy > 7.0:
                    threats.append(FileThreat(
                        category="Packed Executable",
                        description=(
                            f"Executable section '{sec_name}' has very high entropy "
                            f"({entropy:.2f}/8.0), suggesting it is packed or encrypted."
                        ),
                        severity="High",
                        evidence=f"Section: {sec_name}, Entropy: {entropy:.2f}, Flags: EXECUTE",
                        confidence=0.80,
                    ))

        return threats

    # ===================================================================
    # 2. Per-section entropy analysis
    # ===================================================================

    _EXPECTED_ENTROPY: Dict[str, tuple] = {
        ".text":  (5.5, 6.5),
        ".code":  (5.5, 6.5),
        ".data":  (3.0, 5.0),
        ".rdata": (3.0, 5.5),
        ".rsrc":  (3.0, 6.0),
        ".bss":   (0.0, 1.0),
        ".reloc": (4.0, 6.0),
    }

    def _check_section_entropy(self, pe: pefile.PE) -> List[FileThreat]:
        """Flag sections with anomalously high entropy."""
        threats: List[FileThreat] = []

        for section in pe.sections:
            if section.SizeOfRawData == 0:
                continue

            try:
                sec_name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").lower()
            except Exception:
                sec_name = "unknown"

            entropy = section.get_entropy()

            # --- absolute threshold: near-random data ---
            if entropy > 7.0:
                threats.append(FileThreat(
                    category="High Section Entropy",
                    description=(
                        f"Section '{sec_name}' has near-random entropy ({entropy:.2f}/8.0), "
                        f"strongly suggesting encryption or packing."
                    ),
                    severity="High",
                    evidence=f"Section: {sec_name}, Entropy: {entropy:.2f}",
                    confidence=0.80,
                ))
                continue  # no need for the relative check

            # --- relative threshold: outside expected range for known sections ---
            expected = self._EXPECTED_ENTROPY.get(sec_name)
            if expected:
                low, high = expected
                if entropy > high + 0.8:
                    threats.append(FileThreat(
                        category="Abnormal Section Entropy",
                        description=(
                            f"Section '{sec_name}' has higher entropy ({entropy:.2f}) than "
                            f"expected for its type (normal range: {low:.1f}–{high:.1f}). "
                            f"This may indicate obfuscation."
                        ),
                        severity="Medium",
                        evidence=(
                            f"Section: {sec_name}, Entropy: {entropy:.2f}, "
                            f"Expected: {low:.1f}–{high:.1f}"
                        ),
                        confidence=0.60,
                    ))

        return threats

    # ===================================================================
    # 3. Import Address Table analysis
    # ===================================================================

    def _check_imports(self, pe: pefile.PE) -> List[FileThreat]:
        """Flag suspicious combinations of imported API functions."""
        threats: List[FileThreat] = []

        imported_functions: set = set()
        try:
            if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                )
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                for imp in entry.imports:
                    if imp.name:
                        imported_functions.add(imp.name.decode("ascii", errors="replace"))
        except Exception as exc:
            logger.debug("Could not parse IAT: %s", exc)
            return threats

        for group in _SUSPICIOUS_IMPORT_GROUPS:
            required = group.get("required", set())
            any_of = group.get("any_of", set())

            # "required" means ALL must be present
            required_match = required.issubset(imported_functions) if required else True

            # "any_of" means at least one must be present
            any_match = bool(any_of & imported_functions) if any_of else True

            if required_match and any_match and (required or any_of):
                matched = (required & imported_functions) | (any_of & imported_functions)
                threats.append(FileThreat(
                    category=f"Suspicious Imports – {group['name']}",
                    description=group["description"],
                    severity=group["severity"],
                    evidence=f"Matched APIs: {', '.join(sorted(matched))}",
                    confidence=group["confidence"],
                ))

        return threats

    # ===================================================================
    # 4. Authenticode / digital signature check
    # ===================================================================

    _SECURITY_DIR_INDEX = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]

    def _check_authenticode(self, pe: pefile.PE, content: bytes) -> List[FileThreat]:
        """Check whether the PE carries an Authenticode digital signature."""
        threats: List[FileThreat] = []

        try:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[self._SECURITY_DIR_INDEX]
            has_signature = (security_dir.VirtualAddress != 0 and security_dir.Size != 0)
        except (IndexError, AttributeError):
            has_signature = False

        if has_signature:
            threats.append(FileThreat(
                category="Digital Signature",
                description=(
                    "The PE contains an Authenticode digital signature (IMAGE_DIRECTORY_ENTRY_SECURITY). "
                    "Note: the signature has not been cryptographically verified."
                ),
                severity="Info",
                evidence=f"Security directory VA=0x{security_dir.VirtualAddress:08X}, Size={security_dir.Size}",
                confidence=0.90,
            ))
        else:
            # Only flag non-trivial executables (> 10 KB)
            if len(content) > 10_240:
                threats.append(FileThreat(
                    category="Unsigned Executable",
                    description=(
                        "This PE executable is not digitally signed. Legitimate "
                        "software is typically signed by the publisher."
                    ),
                    severity="Medium",
                    evidence="No IMAGE_DIRECTORY_ENTRY_SECURITY present",
                    confidence=0.50,
                ))

        return threats

    # ===================================================================
    # 5. Suspicious resources
    # ===================================================================

    _LARGE_RESOURCE_THRESHOLD = 1 * 1024 * 1024  # 1 MB

    def _check_suspicious_resources(self, pe: pefile.PE) -> List[FileThreat]:
        """Inspect the PE resource directory for embedded payloads."""
        threats: List[FileThreat] = []

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return threats

        try:
            self._walk_resources(pe, pe.DIRECTORY_ENTRY_RESOURCE, threats)
        except Exception as exc:
            logger.debug("Resource walk error: %s", exc)

        return threats

    def _walk_resources(
        self,
        pe: pefile.PE,
        resource_dir,
        threats: List[FileThreat],
        depth: int = 0,
    ) -> None:
        """Recursively walk the resource tree."""
        if depth > 5:
            return

        RT_RCDATA = pefile.RESOURCE_TYPE.get("RT_RCDATA", 10)  # type: ignore[arg-type]

        for entry in resource_dir.entries:
            if hasattr(entry, "directory"):
                self._walk_resources(pe, entry.directory, threats, depth + 1)

            elif hasattr(entry, "data"):
                res_data_entry = entry.data
                try:
                    offset = res_data_entry.struct.OffsetToData
                    size = res_data_entry.struct.Size
                except AttributeError:
                    continue

                # --- Embedded executable (MZ header) ---
                try:
                    data = pe.get_data(offset, min(size, 4096))
                    if data[:2] == b"MZ":
                        threats.append(FileThreat(
                            category="Embedded PE in Resource",
                            description=(
                                f"A resource at RVA 0x{offset:08X} (size {size:,} bytes) "
                                f"starts with an MZ header, indicating an embedded executable."
                            ),
                            severity="High",
                            evidence=f"RVA: 0x{offset:08X}, Size: {size}",
                            confidence=0.85,
                        ))
                except Exception:
                    data = b""

                # --- Very large resource ---
                if size > self._LARGE_RESOURCE_THRESHOLD:
                    threats.append(FileThreat(
                        category="Large Resource Payload",
                        description=(
                            f"Resource at RVA 0x{offset:08X} is {size / (1024 * 1024):.1f} MB. "
                            f"Very large resources can conceal embedded payloads."
                        ),
                        severity="Medium",
                        evidence=f"RVA: 0x{offset:08X}, Size: {size:,} bytes",
                        confidence=0.60,
                    ))

                # --- RT_RCDATA with high entropy ---
                is_rcdata = False
                try:
                    # Walk up to determine the resource type id
                    parent = resource_dir
                    if hasattr(parent, "entries") and parent.entries:
                        first = parent.entries[0]
                        if hasattr(first, "id") and first.id == RT_RCDATA:
                            is_rcdata = True
                except Exception:
                    pass

                if is_rcdata and len(data) > 256:
                    entropy = self._calculate_entropy(data)
                    if entropy > 7.0:
                        threats.append(FileThreat(
                            category="Suspicious RCDATA Resource",
                            description=(
                                f"RT_RCDATA resource at RVA 0x{offset:08X} has very high "
                                f"entropy ({entropy:.2f}/8.0), suggesting encrypted or "
                                f"compressed payload data."
                            ),
                            severity="High",
                            evidence=f"RVA: 0x{offset:08X}, Entropy: {entropy:.2f}",
                            confidence=0.75,
                        ))

    # ===================================================================
    # 6. Structural anomalies
    # ===================================================================

    def _check_anomalies(self, pe: pefile.PE, content: bytes) -> List[FileThreat]:
        """Detect structural anomalies in the PE header."""
        threats: List[FileThreat] = []

        # --- File / section alignment mismatch ---
        try:
            file_align = pe.OPTIONAL_HEADER.FileAlignment
            section_align = pe.OPTIONAL_HEADER.SectionAlignment
            if file_align == 0 or (file_align & (file_align - 1)):
                threats.append(FileThreat(
                    category="PE Anomaly",
                    description=(
                        f"FileAlignment ({file_align}) is not a power of two, "
                        f"which violates the PE specification."
                    ),
                    severity="Medium",
                    evidence=f"FileAlignment: {file_align}",
                    confidence=0.70,
                ))
            if section_align < file_align:
                threats.append(FileThreat(
                    category="PE Anomaly",
                    description=(
                        f"SectionAlignment ({section_align}) is smaller than "
                        f"FileAlignment ({file_align}), indicating a malformed PE."
                    ),
                    severity="Medium",
                    evidence=f"SectionAlignment: {section_align}, FileAlignment: {file_align}",
                    confidence=0.70,
                ))
        except AttributeError:
            pass

        # --- Entry point in a non-standard section ---
        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = None
            for section in pe.sections:
                sec_va = section.VirtualAddress
                sec_size = section.Misc_VirtualSize or section.SizeOfRawData
                if sec_va <= ep < sec_va + sec_size:
                    ep_section = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                    break

            if ep_section and ep_section.lower() not in (".text", ".code", "code", ".init"):
                threats.append(FileThreat(
                    category="Unusual Entry Point",
                    description=(
                        f"Entry point (RVA 0x{ep:08X}) resides in section "
                        f"'{ep_section}' instead of the standard .text section. "
                        f"Packers and malware often relocate the entry point."
                    ),
                    severity="Medium",
                    evidence=f"EP RVA: 0x{ep:08X}, Section: {ep_section}",
                    confidence=0.65,
                ))
            elif ep_section is None and ep != 0:
                threats.append(FileThreat(
                    category="Entry Point Outside Sections",
                    description=(
                        f"Entry point (RVA 0x{ep:08X}) does not fall within any "
                        f"defined section. This is highly abnormal."
                    ),
                    severity="High",
                    evidence=f"EP RVA: 0x{ep:08X}",
                    confidence=0.80,
                ))
        except AttributeError:
            pass

        # --- Suspicious timestamp ---
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts > 0:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                now = datetime.now(tz=timezone.utc)
                if dt > now:
                    threats.append(FileThreat(
                        category="Future Timestamp",
                        description=(
                            f"PE TimeDateStamp ({dt.isoformat()}) is in the future. "
                            f"This may indicate timestamp tampering."
                        ),
                        severity="Medium",
                        evidence=f"TimeDateStamp: {ts} ({dt.isoformat()})",
                        confidence=0.65,
                    ))
                elif dt.year < 2000:
                    threats.append(FileThreat(
                        category="Ancient Timestamp",
                        description=(
                            f"PE TimeDateStamp ({dt.isoformat()}) predates the year 2000. "
                            f"This may indicate timestamp tampering or a corrupted header."
                        ),
                        severity="Low",
                        evidence=f"TimeDateStamp: {ts} ({dt.isoformat()})",
                        confidence=0.50,
                    ))
        except (AttributeError, OSError, OverflowError, ValueError):
            pass

        # --- Checksum mismatch ---
        try:
            claimed = pe.OPTIONAL_HEADER.CheckSum
            if claimed != 0:
                calculated = pe.generate_checksum()
                if claimed != calculated:
                    threats.append(FileThreat(
                        category="Checksum Mismatch",
                        description=(
                            f"PE header checksum (0x{claimed:08X}) does not match the "
                            f"calculated checksum (0x{calculated:08X}). The file may have "
                            f"been modified after compilation."
                        ),
                        severity="Medium",
                        evidence=f"Claimed: 0x{claimed:08X}, Calculated: 0x{calculated:08X}",
                        confidence=0.60,
                    ))
        except Exception:
            pass

        # --- Very few or no imports ---
        try:
            import_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    import_count += len(entry.imports)

            if import_count == 0 and len(content) > 4096:
                threats.append(FileThreat(
                    category="No Imports",
                    description=(
                        "The PE has zero imported functions. Legitimate executables "
                        "almost always import OS APIs. This strongly suggests the "
                        "import table is dynamically resolved at runtime to evade "
                        "static analysis."
                    ),
                    severity="High",
                    evidence="Import count: 0",
                    confidence=0.80,
                ))
            elif 0 < import_count <= 5 and len(content) > 10_240:
                threats.append(FileThreat(
                    category="Minimal Imports",
                    description=(
                        f"The PE imports only {import_count} function(s). Most "
                        f"legitimate executables import dozens. A very low import "
                        f"count suggests dynamic API resolution."
                    ),
                    severity="Medium",
                    evidence=f"Import count: {import_count}",
                    confidence=0.60,
                ))
        except Exception:
            pass

        # --- SizeOfImage much larger than actual file ---
        try:
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            file_size = len(content)
            if file_size > 0 and size_of_image > file_size * 10:
                threats.append(FileThreat(
                    category="Inflated SizeOfImage",
                    description=(
                        f"SizeOfImage ({size_of_image:,} bytes) is more than 10× the "
                        f"actual file size ({file_size:,} bytes). This can indicate "
                        f"header manipulation or an attempt to interfere with analysis."
                    ),
                    severity="Medium",
                    evidence=(
                        f"SizeOfImage: {size_of_image:,}, "
                        f"FileSize: {file_size:,}, "
                        f"Ratio: {size_of_image / file_size:.1f}×"
                    ),
                    confidence=0.65,
                ))
        except (AttributeError, ZeroDivisionError):
            pass

        return threats

    # ===================================================================
    # Utility helpers
    # ===================================================================

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a block of bytes."""
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
