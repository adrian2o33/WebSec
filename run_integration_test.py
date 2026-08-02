import time
import logging
from scanner.scanner import Scanner

logging.basicConfig(level=logging.INFO)

def run_tests():
    scanner = Scanner("http://127.0.0.1:5001", max_depth=2, max_pages=10, request_delay=0)
    
    print("--- Starting Scanner on Test Target ---")
    result = scanner.scan()
    
    print("\n--- Scan Results ---")
    print(f"Total Findings: {len(result.findings)}")
    
    found_xss = False
    found_sqli = False
    found_yara = False
    found_vt = False
    found_redirect = False
    found_dir_listing = False
    
    for f in result.findings:
        print(f"\n[{f.severity.value}] {f.vuln_type.value} at {f.url}")
        print(f"Evidence: {f.evidence[:100]}")
        
        if f.vuln_type.value == "Reflected XSS" and "DOM-Verified" in f.evidence:
            found_xss = True
        if f.vuln_type.value == "SQL Injection" and "Time-based blind" in f.evidence:
            found_sqli = True
        if f.vuln_type.value == "Malware Infection" and "Matched YARA rule" in f.evidence:
            found_yara = True
        if f.vuln_type.value == "Malicious Script Detected" and ("evil.com" in f.evidence or "VirusTotal" in f.evidence):
            found_vt = True
        if f.vuln_type.value == "Open Redirect":
            found_redirect = True
        if f.vuln_type.value == "Directory Listing":
            found_dir_listing = True

    print("\n--- Summary of Expected Functionality ---")
    print(f"DOM-Verified XSS detected:     {'PASS' if found_xss else 'FAIL'}")
    print(f"Time-based SQLi detected:      {'PASS' if found_sqli else 'FAIL'}")
    print(f"YARA malware rule matched:     {'PASS' if found_yara else 'FAIL'}")
    print(f"VirusScanner/VT flagged evil:  {'PASS' if found_vt else 'FAIL'}")
    print(f"Open Redirect detected:        {'PASS' if found_redirect else 'FAIL'}")
    print(f"Directory Listing detected:    {'PASS' if found_dir_listing else 'FAIL'}")

if __name__ == "__main__":
    run_tests()
