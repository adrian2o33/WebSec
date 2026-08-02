"""
Report Generator
Produces scan reports in HTML, CSV, and JSON formats.
"""
import csv
import json
import os
import logging
from datetime import datetime
from typing import List
from io import StringIO

from scanner.models import ScanResult, Finding, SeverityLevel
from config import ReportConfig

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates scan reports in multiple formats."""

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or ReportConfig.OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all(self, result: ScanResult, is_premium: bool = False) -> dict:
        """Generate all configured reports and return their paths."""
        reports = {}
        reports["html"] = self.generate_html(result, is_premium)
        reports["csv"] = self.generate_csv(result)
        reports["json"] = self.generate_json(result)
        return reports

    def generate_json(self, result: ScanResult) -> str:
        """Generate JSON report."""
        filepath = os.path.join(self.output_dir, f"scan_{result.scan_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        logger.info(f"JSON report saved: {filepath}")
        return filepath

    def generate_csv(self, result: ScanResult) -> str:
        """Generate CSV report."""
        filepath = os.path.join(self.output_dir, f"scan_{result.scan_id}.csv")
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Severity", "Type", "URL", "Parameter", "Payload",
                "Evidence", "Confidence", "Description", "Recommendation"
            ])
            for finding in result.findings:
                writer.writerow([
                    finding.severity.value,
                    finding.vuln_type.value,
                    finding.url,
                    finding.parameter,
                    finding.payload,
                    finding.evidence[:200],
                    f"{finding.confidence:.2f}",
                    finding.description,
                    finding.recommendation,
                ])
        logger.info(f"CSV report saved: {filepath}")
        return filepath

    def generate_csv_string(self, result: ScanResult) -> str:
        """Generate CSV as string (for download without file)."""
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Severity", "Type", "URL", "Parameter", "Payload",
            "Evidence", "Confidence", "Description", "Recommendation"
        ])
        for finding in result.findings:
            writer.writerow([
                finding.severity.value,
                finding.vuln_type.value,
                finding.url,
                finding.parameter,
                finding.payload,
                finding.evidence[:200],
                f"{finding.confidence:.2f}",
                finding.description,
                finding.recommendation,
            ])
        return output.getvalue()

    def generate_html(self, result: ScanResult, is_premium: bool = False) -> str:
        """Generate styled HTML report."""
        filepath = os.path.join(self.output_dir, f"scan_{result.scan_id}.html")

        severity_colors = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#6b7280",
        }

        findings_html = ""
        for i, finding in enumerate(result.findings):
            color = severity_colors.get(finding.severity.value, "#6b7280")
            # Escape HTML in evidence and payload to prevent XSS in report
            safe_evidence = self._escape_html(finding.evidence[:500])
            safe_payload = self._escape_html(finding.payload)

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};" data-type="{finding.vuln_type.value}">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {color};">
                        {finding.severity.value}
                    </span>
                    <span class="vuln-type">{finding.vuln_type.value}</span>
                    <span class="confidence">Confidence: {finding.confidence:.0%}</span>
                </div>
                <div class="vuln-description" id="vulnDesc_{i}"></div>
                <div class="finding-body">
                    <p><strong>URL:</strong> <code>{self._escape_html(finding.url)}</code></p>
                    {'<p><strong>Parameter:</strong> <code>' + self._escape_html(finding.parameter) + '</code></p>' if finding.parameter else ''}
                    {'<p><strong>Payload:</strong> <code>' + safe_payload + '</code></p>' if finding.payload else ''}
                    <p><strong>Description:</strong> {self._escape_html(finding.description)}</p>
                    <p><strong>Evidence:</strong></p>
                    <pre class="evidence">{safe_evidence}</pre>
                </div>
            </div>
            """

        summary = result.severity_summary
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report — {self._escape_html(result.target_url)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .scan-info {{
            background: #1e293b;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        .info-item {{ text-align: center; }}
        .info-item .label {{ color: #94a3b8; font-size: 0.85rem; }}
        .info-item .value {{ font-size: 1.5rem; font-weight: 700; color: #f1f5f9; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }}
        .summary-card {{
            background: #1e293b;
            border-radius: 12px;
            padding: 1.25rem;
            text-align: center;
        }}
        .summary-card .count {{ font-size: 2.5rem; font-weight: 800; }}
        .summary-card .label {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.25rem; }}
        .finding {{
            background: #1e293b;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            transition: transform 0.15s ease;
        }}
        .finding:hover {{ transform: translateX(4px); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .severity-badge {{
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .vuln-type {{ font-weight: 600; font-size: 1.1rem; }}
        .confidence {{ margin-left: auto; color: #94a3b8; font-size: 0.85rem; }}
        .finding-body p {{ margin: 0.5rem 0; }}
        code {{
            background: #0f172a;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
            color: #a5b4fc;
            word-break: break-all;
        }}
        pre.evidence {{
            background: #0f172a;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
            color: #cbd5e1;
            margin: 0.5rem 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .footer {{
            text-align: center;
            color: #64748b;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #1e293b;
        }}
        .vuln-info-box {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 1rem;
            margin: 0 0 1.5rem 0;
            display: flex;
            gap: 1rem;
            align-items: flex-start;
        }}
        .vuln-info-icon {{ font-size: 1.5rem; }}
        .vuln-info-content p {{ margin: 0 0 0.5rem 0; }}
        .btn-scenario-toggle {{
            background: none;
            border: none;
            color: #a5b4fc;
            cursor: pointer;
            font-weight: 600;
            padding: 0;
            font-size: 0.95rem;
            margin-top: 0.5rem;
            font-family: inherit;
        }}
        .btn-scenario-toggle:hover {{ text-decoration: underline; color: #c7d2fe; }}
        .scenario-content {{
            background: rgba(99, 102, 241, 0.1);
            padding: 1rem;
            border-radius: 8px;
            margin-top: 0.5rem;
            border-left: 3px solid #6366f1;
        }}
        .btn-premium {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #6366f1, #d946ef);
            color: #ffffff !important;
            padding: 0.6rem 1.5rem;
            border-radius: 100px;
            font-weight: 600;
            font-size: 0.95rem;
            text-decoration: none;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            box-shadow: 0 4px 12px rgba(217, 70, 239, 0.2);
            border: none;
            cursor: pointer;
        }}
        .btn-premium:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(217, 70, 239, 0.35);
        }}
        @media (max-width: 768px) {{
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .scan-info {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Web Security Scan Report</h1>
        <p style="color: #94a3b8; margin-bottom: 2rem;">Target: <strong>{self._escape_html(result.target_url)}</strong></p>

        <div style="background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 1.5rem; border-left: 6px solid {{'A+': '#10b981', 'A-': '#10b981', 'B+': '#3b82f6', 'B': '#3b82f6', 'C': '#f59e0b', 'D': '#f97316', 'F': '#ef4444'}}.get(result.security_grade, '#6b7280');">
            <div style="font-size: 4rem; font-weight: 900; line-height: 1; color: {{'A+': '#10b981', 'A-': '#10b981', 'B+': '#3b82f6', 'B': '#3b82f6', 'C': '#f59e0b', 'D': '#f97316', 'F': '#ef4444'}}.get(result.security_grade, '#6b7280');">
                {result.security_grade}
            </div>
            <div>
                <h3 style="font-size: 1.25rem; margin-bottom: 0.25rem;">Security Grade: {result.security_grade}</h3>
                <p style="color: #cbd5e1; font-size: 0.95rem; line-height: 1.4;"><strong>Bottom Line:</strong> {result.bottom_line}</p>
            </div>
        </div>

        <div class="scan-info">
            <div class="info-item">
                <div class="label">Scan ID</div>
                <div class="value" style="font-size: 1rem;">{result.scan_id}</div>
            </div>
            <div class="info-item">
                <div class="label">Pages Crawled</div>
                <div class="value">{result.pages_crawled}</div>
            </div>
            <div class="info-item">
                <div class="label">Forms Found</div>
                <div class="value">{result.forms_found}</div>
            </div>
            <div class="info-item">
                <div class="label">Total Requests</div>
                <div class="value">{result.total_requests}</div>
            </div>
            <div class="info-item">
                <div class="label">Duration</div>
                <div class="value">{result.scan_duration_seconds:.1f}s</div>
            </div>
            <div class="info-item">
                <div class="label">ML Enabled</div>
                <div class="value">{"Yes" if result.ml_enabled else "No"}</div>
            </div>
        </div>

        <h2 style="margin: 1.5rem 0 0.5rem;">Severity Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="count" style="color: #dc2626;">{summary.get('Critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #ea580c;">{summary.get('High', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #d97706;">{summary.get('Medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #2563eb;">{summary.get('Low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <div class="count" style="color: #6b7280;">{summary.get('Info', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <h2 style="margin: 2rem 0 0.5rem;">Findings ({len(result.findings)})</h2>
        {findings_html if findings_html else '<p style="color: #94a3b8; padding: 2rem; text-align: center;">No vulnerabilities found. The target appears to be secure against the tested vectors.</p>'}

        <div class="footer">
            <p>Generated by <strong>WebSecScanner v{result.scanner_version}</strong></p>
            <p>Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 0.5rem; font-size: 0.8rem;">
                This report is for authorised security testing only.
                Always verify findings manually before remediation.
            </p>
        </div>
    </div>
    <script>
    const VULN_INFO = {{
        "Reflected XSS": {{
            description: "Reflected Cross-Site Scripting occurs when user-supplied input is echoed back in the HTML response without proper sanitization.",
            impact: "An attacker can inject malicious JavaScript that executes in the victim's browser, enabling cookie theft, session hijacking, phishing, and account takeover.",
            icon: "",
            scenario: "Imagine a search bar where you type 'Hello'. The site reloads and says 'You searched for: Hello'. If the site doesn't filter special characters, a hacker can send you a link where the search term is actually a hidden script. When you click the link, the site accidentally runs the hacker's script in your browser, allowing them to steal your login session.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Use context-aware output encoding (e.g., HTML entity encoding) before reflecting user input.</li><li>Implement a strict Content-Security-Policy (CSP) to restrict script execution.</li><li>Use modern frameworks (React, Angular) that automatically escape output.</li></ul>"
        }},
        "Stored XSS": {{
            description: "Stored Cross-Site Scripting occurs when malicious input is permanently saved on the server and served to other users.",
            impact: "An attacker can compromise every user who views the affected page, steal credentials, redirect users to malicious sites, or deface the application.",
            icon: "",
            scenario: "Imagine a public message board. A hacker writes a post, but instead of text, they type a hidden malicious script. The website saves this script into its database. Now, every single time a normal user visits that message board, the website unknowingly delivers the hacker's script to them, which silently steals their passwords or credit card info.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Sanitize all user input upon saving to the database.</li><li>Apply output encoding when rendering stored content.</li><li>For rich text, use a secure HTML sanitizer library like DOMPurify to strip dangerous tags.</li></ul>"
        }},
        "SQL Injection": {{
            description: "SQL Injection occurs when user input is incorporated directly into database queries without parameterization.",
            impact: "An attacker can read, modify, or delete all database records, bypass authentication, escalate privileges, and potentially execute OS commands on the database server.",
            icon: "",
            scenario: "Imagine a login form as a security guard who asks for your name and checks it against a guest list. A hacker tells the guard their name is 'John OR 1=1'. If the guard isn't smart enough to distinguish between a real name and a mathematical trick, they might get confused by '1=1' always being true and accidentally let the hacker in without a password, or hand over the entire guest list.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Never use string concatenation to build SQL queries.</li><li>Always use Prepared Statements (Parameterized Queries) or an ORM (like SQLAlchemy or Entity Framework).</li><li>Enforce principle of least privilege on the database user account.</li></ul>"
        }},
        "Path Traversal": {{
            description: "Path Traversal (Directory Traversal) allows an attacker to access files outside the intended directory by manipulating file path references.",
            impact: "An attacker can read sensitive server files like /etc/passwd, configuration files with database credentials, source code, and private keys.",
            icon: "",
            scenario: "Imagine asking a librarian for a specific book by saying 'Give me the book from Section A, Shelf 2'. A hacker instead says 'Give me the book from ../../Manager_Office/Secret_Safe/Passwords'. If the librarian (the web server) blindly follows these directions without restricting access to the public reading room, they will hand over sensitive internal server files.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Avoid passing raw user input directly to filesystem APIs.</li><li>If necessary, validate input against a strict allowlist of permitted filenames.</li><li>Resolve the absolute path and verify it starts with the expected base directory (e.g., using <code>os.path.abspath</code> and <code>startswith()</code>).</li></ul>"
        }},
        "Open Redirect": {{
            description: "An Open Redirect occurs when an application takes a user-supplied URL and redirects them to it without any validation.",
            impact: "Attackers can construct a trusted-looking URL that redirects victims to a malicious site, facilitating highly convincing phishing attacks or malware delivery.",
            icon: "",
            scenario: "Imagine a club bouncer who blindly escorts anyone to wherever a VIP tells them to go. A hacker gives the bouncer a fake VIP pass that says 'Escort this person to the dark alley outside'. Because the victim trusts the bouncer (the legitimate website), they follow them without realizing they are being led into a trap.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Do not allow user input to dictate redirect destinations.</li><li>If required, validate the target URL against a strict allowlist of trusted domains.</li><li>Force all redirects to use relative paths rather than absolute URLs.</li></ul>"
        }},
        "Directory Listing": {{
            description: "The web server is configured to automatically display a listing of all files and folders when a directory without an index file is requested.",
            impact: "Attackers can easily browse the directory structure, potentially discovering backup files, source code, sensitive documents, and hidden endpoints.",
            icon: "",
            scenario: "Imagine walking into a corporate office to ask a question, and instead of a receptionist greeting you, you find an open filing cabinet containing every single company document neatly sorted. Directory listing acts like that open cabinet, giving anyone who asks a complete map of the server's private files.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Disable directory listing (autoindex) in your web server configuration (e.g., Apache <code>Options -Indexes</code>, Nginx <code>autoindex off;</code>).</li><li>Ensure all public directories contain a default <code>index.html</code> or <code>index.php</code> file.</li></ul>"
        }},
        "Command Injection": {{
            description: "Command Injection occurs when user input is passed to an OS shell command without proper sanitization.",
            impact: "An attacker can execute arbitrary commands on the server, gaining full system control, installing backdoors, exfiltrating data, or pivoting to internal networks.",
            icon: "",
            scenario: "Imagine a website feature that lets you ping an IP address to see if it's online. It asks for an IP, and behind the scenes, runs the server command 'ping [your_input]'. If the hacker inputs '127.0.0.1; delete_all_files', a vulnerable server will run the ping, finish it, and then immediately execute the hacker's second command, destroying the server.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Avoid calling OS commands directly from the application code.</li><li>If unavoidable, use language-specific robust APIs (like Python's <code>subprocess.run</code> with <code>shell=False</code>) instead of passing raw strings to a shell.</li><li>Strictly validate and sanitize any input passed to commands.</li></ul>"
        }},
        "Missing HTTPS": {{
            description: "The application does not enforce HTTPS, meaning traffic between the user and server is transmitted in plaintext.",
            impact: "An attacker on the same network can intercept all traffic (man-in-the-middle), capturing login credentials, session tokens, and sensitive data.",
            icon: "",
            scenario: "Imagine sending a postcard through the mail with your credit card number written on it. Anyone handling the mail along the way can read it. HTTP works exactly the same way. Without HTTPS (the 'S' stands for Secure), everything you send to the website—including passwords—is sent in plain text and can be easily intercepted by anyone on your Wi-Fi network.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Obtain an SSL/TLS certificate (e.g., via Let's Encrypt) and install it on the web server.</li><li>Configure the server to force redirect all HTTP traffic to HTTPS (port 80 to 443).</li></ul>"
        }},
        "Insecure Certificate": {{
            description: "The SSL/TLS certificate is expired, self-signed, or uses a weak cipher suite.",
            impact: "An attacker can perform man-in-the-middle attacks. Users may ignore browser warnings, training them to accept insecure connections.",
            icon: "",
            scenario: "Imagine a website showing you an ID badge to prove who they are, but the badge is expired, or it was printed by a random person instead of a trusted authority. An insecure certificate means the encryption is either broken or the website cannot cryptographically prove they are who they claim to be, making it easy for hackers to impersonate them.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Renew expired certificates via a trusted Certificate Authority (CA).</li><li>Do not use self-signed certificates in production.</li><li>Disable outdated protocols like TLS 1.0/1.1 and weak cipher suites.</li></ul>"
        }},
        "Missing Security Header": {{
            description: "One or more important HTTP security response headers are missing or misconfigured.",
            impact: "Without proper headers, the application is vulnerable to clickjacking (X-Frame-Options), MIME sniffing (X-Content-Type-Options), XSS (CSP), and protocol downgrade attacks (HSTS).",
            icon: "",
            scenario: "If a user simply types yourdomain.com into their browser, the browser initially connects via an unencrypted HTTP connection. Without security headers forcing an immediate secure connection, a hacker on the same Wi-Fi network can intercept this split-second unencrypted request and silently hijack the session (an attack known as SSL Stripping).",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Configure your server to return <code>Strict-Transport-Security</code> (HSTS) to enforce HTTPS.</li><li>Add <code>X-Frame-Options: DENY</code> or <code>SAMEORIGIN</code> to prevent Clickjacking.</li><li>Implement a robust <code>Content-Security-Policy</code> (CSP) to mitigate XSS.</li><li>Add <code>X-Content-Type-Options: nosniff</code> to prevent MIME-sniffing.</li></ul>"
        }},
        "Insecure Cookie": {{
            description: "Cookies are missing important security flags such as HttpOnly, Secure, or SameSite.",
            impact: "An attacker can steal cookies via XSS (missing HttpOnly), intercept them over HTTP (missing Secure), or exploit CSRF vulnerabilities (missing SameSite).",
            icon: "",
            scenario: "Imagine your session cookie as a VIP wristband that keeps you logged in. If it lacks the 'Secure' flag, your browser might accidentally show it over an unencrypted connection. If it lacks 'HttpOnly', a hacker's script running on the page can easily steal it. Once the hacker has a copy of your wristband, they can log into your account without needing your password.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Set the <code>HttpOnly</code> flag to prevent JavaScript access to the cookie.</li><li>Set the <code>Secure</code> flag to ensure the cookie is only transmitted over HTTPS.</li><li>Set the <code>SameSite=Lax</code> or <code>Strict</code> attribute to defend against Cross-Site Request Forgery (CSRF).</li></ul>"
        }},
        "Information Disclosure": {{
            description: "The server exposes sensitive information such as software versions, internal paths, or technology stack details in response headers or error pages.",
            impact: "An attacker can use disclosed version numbers to find known CVEs and craft targeted exploits against the specific software in use.",
            icon: "",
            scenario: "Imagine a business accidentally leaving their architectural blueprints, security system manual, and employee roster on a public bench. When a server leaks exact version numbers, internal file paths, or stack traces in its error messages, it acts as a treasure map for hackers, telling them exactly which exploits to use.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Remove or mask <code>Server</code> and <code>X-Powered-By</code> headers in server configuration.</li><li>Configure the application to display generic, user-friendly error pages instead of stack traces.</li><li>Ensure debug mode is disabled in production environments.</li></ul>"
        }},
        "Malicious Script Detected": {{
            description: "A potentially malicious JavaScript pattern was detected on the page, such as obfuscated eval() calls or encoded payloads.",
            impact: "An attacker could be using the script to steal credentials, redirect users, mine cryptocurrency, or serve drive-by downloads.",
            icon: "",
            scenario: "Malicious scripts are unauthorized code running on a website to perform harmful actions. This could range from stealing user data to showing intrusive ads or redirecting users to scam websites without their permission.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Immediately review the source code of the page for unauthorized injections.</li><li>Check server logs to identify how the script was injected (e.g., via Stored XSS or compromised admin credentials).</li><li>Remove the malicious script and implement a strict Content-Security-Policy (CSP) to block inline script execution.</li></ul>"
        }},
        "Suspicious Iframe": {{
            description: "A hidden or suspiciously configured iframe was detected, possibly loading external malicious content.",
            impact: "An attacker can use hidden iframes for clickjacking, credential phishing, malware delivery, or tracking users without consent.",
            icon: "",
            scenario: "An iframe is a window within a webpage that displays another page. A suspicious iframe is one that is hidden or points to a dangerous site, often used by attackers to trick users into clicking links or to download malware in the background.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Inspect the source of the iframe. If unauthorized, remove it immediately.</li><li>Ensure the site uses <code>X-Frame-Options</code> to control framing policies.</li><li>Review third-party plugins and advertisements, as they are common vectors for malicious iframe injection.</li></ul>"
        }},
        "Malicious Redirect": {{
            description: "The page performs an automatic redirect to a potentially malicious external domain.",
            impact: "Users may be redirected to phishing sites, malware download pages, or scam/exploit kit landing pages.",
            icon: "",
            scenario: "A malicious redirect forces a user away from your site to an attacker-controlled page. This is commonly used to trick users into entering credentials on a fake login page or to start an automated download of malicious software.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Audit the site's code and `.htaccess`/server configurations for unauthorized redirect rules.</li><li>Ensure all open redirect vulnerabilities are patched so attackers cannot hijack legitimate redirection mechanisms.</li></ul>"
        }},
        "Malware Download Link": {{
            description: "A link to a potentially malicious file download (e.g., .exe, .bat, .ps1) was found on the page.",
            impact: "Users clicking the link may download and execute malware, leading to system compromise, ransomware infection, or data theft.",
            icon: "",
            scenario: "A malware download link points to an executable file designed to cause harm. If a user clicks this link, their computer may be infected with viruses, ransomware, or spyware, often without them realizing the file is dangerous.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Remove the malicious links.</li><li>Scan the server filesystem for uploaded malware and remove the offending files.</li><li>Implement strict file upload validation (checking MIME types and file extensions) to prevent attackers from hosting malware on your site.</li></ul>"
        }},
        "Obfuscated Malicious Code": {{
            description: "Heavily obfuscated JavaScript code was detected, a common technique used by malware to evade detection.",
            impact: "The obfuscated code may perform credential theft, cryptomining, keylogging, or serve as a dropper for additional malware payloads.",
            icon: "",
            scenario: "Obfuscation is the process of scrambling code to hide its true intent from security scanners and developers. When detected on a website, it is a strong indicator that the site has been compromised and is running malicious commands behind a layer of complexity.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Identify and remove the obfuscated code blocks.</li><li>Check for backdoor shells on the server (like PHP web shells) that may have been used to inject the code.</li><li>Change all admin and database passwords, assuming the server has been compromised.</li></ul>"
        }},
        "Cryptocurrency Miner": {{
            description: "JavaScript-based cryptocurrency mining code was detected on the page.",
            impact: "The miner abuses visitors' CPU/GPU resources to mine cryptocurrency for the attacker, degrading performance and increasing electricity costs.",
            icon: "",
            scenario: "A web crypto miner uses the computing power of your visitors to mine digital currency without their permission. This causes the visitor's device to slow down, overheat, and consume more battery life, all to make money for the attacker.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Remove the cryptomining script (commonly associated with services like Coinhive or Monero web miners).</li><li>Block outbound connections to known mining pool websockets at the network firewall level.</li></ul>"
        }},
        "Phishing Indicator": {{
            description: "The page contains patterns commonly associated with phishing attacks, such as fake login forms mimicking popular services.",
            impact: "Users may unknowingly submit their real credentials to the attacker, leading to account compromise and identity theft.",
            icon: "",
            scenario: "Phishing indicators are signs that a page is trying to impersonate a trusted service. Attackers create fake login forms that look identical to those of banks or email providers to harvest the real credentials of users who are tricked into entering them.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Take down the offending pages immediately.</li><li>If the site was compromised to host phishing pages, perform a full incident response investigation to determine the point of entry and patch the vulnerability.</li></ul>"
        }},
        "Malware Infection": {{
            description: "A known malware signature (e.g. via YARA) or malicious domain (via VirusTotal) was detected associated with the target.",
            impact: "The server or domain is actively distributing malware, which compromises visitors and blacklists the site.",
            icon: "",
            scenario: "A malware infection means the site has been flagged by security systems as a distributor of harmful software. This is a severe issue where the server itself or the files hosted on it are actively harming visitors and will likely lead to the site being blocked by major browsers.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Take the site offline immediately to prevent further harm to visitors.</li><li>Restore the server from a known clean backup, or rebuild the server entirely.</li><li>After cleaning, submit a review request to Google Safe Browsing and VirusTotal to remove the domain from blacklists.</li></ul>"
        }},
        "XML External Entity (XXE) Injection": {{
            description: "XML External Entity (XXE) Injection occurs when poorly configured XML parsers process external entities.",
            impact: "An attacker can read local files on the server (like /etc/passwd), perform Server-Side Request Forgery (SSRF), or cause Denial of Service.",
            icon: "",
            scenario: "XXE injection exploits XML parsers that allow the loading of external files. An attacker can craft an XML file that asks the server to include a sensitive local file, such as password logs, and have it returned to them in the application response.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Configure your XML parser to strictly disable Document Type Definitions (DTDs) and external entity resolution.</li><li>In Java, set <code>factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);</code>.</li><li>Prefer less complex formats like JSON when parsing untrusted data.</li></ul>"
        }},
        "Invalid Input / Fuzzing Exception": {{
            description: "The application failed to gracefully handle unexpected or massive input, resulting in an unhandled exception or crash.",
            impact: "An attacker can glean sensitive information from stack traces or cause Denial of Service (DoS) by crashing the application thread.",
            icon: "",
            scenario: "Input-related exceptions occur when a website doesn't know how to handle weird or malformed data. Instead of showing a nice error, the server crashes and reveals technical error logs, giving attackers a glimpse into the internal software structure and potential weaknesses.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Implement global exception handlers to catch unexpected errors before they reach the user.</li><li>Ensure all user input is validated (type, length, format) before processing.</li><li>Never return raw stack traces in HTTP responses in production environments.</li></ul>"
        }},
        "Broken Access Control (IDOR)": {{
            description: "Insecure Direct Object Reference (IDOR) occurs when an application provides direct access to objects based on user-supplied input without authorization checks.",
            impact: "A low-privileged user can view, modify, or delete data belonging to other users or administrators.",
            icon: "",
            scenario: "IDOR occurs when a website relies on predictable inputs, like an ID number in a URL, to show private data. Because the site fails to check if the current user owns that data, an attacker can simply change the ID number to view someone else's sensitive information.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Implement mandatory access control checks on every request attempting to access a specific resource.</li><li>Do not rely on obscure IDs. Always verify that the currently authenticated user owns the requested object ID.</li><li>Use indirect references (like session variables) or non-guessable UUIDs instead of predictable sequential integers.</li></ul>"
        }},
        "Missing Rate Limiting": {{
            description: "The server does not enforce a limit on the number of requests a user can make in a given timeframe.",
            impact: "An attacker can launch brute-force attacks against login forms, scrape data rapidly, or cause Application-Layer Denial of Service (DoS).",
            icon: "",
            scenario: "Missing Rate Limiting means there are no restrictions on how often a single user can talk to your server. Without this, an attacker can send thousands of requests per second to brute-force passwords, scrape all your content, or simply overwhelm the server until it crashes.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Implement API rate limiting (e.g., 100 requests per minute per IP address).</li><li>For authentication endpoints, enforce account lockouts or CAPTCHAs after a small number of failed login attempts.</li><li>Use a Web Application Firewall (WAF) or tools like Fail2Ban to block IPs demonstrating malicious burst patterns.</li></ul>"
        }},
        "Command Injection": {{
            description: "OS Command Injection occurs when an application passes unsafe user-supplied data to a system shell.",
            impact: "An attacker can execute arbitrary OS commands, completely compromising the server and its underlying network.",
            icon: "",
            scenario: "OS Command Injection occurs when an application passes unsafe user input directly to the server's command line. For example, if an app lets you ping an IP address, an attacker can append a semicolon followed by a secondary command like 'whoami'. The server will run the ping, and then immediately run the hidden command, giving the attacker control over the system.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Never pass user input directly into system shells (e.g., `os.system` in Python).</li><li>Use language-specific APIs that execute binaries directly without invoking a shell (e.g., `subprocess.run`).</li><li>If you must pass input, strictly validate it against an alphanumeric whitelist.</li></ul>"
        }},
        "CORS Misconfiguration": {{
            description: "Cross-Origin Resource Sharing (CORS) is configured to trust arbitrary origins, allowing malicious sites to read sensitive data.",
            impact: "An attacker can create a malicious website that forces the victim's browser to silently fetch and exfiltrate private API data.",
            icon: "",
            scenario: "Cross-Origin Resource Sharing (CORS) is a security mechanism that controls which external websites can interact with an API. If configured too permissively to trust any domain (using a wildcard '*'), an attacker can build a malicious website that forces the victim's browser to silently extract sensitive private data from the API.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Never use `Access-Control-Allow-Origin: *` on endpoints that require authentication.</li><li>Configure your server to only return the Origin header if it matches a strict, hardcoded whitelist of trusted domains.</li><li>Never dynamically reflect the incoming `Origin` header.</li></ul>"
        }},
        "Cross-Site Request Forgery (CSRF)": {{
            description: "The application allows state-changing requests to be executed on behalf of an authenticated user without verifying the intent.",
            impact: "An attacker can trick a victim into clicking a link that silently performs unauthorized actions (like transferring funds or changing passwords) on the victim's behalf.",
            icon: "",
            scenario: "CSRF relies on the fact that browsers automatically attach session cookies to requests. If an application lacks anti-CSRF tokens, an attacker can trick an authenticated user into clicking a malicious link. The link will silently force the user's browser to submit a state-changing action, like transferring funds or changing a password, on the victim's behalf.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>Implement the synchronizer token pattern. Embed a unique, secure hidden token in every state-changing HTML form, and validate it.</li><li>Set the `SameSite=Lax` or `SameSite=Strict` attribute on your session cookies.</li></ul>"
        }},
        "Server-Side Request Forgery (SSRF)": {{
            description: "The server accepts user-supplied URLs and fetches them without validation, allowing access to internal services or cloud metadata.",
            impact: "An attacker can bypass firewalls to scan internal networks, read local files, or extract sensitive cloud metadata credentials (e.g., AWS IAM keys).",
            icon: "",
            scenario: "SSRF occurs when a server fetches data from a URL provided by the user without checking it. An attacker can provide internal addresses that are normally inaccessible, forcing the server to act as a proxy and access sensitive internal resources or cloud infrastructure.",
            remediation: "<ul style='margin-left: 1.5rem;'><li>If the application must fetch URLs, strictly whitelist the allowed destination domains.</li><li>Implement a network-level or code-level block against resolving internal IP addresses (127.0.0.1, 192.168.x.x, 169.254.169.254).</li><li>Configure backend HTTP clients to NOT automatically follow HTTP redirects.</li></ul>"
        }}
    }};

    document.querySelectorAll('.finding').forEach((card, index) => {{
        const vulnType = card.dataset.type;
        const info = VULN_INFO[vulnType];
        const descEl = document.getElementById(`vulnDesc_${{index}}`);
        if (info && descEl) {{
            let dynamicScenario = info.scenario;
            let dynamicRemediation = info.remediation;
            if (vulnType === "Missing Security Header") {{
                const evidenceEl = card.querySelector('.evidence');
                const evidenceText = evidenceEl ? evidenceEl.textContent : "";
                if (evidenceText.includes("X-Frame-Options")) {{
                    dynamicScenario = "Without the X-Frame-Options header, a web application allows its content to be embedded inside an iframe on an external domain. This enables Clickjacking, where an attacker layers your legitimate site invisibly under a malicious site, tricking users into clicking buttons they can't see.";
                    dynamicRemediation = "<ul style='margin-left: 1.5rem;'><li>Configure your server to return <code>X-Frame-Options: DENY</code> or <code>SAMEORIGIN</code> to prevent Clickjacking.</li></ul>";
                }} else if (evidenceText.includes("Strict-Transport-Security") || evidenceText.includes("HSTS")) {{
                    dynamicScenario = "Without HTTP Strict Transport Security (HSTS), the very first connection a user makes to a website might occur over unencrypted HTTP. An attacker on the same network can intercept this split-second unencrypted request and silently hijack the session before a secure connection is established.";
                    dynamicRemediation = "<ul style='margin-left: 1.5rem;'><li>Configure your server to return <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code> to enforce HTTPS and prevent SSL Stripping.</li></ul>";
                }} else if (evidenceText.includes("Content-Security-Policy") || evidenceText.includes("CSP")) {{
                    dynamicScenario = "Without a strict Content-Security-Policy (CSP), the browser lacks a definitive 'allowlist' of trusted scripts. As a result, the browser cannot differentiate between legitimate application scripts and maliciously injected payloads, drastically reducing the site's defense against Cross-Site Scripting (XSS).";
                    dynamicRemediation = "<ul style='margin-left: 1.5rem;'><li>Implement a robust <code>Content-Security-Policy</code> to mitigate XSS. Start with <code>Content-Security-Policy: default-src 'self'</code>.</li></ul>";
                }} else if (evidenceText.includes("X-Content-Type-Options")) {{
                    dynamicScenario = "Without the X-Content-Type-Options: nosniff directive, browsers might try to 'guess' a file's type. This allows attackers to upload dangerous executable scripts disguised as benign images, which the browser will mistakenly execute, bypassing standard file upload restrictions.";
                    dynamicRemediation = "<ul style='margin-left: 1.5rem;'><li>Configure your server to return <code>X-Content-Type-Options: nosniff</code> to prevent MIME-sniffing attacks.</li></ul>";
                }} else if (evidenceText.includes("Permissions-Policy")) {{
                    dynamicRemediation = "<ul style='margin-left: 1.5rem;'><li>Restrict browser features your site doesn't need: <code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code>.</li></ul>";
                }}
            }}

            descEl.innerHTML = `
            <div class="vuln-info-box" style="display: flex; flex-direction: column; gap: 0.5rem; width: 100%;">
                <div style="display: flex; gap: 1rem; align-items: flex-start;">
                    <div class="vuln-info-content">
                        <p class="vuln-info-desc">${{info.description}}</p>
                        <p class="vuln-info-impact"><strong>Impact:</strong> ${{info.impact}}</p>
                    </div>
                </div>
                
                <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                    ${{dynamicScenario ? `
                    <div class="scenario-container" style="flex: 1;">
                        <button class="btn-scenario-toggle" onclick="toggleSection(this)">Explain in Plain English ▾</button>
                        <div class="scenario-content toggle-content" style="display: none; background: rgba(99, 102, 241, 0.1); padding: 1rem; border-radius: 8px; border-left: 3px solid #6366f1; margin-top: 0.5rem;">
                            <p><strong>Real-World Scenario:</strong> ${{dynamicScenario}}</p>
                        </div>
                    </div>
                    ` : ''}}
                    
                    ${{dynamicRemediation ? `
                    <div class="remediation-container" style="flex: 1;">
                        <button class="btn-scenario-toggle" onclick="toggleSection(this)" style="color: #10b981;">How to Fix ▾</button>
                        <div class="remediation-content toggle-content" style="display: none; background: rgba(16, 185, 129, 0.1); padding: 1rem; border-radius: 8px; border-left: 3px solid #10b981; margin-top: 0.5rem; font-size: 0.95rem;">
                            <strong style="display: block; margin-bottom: 0.5rem;">Remediation Guide:</strong>
                            ${{dynamicRemediation}}
                        </div>
                    </div>
                    ` : ''}}
                </div>
            </div>
            `;
        }}
    }});

    const IS_PREMIUM = {str(is_premium).lower()};

    window.toggleSection = function(btn) {{
        const content = btn.nextElementSibling;
        const isPlain = btn.innerHTML.includes('Explain');
        const label = isPlain ? 'Explain in Plain English' : 'How to Fix';

        if (content.style.display === 'none') {{
            if (!isPlain && !IS_PREMIUM) {{
                content.innerHTML = `
                <div style="padding: 1.25rem 0; text-align: left;">
                    <h4 style="color: #ea580c; margin-bottom: 0.5rem; font-size: 1.05rem;">Premium Feature</h4>
                    <p style="margin-bottom: 1rem; color: #cbd5e1; font-size: 0.95rem;">The detailed remediation guide is a Premium feature.</p>
                    <a href="http://127.0.0.1:5000/pricing" target="_blank" class="btn-premium">Upgrade to Premium</a>
                </div>`;
            }}
            content.style.display = 'block';
            btn.innerHTML = `Hide ${{isPlain ? 'Plain English' : 'Guide'}} ▴`;
        }} else {{
            content.style.display = 'none';
            btn.innerHTML = `${{label}} ▾`;
        }}
    }};
    </script>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved: {filepath}")
        return filepath

    def generate_file_all(self, result_dict: dict) -> dict:
        """Generate HTML report for a file scan."""
        reports = {}
        reports["html"] = self.generate_file_html(result_dict)
        return reports

    def generate_file_html(self, result: dict) -> str:
        """Generate styled HTML report for file scan."""
        import urllib.parse
        filename = result.get("original_filename", result.get("filename", "unknown"))
        safe_filename = urllib.parse.quote(filename).replace("%", "_")
        filepath = os.path.join(self.output_dir, f"scan_file_{safe_filename}.html")

        severity_colors = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#6b7280",
        }

        findings_html = ""
        threats = result.get("threats", [])
        for i, threat in enumerate(threats):
            color = severity_colors.get(threat.get("severity"), "#6b7280")
            safe_evidence = self._escape_html(threat.get("evidence", "")[:500])
            
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {color};">
                        {threat.get("severity")}
                    </span>
                    <span class="vuln-type">{threat.get("category")}</span>
                    {f'<span class="confidence">Confidence: {threat.get("confidence", 0) * 100:.0f}%</span>' if threat.get("severity") != 'Info' else ''}
                </div>
                <div class="finding-body">
                    <p><strong>Description:</strong> {self._escape_html(threat.get("description", ""))}</p>
                    <p><strong>Evidence:</strong></p>
                    <pre class="evidence">{safe_evidence}</pre>
                </div>
            </div>
            """

        grade_color = '#6b7280'
        grade = 'N/A'
        threat_level = result.get("threat_level", "Unknown")
        if threat_level == 'Clean':
            grade_color = '#10b981'
            grade = 'A'
        elif threat_level == 'Suspicious':
            grade_color = '#f59e0b'
            grade = 'C'
        elif threat_level == 'Malicious':
            grade_color = '#ef4444'
            grade = 'F'

        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        entropy_note = '<br><span style="font-size: 0.8rem; color: #94a3b8; font-weight: normal; display: block; margin-top: -0.2rem;">(Normal for this format)</span>' if ext in ['pdf', 'zip', 'rar', '7z', 'gz', 'png', 'jpg', 'mp4', 'mp3', 'docx', 'xlsx', 'pptx'] else ''

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Scan Report — {self._escape_html(filename)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            font-size: 2rem;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .scan-info {{
            background: #1e293b;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        .info-item {{ text-align: center; }}
        .info-item .label {{ color: #94a3b8; font-size: 0.85rem; }}
        .info-item .value {{ font-size: 1.5rem; font-weight: 700; color: #f1f5f9; }}
        .finding {{
            background: #1e293b;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            transition: transform 0.15s ease;
        }}
        .finding:hover {{ transform: translateX(4px); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .severity-badge {{
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .vuln-type {{ font-weight: 600; font-size: 1.1rem; }}
        .confidence {{ margin-left: auto; color: #94a3b8; font-size: 0.85rem; }}
        .finding-body p {{ margin: 0.5rem 0; }}
        pre.evidence {{
            background: #0f172a;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
            color: #cbd5e1;
            margin: 0.5rem 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .footer {{
            text-align: center;
            color: #64748b;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #1e293b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ File Scan Report</h1>
        <p style="color: #94a3b8; margin-bottom: 2rem;">Target: <strong>{self._escape_html(filename)}</strong></p>

        <div style="background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 1.5rem; border-left: 6px solid {grade_color};">
            <div style="font-size: 4rem; font-weight: 900; line-height: 1; color: {grade_color};">
                {grade}
            </div>
            <div>
                <h3 style="font-size: 1.25rem; margin-bottom: 0.25rem;">Verdict: {threat_level}</h3>
            </div>
        </div>

        <div class="scan-info">
            <div class="info-item">
                <div class="label">File Size</div>
                <div class="value">{result.get('file_size_human')}</div>
            </div>
            <div class="info-item">
                <div class="label">File Type</div>
                <div class="value">{result.get('file_type')}</div>
            </div>
            <div class="info-item">
                <div class="label">Entropy</div>
                <div class="value">{result.get('entropy', 0):.2f}/8.0{entropy_note}</div>
            </div>
            <div class="info-item">
                <div class="label">Duration</div>
                <div class="value">{result.get('scan_time', 0):.2f}s</div>
            </div>
        </div>

        <h2 style="margin: 2rem 0 0.5rem;">Threats Found ({len([t for t in threats if t.get('severity') != 'Info'])})</h2>
        
        {findings_html if threats else '<div class="finding" style="text-align:center;"><p>No threats found. File appears clean.</p></div>'}

        <div class="footer">
            <p>Generated by <strong>WebSecScanner v1.0.0</strong></p>
            <p>Scan completed at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"File HTML report saved: {filepath}")
        return filepath

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters to prevent XSS in reports."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
