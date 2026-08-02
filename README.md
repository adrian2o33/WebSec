# WebSecScanner

A Python platform for testing web applications for security vulnerabilities and malware. The tool uses a hybrid approach that mixes static analysis, browser automation, and machine learning to detect security flaws while keeping false alarms to a minimum.

## Core Features & Algorithms

- **Browser Automation and DOM Analysis**: Uses Playwright with Chromium and Chrome DevTools Protocol to execute JavaScript in a real browser context. It catches DOM alerts and monitors network WebSocket traffic in real time to uncover client side threats like cryptocurrency miners.
- **Machine Learning Filtering**: A Random Forest classifier built with Scikit-Learn evaluates scan results, normalizes threat metrics using StandardScaler, and filters out false positive findings.
- **Static and Malware Analysis**: Integrated YARA rules check web page content directly in system memory for obfuscated JavaScript, webshells, and malware signatures without writing temporary files to disk.
- **Vulnerability Coverage**: Detects SQL Injection, XSS, Path Traversal, XXE, SSRF, Command Injection, IDOR (via automated ID mutation), Rate Limiting flaws (using asynchronous traffic bursting with asyncio and aiohttp), missing security headers, and insecure cookie configurations.

## Technology Stack

- **Backend**: Python 3, Flask, Flask-SocketIO, asyncio, aiohttp, requests, BeautifulSoup, lxml
- **Machine Learning**: Scikit-Learn, pandas, numpy, joblib
- **Automation and Security**: Playwright, Chrome DevTools Protocol, YARA, VirusTotal API
- **Frontend**: HTML5, Vanilla CSS, WebSockets for live scan updates

## Getting Started

### Prerequisites

Set up a Python virtual environment, then install the dependencies and browser binary:

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```

### Starting the Web Dashboard

If your virtual environment is active, start the server with:

```cmd
python -m web.app
```

Or execute it directly from the virtual environment path on Windows:

```cmd
.venv\Scripts\python.exe -m web.app
```

Open `http://localhost:5000` in your web browser to view the interface.

### Running CLI Scans

To initiate automated scans directly from the command line:

```cmd
.venv\Scripts\python.exe main.py http://target-domain.com --depth 3 --pages 50
```

### Running Tests

The project includes an intentionally vulnerable sandbox app and a complete verification test suite to check that all detection modules work properly.

Note: Because the tests evaluate vulnerability payloads and simulated malware signatures, real time antivirus software (like Windows Defender) may interrupt execution or quarantine files. You may need to temporarily disable real time protection or add a folder exclusion before running the tests.

To execute all verification tests:

```cmd
.venv\Scripts\python.exe tests/run_all_tests.py
```

To run the integration verification script:

```cmd
.venv\Scripts\python.exe run_integration_test.py
```

## License

Developed for academic research and practical evaluation in web application security testing.
