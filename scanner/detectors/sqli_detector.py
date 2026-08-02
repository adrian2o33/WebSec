"""
SQL Injection Detector
Analyses fuzzing responses for signs of SQL injection vulnerabilities.
"""
import re
import logging
from typing import List, Optional
from scanner.fuzzer import FuzzResult
from scanner.models import Finding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)

# SQL error patterns from various database engines
SQL_ERROR_PATTERNS = [
    # MySQL
    (r"you have an error in your sql syntax", "MySQL syntax error"),
    (r"warning.*?\bmysql", "MySQL warning"),
    (r"MySqlException", "MySQL exception"),
    (r"com\.mysql\.jdbc", "MySQL JDBC error"),
    (r"Unclosed quotation mark", "Unclosed quote in SQL"),
    (r"mysql_fetch", "MySQL fetch error"),
    (r"mysql_num_rows", "MySQL num_rows error"),
    (r"MySQL server version", "MySQL version disclosure"),
    
    # PostgreSQL
    (r"PostgreSQL.*?ERROR", "PostgreSQL error"),
    (r"pg_query\(\).*?failed", "PostgreSQL query failed"),
    (r"pg_exec\(\).*?failed", "PostgreSQL exec failed"),
    (r"PSQLException", "PostgreSQL exception"),
    (r"valid PostgreSQL result", "PostgreSQL result error"),
    
    # MSSQL
    (r"Microsoft.*?ODBC.*?SQL Server", "MSSQL ODBC error"),
    (r"\bOLE DB\b.*?SQL Server", "MSSQL OLE DB error"),
    (r"Microsoft SQL Native Client", "MSSQL Native Client error"),
    (r"SqlException", "MSSQL SqlException"),
    (r"Msg \d+, Level \d+, State \d+", "MSSQL error message"),
    (r"mssql_query\(\)", "MSSQL query error"),
    (r"Incorrect syntax near", "MSSQL syntax error"),
    
    # Oracle
    (r"ORA-\d{5}", "Oracle error code"),
    (r"Oracle.*?Driver", "Oracle driver error"),
    (r"oracle\.jdbc", "Oracle JDBC error"),
    (r"quoted string not properly terminated", "Oracle string error"),
    
    # SQLite
    (r"SQLite.*?error", "SQLite error"),
    (r"sqlite3\.OperationalError", "SQLite operational error"),
    (r"SQLITE_ERROR", "SQLite error code"),
    (r"sqlite3_", "SQLite C API error"),
    (r"unrecognized token", "SQLite token error"),
    
    # Generic SQL
    (r"SQL syntax.*?error", "Generic SQL syntax error"),
    (r"syntax error.*?SQL", "Generic SQL syntax error"),
    (r"unexpected end of SQL command", "SQL command error"),
    (r"SQLSTATE\[", "SQLSTATE error"),
    (r"Division by zero", "SQL division by zero"),
    (r"supplied argument is not a valid", "Invalid SQL argument"),
]

# Patterns that suggest a successful injection (data extraction)
INJECTION_SUCCESS_PATTERNS = [
    (r"root:.*?:0:0:", "Unix /etc/passwd content leaked via SQLi"),
    (r"admin.*?password", "Admin credentials possibly leaked"),
    (r"information_schema", "Database schema information leaked"),
    (r"@@version", "Database version string (variable reference)"),
]


class SQLiDetector:
    """Detects SQL injection vulnerabilities from fuzz results."""

    def __init__(self):
        self._compiled_error_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in SQL_ERROR_PATTERNS
        ]
        self._compiled_success_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in INJECTION_SUCCESS_PATTERNS
        ]

    def analyse(self, fuzz_results: List[FuzzResult]) -> List[Finding]:
        """Analyse fuzz results for SQL injection indicators."""
        findings = []
        for result in fuzz_results:
            finding = self._check_sqli(result)
            if finding:
                findings.append(finding)
        return findings

    def _check_sqli(self, result: FuzzResult) -> Optional[Finding]:
        """Check a single fuzz result for SQL injection indicators."""
        if not result.response_body:
            # Check for time-based blind SQLi
            return self._check_time_based(result)

        body = result.response_body
        payload = result.payload

        # Only check SQLi-relevant payloads
        sqli_indicators = ["'", '"', '--', '#', 'UNION', 'SELECT', 'OR ', 'AND ',
                           'SLEEP', 'WAITFOR', 'ORDER BY', 'DROP', 'INSERT', 'UPDATE',
                           'BENCHMARK', 'pg_sleep', 'CONVERT', 'CAST']
        if not any(ind.lower() in payload.lower() for ind in sqli_indicators):
            return None

        confidence = 0.0
        evidence_parts = []

        # Check 1: SQL error messages in response
        for pattern, description in self._compiled_error_patterns:
            match = pattern.search(body)
            if match:
                confidence += 0.5
                context = body[max(0, match.start() - 30):match.end() + 30]
                evidence_parts.append(f"{description}: ...{context}...")
                break  # One error pattern is sufficient

        # Check 2: Successful injection indicators
        for pattern, description in self._compiled_success_patterns:
            if pattern.search(body):
                confidence += 0.4
                evidence_parts.append(description)
                break

        # Check 3: Response length anomaly (boolean-based blind)
        if result.baseline_length > 0:
            ratio = len(body) / max(result.baseline_length, 1)
            if ratio > 2.0 or ratio < 0.3:
                confidence += 0.2
                evidence_parts.append(
                    f"Response length anomaly (baseline: {result.baseline_length}, "
                    f"current: {len(body)}, ratio: {ratio:.2f})"
                )

        # Check 4: Different status code
        if result.response_status == 500:
            confidence += 0.25
            evidence_parts.append("Server returned 500 Internal Server Error")

        # Check 5: Time-based detection
        time_finding = self._check_time_based(result)
        if time_finding:
            return time_finding

        if confidence >= 0.5:
            severity = SeverityLevel.CRITICAL if confidence >= 0.7 else SeverityLevel.HIGH
            return Finding(
                url=result.url,
                parameter=result.parameter,
                payload=payload,
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=severity,
                evidence="; ".join(evidence_parts)[:500],
                confidence=min(confidence, 1.0),
                description=f"SQL Injection detected in parameter '{result.parameter}'. "
                            f"The application appears to incorporate user input directly into SQL queries.",
                recommendation="Use parameterised queries (prepared statements) instead of string concatenation. "
                               "Implement input validation and use an ORM. "
                               "Apply the principle of least privilege for database accounts.",
            )
        return None

    def _check_time_based(self, result: FuzzResult) -> Optional[Finding]:
        """Check for time-based blind SQL injection using baseline comparison.
        
        Uses the baseline response time measured by the fuzzer to detect
        statistically significant delays caused by time-based payloads like
        SLEEP(), WAITFOR DELAY, pg_sleep(), and BENCHMARK().
        """
        payload = result.payload
        time_payloads = ['SLEEP', 'WAITFOR', 'pg_sleep', 'BENCHMARK']
        if not any(tp.lower() in payload.lower() for tp in time_payloads):
            return None

        baseline = getattr(result, 'baseline_time', 0.0) or 0.0
        
        # Adaptive threshold: response must be significantly slower than baseline.
        # For a SLEEP(5), we expect ~5s deviation from baseline.
        # Use baseline + 3s as the minimum threshold (accounts for network jitter).
        time_threshold = max(baseline + 3.0, 4.0)
        time_deviation = result.response_time - baseline

        if result.response_time >= time_threshold and time_deviation >= 3.0:
            # Higher confidence when deviation closely matches expected delay
            confidence = 0.80
            if 4.0 <= time_deviation <= 6.0:
                confidence = 0.90  # Very likely a 5-second SLEEP confirmed
            elif time_deviation > 6.0:
                confidence = 0.85  # Slower than expected but still suspicious

            return Finding(
                url=result.url,
                parameter=result.parameter,
                payload=payload,
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=SeverityLevel.CRITICAL,
                evidence=f"Time-based blind SQLi confirmed: response took {result.response_time:.2f}s "
                         f"(baseline: {baseline:.2f}s, deviation: +{time_deviation:.2f}s, "
                         f"threshold: {time_threshold:.2f}s)",
                confidence=confidence,
                description=f"Time-based blind SQL Injection in parameter '{result.parameter}'. "
                            f"The server delayed its response by {time_deviation:.1f}s compared to "
                            f"the measured baseline of {baseline:.2f}s, matching the injected time function.",
                recommendation="Use parameterised queries. Never concatenate user input into SQL. "
                               "Implement query timeouts as a defence-in-depth measure.",
            )
        return None
