"""
WebSecScanner — CLI Entry Point
Run vulnerability scans and malware detection from the command line.
"""
import argparse
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.scanner import Scanner
from scanner.reporter import ReportGenerator


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_banner():
    print("""
╔══════════════════════════════════════════════╗
║   🛡️  WebSecScanner v1.0                     ║
║   Automated Web Vulnerability & Malware      ║
║   Scanner with ML-Powered Analysis           ║
╚══════════════════════════════════════════════╝
    """)


def print_findings_summary(result):
    """Print a coloured summary of findings to the terminal."""
    summary = result.severity_summary
    total = len(result.findings)

    print(f"\n{'=' * 60}")
    print(f"  SCAN RESULTS — {result.target_url}")
    print(f"{'=' * 60}")
    print(f"  Scan ID:        {result.scan_id}")
    print(f"  Pages Crawled:  {result.pages_crawled}")
    print(f"  Forms Found:    {result.forms_found}")
    print(f"  Total Requests: {result.total_requests}")
    print(f"  Duration:       {result.scan_duration_seconds:.1f}s")
    print(f"  ML Enabled:     {'Yes' if result.ml_enabled else 'No'}")
    print(f"  Virus Scan:     {'Yes' if result.virus_scan_enabled else 'No'}")
    print(f"{'─' * 60}")
    print(f"  FINDINGS: {total}")
    print(f"    Critical: {summary.get('Critical', 0)}")
    print(f"    High:     {summary.get('High', 0)}")
    print(f"    Medium:   {summary.get('Medium', 0)}")
    print(f"    Low:      {summary.get('Low', 0)}")
    print(f"    Info:     {summary.get('Info', 0)}")
    print(f"{'─' * 60}")

    if result.findings:
        print(f"\n  TOP FINDINGS:")
        for i, f in enumerate(result.findings[:15], 1):
            severity_markers = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🔵",
                "Info": "⚪",
            }
            marker = severity_markers.get(f.severity.value, "⚪")
            print(f"  {i:2d}. {marker} [{f.severity.value:8s}] {f.vuln_type.value}")
            print(f"      URL: {f.url}")
            if f.parameter:
                print(f"      Param: {f.parameter}")
            print(f"      {f.description[:100]}")
            print()

        if total > 15:
            print(f"  ... and {total - 15} more findings. See the full report for details.\n")
    else:
        print("\n  ✅ No vulnerabilities found! The target appears secure.\n")


def main():
    parser = argparse.ArgumentParser(
        description="WebSecScanner — Automated Web Vulnerability & Malware Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py http://localhost:5001
  python main.py https://example.com --depth 5 --pages 100
  python main.py http://target.com --no-ml --no-virus --delay 1.0
  python main.py http://target.com --output ./my_reports
        """,
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--depth", type=int, default=3, help="Max crawl depth (default: 3)")
    parser.add_argument("--pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--no-ml", action="store_true", help="Disable ML post-processing")
    parser.add_argument("--no-virus", action="store_true", help="Disable virus/malware scanning")
    parser.add_argument("--output", type=str, default=None, help="Output directory for reports")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    setup_logging(args.verbose)
    print_banner()

    # Ensure URL has scheme
    url = args.url
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    print(f"  Target:    {url}")
    print(f"  Depth:     {args.depth}")
    print(f"  Max Pages: {args.pages}")
    print(f"  Delay:     {args.delay}s")
    print(f"  ML:        {'Disabled' if args.no_ml else 'Enabled'}")
    print(f"  Virus:     {'Disabled' if args.no_virus else 'Enabled'}")
    print()

    # Run scan
    scanner = Scanner(
        target_url=url,
        max_depth=args.depth,
        max_pages=args.pages,
        request_delay=args.delay,
        enable_ml=not args.no_ml,
        enable_virus_scan=not args.no_virus,
    )

    def on_progress(progress):
        status = progress.status.value if progress.status else "Unknown"
        action = progress.current_action or ""
        print(f"\r  [{status}] {action[:80]}", end="", flush=True)

    scanner.set_progress_callback(on_progress)
    result = scanner.scan()
    print()  # Clear progress line

    # Print summary
    print_findings_summary(result)

    # Generate reports
    output_dir = args.output
    reporter = ReportGenerator(output_dir=output_dir) if output_dir else ReportGenerator()
    reports = reporter.generate_all(result)

    print(f"  📄 Reports saved:")
    for fmt, path in reports.items():
        print(f"    {fmt.upper()}: {path}")
    print()


if __name__ == "__main__":
    main()
