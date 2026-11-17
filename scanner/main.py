#!/usr/bin/env python3
"""Command line entry point for the Automated Compliance Scanner."""

import argparse
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

from scanner import __version__
from scanner.catalog import PLATFORMS, load_checks
from scanner.linux_checks import DEFAULT_FIND_TIMEOUT
from scanner.model import CATEGORIES, SEVERITIES, exit_code
from scanner.reports import CSVReportGenerator, HTMLReportGenerator, JSONReportGenerator, POAMReportGenerator
from scanner.runner import detect_platform, run_scan

EXIT_USAGE = 64
FRAMEWORK_CHOICES = {"nist": "nist_800_53", "soc2": "soc2", "iso27001": "iso_27001"}
STATUS_STYLE = {"PASS": "green", "FAIL": "red", "ERROR": "yellow", "NOT_APPLICABLE": "dim", "MANUAL": "cyan"}
SEVERITY_STYLE = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim"}


class Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors must not look like scan results (exit 1 or 2)
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> Parser:
    parser = Parser(
        prog="compliance-scanner",
        description="Check this host against CIS Benchmark recommendations and map the findings to "
                    "NIST SP 800-53 Rev. 5, SOC 2 and ISO/IEC 27001:2022.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exit codes:
  0   every assessed check passed and nothing errored
  1   at least one check failed
  2   at least one critical check failed
  3   nothing failed, but at least one check could not be assessed
  64  usage error or unsupported platform

Examples:
  %(prog)s
  %(prog)s --output html -f report.html
  %(prog)s --output json -f report.json --quiet
  %(prog)s --output poam -f poam.csv
  %(prog)s --categories authentication network --severity high
  %(prog)s --frameworks nist soc2
  %(prog)s --list-checks --platform windows
""")
    parser.add_argument("--output", "-o", choices=["console", "html", "json", "csv", "poam"], default="console",
                        help="output format (default: console)")
    parser.add_argument("--output-file", "-f", help="file to write for html, json, csv and poam output")
    parser.add_argument("--categories", "-c", nargs="+", choices=list(CATEGORIES),
                        help="only run checks in these categories")
    parser.add_argument("--severity", "-s", choices=list(SEVERITIES) + ["all"], default="all",
                        help="only run checks at this severity or above (default: all)")
    parser.add_argument("--frameworks", nargs="+", choices=list(FRAMEWORK_CHOICES), default=[],
                        help="print control coverage tables for these frameworks in console output")
    parser.add_argument("--nist-mapping", action="store_true", help="same as --frameworks nist")
    parser.add_argument("--find-timeout", type=int, default=DEFAULT_FIND_TIMEOUT, metavar="SECONDS",
                        help=f"time limit per file system for file searches (default: {DEFAULT_FIND_TIMEOUT})")
    parser.add_argument("--list-checks", action="store_true", help="print the check catalog and exit")
    parser.add_argument("--platform", choices=list(PLATFORMS), help="catalog to show with --list-checks")
    parser.add_argument("--quiet", "-q", action="store_true", help="print nothing but the requested output")
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {__version__}")
    return parser


def _rate(value) -> str:
    return "n/a" if value is None else f"{value}%"


def print_catalog(console: Console, platform: str) -> None:
    table = Table(title=f"{platform.capitalize()} checks", show_lines=False)
    for column in ("ID", "Category", "Severity", "Needs root"):
        table.add_column(column, no_wrap=True)
    table.add_column("Check")
    table.add_column("NIST 800-53")
    for check in load_checks(platform):
        table.add_row(check.id, check.category, check.severity, "yes" if check.requires_root else "no",
                      check.title, ", ".join(check.nist_800_53))
    console.print(table)


def print_console_report(console: Console, result: Dict[str, Any], frameworks: List[str]) -> None:
    summary = result["summary"]
    console.print(f"[bold]Host:[/bold] {result['system_info']['hostname']}   "
                  f"[bold]OS:[/bold] {result['system_info']['distribution']}   "
                  f"[bold]Scan time (UTC):[/bold] {result['scan_time']}", highlight=False)
    console.print(
        f"[bold]Checks run:[/bold] {summary['total_checks']}   [green]Passed:[/green] {summary['passed']}   "
        f"[red]Failed:[/red] {summary['failed']}   [yellow]Not assessed:[/yellow] {summary['errors']}   "
        f"[cyan]Manual review:[/cyan] {summary['manual']}   Not applicable: {summary['not_applicable']}",
        highlight=False)
    console.print(f"[bold]Compliance rate (pass / assessed):[/bold] {_rate(summary['compliance_rate'])}\n",
                  highlight=False)

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Check")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    for check in result["checks"]:
        status = check["status"]
        table.add_row(
            check["id"], check["title"],
            f"[{SEVERITY_STYLE[check['severity']]}]{check['severity'].upper()}[/]",
            f"[{STATUS_STYLE[status]}]{status.replace('_', ' ')}[/]",
        )
    console.print(table)

    for key in frameworks:
        section = result["framework_summary"][key]
        coverage = Table(title=f"{section['label']}: control coverage", header_style="bold")
        for column in ("Control", "Name", "Passed", "Failed", "No verdict", "Compliance"):
            coverage.add_column(column)
        for control in section["controls"]:
            coverage.add_row(control["control_id"], control["control_name"], str(control["checks_passed"]),
                             str(control["checks_failed"]), str(control["checks_no_verdict"]),
                             _rate(control["compliance_percentage"]))
        console.print(coverage)

    for status, heading in (("FAIL", "Failed checks"), ("MANUAL", "Manual review"), ("ERROR", "Not assessed")):
        rows = [c for c in result["checks"] if c["status"] == status]
        if not rows:
            continue
        console.print(f"\n[bold {STATUS_STYLE[status]}]{heading} ({len(rows)})[/]")
        for check in rows:
            cis = f" (CIS {check['cis']['id']})" if check["cis"]["id"] else ""
            console.print(f"[bold]{check['id']}[/bold]{cis} {check['title']}", highlight=False)
            console.print(f"  Found:    {check['actual']}", highlight=False, markup=False)
            if status != "ERROR":
                console.print(f"  Expected: {check['expected']}", highlight=False, markup=False)
                console.print(f"  Fix:      {check['remediation']}", highlight=False, markup=False)


def closing_line(result: Dict[str, Any]) -> str:
    summary = result["summary"]
    code = exit_code(result["checks"])
    if code == 2:
        return f"[bold red]{summary['failed_by_severity']['critical']} critical check(s) failed.[/]"
    if code == 1:
        return f"[bold red]{summary['failed']} check(s) failed.[/]"
    if code == 3:
        return (f"[bold yellow]No check failed, but {summary['errors']} could not be assessed. "
                "This is not a clean result.[/]")
    extra = f" {summary['manual']} need manual review." if summary["manual"] else ""
    return f"[bold green]All {summary['passed']} assessed checks passed.[/]{extra}"


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    notes = Console(stderr=True, quiet=args.quiet)

    if args.list_checks:
        platform = args.platform or detect_platform()
        if platform not in PLATFORMS:
            platform = "linux"
        print_catalog(console, platform)
        return 0

    platform = detect_platform()
    if platform not in PLATFORMS:
        Console(stderr=True).print("[red]Unsupported operating system.[/red] The scanner runs on Linux and Windows.")
        return EXIT_USAGE
    if args.output != "console" and not args.output_file:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = "csv" if args.output in ("csv", "poam") else args.output
        prefix = "poam" if args.output == "poam" else "compliance_report"
        args.output_file = f"{prefix}_{stamp}.{extension}"

    notes.print(f"Automated Compliance Scanner {__version__} on {platform}", highlight=False)
    with notes.status("Running checks..."):
        result = run_scan(platform, args.categories, args.severity, find_timeout=args.find_timeout)
    if not result["privileged"]:
        rights = "root" if platform == "linux" else "administrator rights"
        notes.print(f"[yellow]Running without {rights}. Checks that need them are reported as ERROR.[/yellow]")

    frameworks = [FRAMEWORK_CHOICES[name] for name in args.frameworks]
    if args.nist_mapping and "nist_800_53" not in frameworks:
        frameworks.insert(0, "nist_800_53")

    if args.output == "console":
        print_console_report(console, result, frameworks)
    elif args.output == "html":
        HTMLReportGenerator().generate(result, args.output_file)
        notes.print(f"HTML report written to {args.output_file}", highlight=False)
    elif args.output == "json":
        JSONReportGenerator().generate(result, args.output_file)
        notes.print(f"JSON report written to {args.output_file}", highlight=False)
    elif args.output == "csv":
        written = CSVReportGenerator().generate(result, args.output_file)
        notes.print(f"CSV reports written to {' and '.join(written)}", highlight=False)
    else:
        count = POAMReportGenerator().generate(result, args.output_file)
        notes.print(f"POA&M worksheet with {count} open item(s) written to {args.output_file}", highlight=False)

    notes.print(closing_line(result))
    return exit_code(result["checks"])


if __name__ == "__main__":
    sys.exit(main())
