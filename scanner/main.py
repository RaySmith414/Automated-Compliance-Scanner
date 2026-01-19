#!/usr/bin/env python3
"""
Automated Compliance Scanner
Checks systems against CIS Benchmarks and maps to NIST 800-53 controls

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import argparse
import platform
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner.linux_checks import LinuxComplianceChecker
from scanner.windows_checks import WindowsComplianceChecker
from scanner.nist_mapper import NISTMapper
from reports.html_report import HTMLReportGenerator
from reports.json_report import JSONReportGenerator
from reports.csv_report import CSVReportGenerator

console = Console()


def detect_os():
    """Detect the operating system"""
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    elif system == 'windows':
        return 'windows'
    else:
        return 'unknown'


def display_banner():
    """Display the application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║         AUTOMATED COMPLIANCE SCANNER v1.0.0                   ║
    ║         CIS Benchmarks | NIST 800-53 Control Mapping          ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))


def display_console_results(results):
    """Display results in a formatted console table"""
    # Summary statistics
    total = len(results['checks'])
    passed = sum(1 for c in results['checks'] if c['status'] == 'PASS')
    failed = sum(1 for c in results['checks'] if c['status'] == 'FAIL')
    errors = sum(1 for c in results['checks'] if c['status'] == 'ERROR')

    # Handle division by zero
    compliance_rate = (passed / total * 100) if total > 0 else 0

    # Summary panel
    summary = f"""
    [bold]Scan Summary[/bold]
    ─────────────────────────────────
    Total Checks:    {total}
    [green]Passed:[/green]          {passed}
    [red]Failed:[/red]          {failed}
    [yellow]Errors:[/yellow]          {errors}
    ─────────────────────────────────
    [bold cyan]Compliance Rate: {compliance_rate:.1f}%[/bold cyan]
    """
    console.print(Panel(summary, title="Results Summary", border_style="blue"))

    # Results table
    table = Table(title="Compliance Check Results", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Category", style="magenta", width=15)
    table.add_column("Check", style="white", width=45)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Severity", justify="center", width=10)

    for check in results['checks']:
        status_color = "green" if check['status'] == 'PASS' else "red" if check['status'] == 'FAIL' else "yellow"
        severity_color = {
            'critical': 'red',
            'high': 'yellow',
            'medium': 'blue',
            'low': 'dim'
        }.get(check['severity'], 'white')

        check_name = check['name'][:42] + '...' if len(check['name']) > 45 else check['name']

        table.add_row(
            check['id'],
            check['category'],
            check_name,
            f"[{status_color}]{check['status']}[/{status_color}]",
            f"[{severity_color}]{check['severity'].upper()}[/{severity_color}]"
        )

    console.print(table)

    # Display NIST summary if available
    if 'nist_summary' in results and results['nist_summary']:
        display_nist_summary(results['nist_summary'])

    # Display failed checks with remediation
    failed_checks = [c for c in results['checks'] if c['status'] == 'FAIL']
    if failed_checks:
        console.print("\n[bold red]Failed Checks - Remediation Required[/bold red]\n")
        for check in failed_checks:
            console.print(f"[bold]{check['id']}[/bold]: {check['name']}")
            console.print(f"  [dim]Current:[/dim] {check.get('actual', 'N/A')}")
            console.print(f"  [dim]Expected:[/dim] {check.get('expected', 'N/A')}")
            console.print(f"  [yellow]Remediation:[/yellow] {check.get('remediation', 'N/A')}")
            console.print()


def display_nist_summary(nist_summary):
    """Display NIST 800-53 control coverage summary"""
    console.print("\n[bold blue]NIST 800-53 Control Coverage[/bold blue]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Control", width=10)
    table.add_column("Family", width=25)
    table.add_column("Description", width=35)
    table.add_column("Compliance", justify="center", width=12)

    for control in nist_summary.get('controls', []):
        compliance = control.get('compliance_percentage', 0)
        if compliance >= 80:
            color = "green"
        elif compliance >= 50:
            color = "yellow"
        else:
            color = "red"

        table.add_row(
            control['control_id'],
            control['control_family'],
            control['control_name'],
            f"[{color}]{compliance}%[/{color}]"
        )

    console.print(table)


def main():
    """Main entry point for the compliance scanner"""
    parser = argparse.ArgumentParser(
        description='Automated Compliance Scanner - CIS Benchmarks & NIST 800-53',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              Run basic scan with console output
  %(prog)s --output html -f report.html Generate HTML report
  %(prog)s --output json --nist-mapping Generate JSON with NIST mappings
  %(prog)s --severity high              Only show high/critical findings
  %(prog)s --categories authentication network  Scan specific categories

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
        """
    )
    parser.add_argument(
        '--output', '-o',
        choices=['html', 'json', 'csv', 'console'],
        default='console',
        help='Output format (default: console)'
    )
    parser.add_argument(
        '--output-file', '-f',
        help='Output file path'
    )
    parser.add_argument(
        '--categories', '-c',
        nargs='+',
        choices=['filesystem', 'authentication', 'network', 'logging', 'access_control', 'services'],
        help='Specific categories to scan (e.g., authentication filesystem network)'
    )
    parser.add_argument(
        '--severity', '-s',
        choices=['critical', 'high', 'medium', 'low', 'all'],
        default='all',
        help='Minimum severity to report (default: all)'
    )
    parser.add_argument(
        '--nist-mapping',
        action='store_true',
        help='Include NIST 800-53 control mappings in report'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress banner and progress output'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='%(prog)s 1.0.0'
    )

    args = parser.parse_args()

    # Display banner unless quiet mode
    if not args.quiet:
        display_banner()

    # Detect OS and initialize appropriate checker
    os_type = detect_os()

    console.print(f"[dim]Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print(f"[dim]Operating System: {os_type.upper()}[/dim]\n")

    if os_type == 'linux':
        checker = LinuxComplianceChecker()
    elif os_type == 'windows':
        checker = WindowsComplianceChecker()
    else:
        console.print("[red]Error: Unsupported operating system[/red]")
        console.print("[dim]This scanner supports Linux and Windows systems.[/dim]")
        sys.exit(1)

    # Run all checks with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task(description="Running compliance checks...", total=None)
        results = checker.run_all_checks(
            categories=args.categories,
            min_severity=args.severity
        )

    # Add NIST mappings if requested
    if args.nist_mapping:
        console.print("[dim]Adding NIST 800-53 control mappings...[/dim]")
        mapper = NISTMapper()
        results = mapper.add_nist_mappings(results)

    # Generate output based on format
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.output == 'console':
        display_console_results(results)
    elif args.output == 'html':
        generator = HTMLReportGenerator()
        report_path = args.output_file or f'compliance_report_{timestamp}.html'
        generator.generate(results, report_path)
        console.print(f"\n[green]HTML report saved to: {report_path}[/green]")
    elif args.output == 'json':
        generator = JSONReportGenerator()
        report_path = args.output_file or f'compliance_report_{timestamp}.json'
        generator.generate(results, report_path)
        console.print(f"\n[green]JSON report saved to: {report_path}[/green]")
    elif args.output == 'csv':
        generator = CSVReportGenerator()
        report_path = args.output_file or f'compliance_report_{timestamp}.csv'
        generator.generate(results, report_path)
        console.print(f"\n[green]CSV report saved to: {report_path}[/green]")

    # Return exit code based on results
    failed_count = sum(1 for c in results['checks'] if c['status'] == 'FAIL')
    critical_failed = sum(1 for c in results['checks']
                         if c['status'] == 'FAIL' and c['severity'] == 'critical')

    if critical_failed > 0:
        console.print(f"\n[bold red]WARNING: {critical_failed} critical check(s) failed![/bold red]")
        sys.exit(2)
    elif failed_count > 0:
        sys.exit(1)
    else:
        console.print("\n[bold green]All checks passed![/bold green]")
        sys.exit(0)


if __name__ == '__main__':
    main()
