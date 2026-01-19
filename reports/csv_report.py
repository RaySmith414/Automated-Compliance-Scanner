"""
CSV Report Generator
Produces spreadsheet-compatible compliance reports

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import csv
from datetime import datetime
from typing import Dict


class CSVReportGenerator:
    """Generate CSV compliance reports for spreadsheet import"""

    def generate(self, results: Dict, output_path: str):
        """Generate CSV report from scan results"""
        fieldnames = [
            'Check ID',
            'Category',
            'Check Name',
            'Severity',
            'Status',
            'Current State',
            'Expected State',
            'Remediation',
            'NIST Controls'
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for check in results.get('checks', []):
                # Format NIST controls as comma-separated string
                nist_controls = ', '.join([
                    nc.get('control_id', '')
                    for nc in check.get('nist_controls', [])
                ])

                writer.writerow({
                    'Check ID': check.get('id', ''),
                    'Category': check.get('category', ''),
                    'Check Name': check.get('name', ''),
                    'Severity': check.get('severity', '').upper(),
                    'Status': check.get('status', ''),
                    'Current State': check.get('actual', ''),
                    'Expected State': check.get('expected', ''),
                    'Remediation': check.get('remediation', ''),
                    'NIST Controls': nist_controls
                })

        # Also generate a summary CSV
        summary_path = output_path.replace('.csv', '_summary.csv')
        self._generate_summary_csv(results, summary_path)

    def _generate_summary_csv(self, results: Dict, output_path: str):
        """Generate a summary CSV with statistics"""
        checks = results.get('checks', [])
        total = len(checks)
        passed = sum(1 for c in checks if c.get('status') == 'PASS')
        failed = sum(1 for c in checks if c.get('status') == 'FAIL')

        # Category statistics
        categories = {}
        for check in checks:
            cat = check.get('category', 'other')
            if cat not in categories:
                categories[cat] = {'total': 0, 'passed': 0, 'failed': 0}
            categories[cat]['total'] += 1
            if check.get('status') == 'PASS':
                categories[cat]['passed'] += 1
            elif check.get('status') == 'FAIL':
                categories[cat]['failed'] += 1

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Overall summary
            writer.writerow(['Compliance Scan Summary'])
            writer.writerow(['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Hostname', results.get('system_info', {}).get('hostname', 'Unknown')])
            writer.writerow([])

            writer.writerow(['Overall Statistics'])
            writer.writerow(['Total Checks', total])
            writer.writerow(['Passed', passed])
            writer.writerow(['Failed', failed])
            writer.writerow(['Compliance Rate', f'{round((passed/total*100), 1) if total > 0 else 0}%'])
            writer.writerow([])

            # Category breakdown
            writer.writerow(['Category Breakdown'])
            writer.writerow(['Category', 'Total', 'Passed', 'Failed', 'Compliance Rate'])
            for cat, stats in sorted(categories.items()):
                rate = round((stats['passed'] / stats['total'] * 100), 1) if stats['total'] > 0 else 0
                writer.writerow([
                    cat.replace('_', ' ').title(),
                    stats['total'],
                    stats['passed'],
                    stats['failed'],
                    f'{rate}%'
                ])
            writer.writerow([])

            # NIST control summary if available
            nist_summary = results.get('nist_summary')
            if nist_summary:
                writer.writerow(['NIST 800-53 Control Coverage'])
                writer.writerow(['Control ID', 'Control Name', 'Checks Passed', 'Checks Total', 'Compliance Rate'])
                for control in nist_summary.get('controls', []):
                    writer.writerow([
                        control.get('control_id', ''),
                        control.get('control_name', ''),
                        control.get('checks_passed', 0),
                        control.get('checks_total', 0),
                        f'{control.get("compliance_percentage", 0)}%'
                    ])
