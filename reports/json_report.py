"""
JSON Report Generator
Produces machine-readable compliance reports

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import json
from datetime import datetime
from typing import Dict


class JSONReportGenerator:
    """Generate JSON compliance reports for automation/integration"""

    def generate(self, results: Dict, output_path: str):
        """Generate JSON report from scan results"""
        # Add metadata
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'report_format': 'compliance-scanner-v1',
                'author': 'Rayshaun Smith',
                'tool': 'Automated Compliance Scanner'
            },
            'system_info': results.get('system_info', {}),
            'summary': self._generate_summary(results),
            'checks': results.get('checks', []),
            'nist_summary': results.get('nist_summary'),
            'recommendations': self._generate_recommendations(results)
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate summary statistics"""
        checks = results.get('checks', [])
        total = len(checks)
        passed = sum(1 for c in checks if c.get('status') == 'PASS')
        failed = sum(1 for c in checks if c.get('status') == 'FAIL')
        errors = sum(1 for c in checks if c.get('status') == 'ERROR')

        # Group by severity
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        failed_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for check in checks:
            severity = check.get('severity', 'low')
            by_severity[severity] = by_severity.get(severity, 0) + 1
            if check.get('status') == 'FAIL':
                failed_by_severity[severity] = failed_by_severity.get(severity, 0) + 1

        # Group by category
        by_category = {}
        for check in checks:
            category = check.get('category', 'other')
            if category not in by_category:
                by_category[category] = {'total': 0, 'passed': 0, 'failed': 0}
            by_category[category]['total'] += 1
            if check.get('status') == 'PASS':
                by_category[category]['passed'] += 1
            elif check.get('status') == 'FAIL':
                by_category[category]['failed'] += 1

        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'compliance_rate': round((passed / total * 100), 2) if total > 0 else 0,
            'checks_by_severity': by_severity,
            'failed_by_severity': failed_by_severity,
            'checks_by_category': by_category,
            'scan_timestamp': results.get('scan_time', datetime.now().isoformat())
        }

    def _generate_recommendations(self, results: Dict) -> list:
        """Generate prioritized recommendations based on failed checks"""
        recommendations = []

        # Priority order: critical > high > medium > low
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

        failed_checks = [
            c for c in results.get('checks', [])
            if c.get('status') == 'FAIL'
        ]

        # Sort by severity
        failed_checks.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 999))

        for check in failed_checks:
            recommendations.append({
                'priority': check.get('severity', 'low'),
                'check_id': check.get('id', ''),
                'check_name': check.get('name', ''),
                'category': check.get('category', ''),
                'current_state': check.get('actual', ''),
                'expected_state': check.get('expected', ''),
                'remediation': check.get('remediation', ''),
                'nist_controls': [
                    nc.get('control_id') for nc in check.get('nist_controls', [])
                ]
            })

        return recommendations
