"""
HTML Report Generator
Produces professional compliance reports

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

from datetime import datetime
from jinja2 import Template
from typing import Dict


class HTMLReportGenerator:
    """Generate HTML compliance reports"""

    def __init__(self):
        self.template = self._get_template()

    def _get_template(self) -> str:
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Scan Report - {{ scan_date }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2rem; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.9; font-size: 1.1rem; }
        .header-meta { margin-top: 20px; opacity: 0.85; }
        .header-meta p { margin: 5px 0; }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
            transition: transform 0.2s ease;
        }
        .stat-card:hover { transform: translateY(-2px); }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        .stat-label { color: #666; margin-top: 5px; font-size: 0.95rem; }
        .stat-pass { color: #48bb78; }
        .stat-fail { color: #f56565; }
        .stat-rate { color: #4299e1; }

        /* Sections */
        .section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }
        .section h2 {
            font-size: 1.3rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #edf2f7;
            color: #2d3748;
        }

        /* Table */
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #edf2f7; }
        th { background: #f7fafc; font-weight: 600; color: #4a5568; }
        tr:hover { background: #f7fafc; }

        /* Status badges */
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
            display: inline-block;
        }
        .badge-pass { background: #c6f6d5; color: #276749; }
        .badge-fail { background: #fed7d7; color: #c53030; }
        .badge-error { background: #feebc8; color: #c05621; }

        /* Severity */
        .severity {
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
            display: inline-block;
        }
        .severity-critical { background: #c53030; color: white; }
        .severity-high { background: #ed8936; color: white; }
        .severity-medium { background: #ecc94b; color: #744210; }
        .severity-low { background: #a0aec0; color: white; }

        /* NIST Controls */
        .nist-tag {
            display: inline-block;
            background: #ebf8ff;
            color: #2b6cb0;
            padding: 2px 8px;
            border-radius: 4px;
            margin: 2px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        /* Expandable details */
        .check-details {
            padding: 15px;
            background: #f7fafc;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 3px solid #e2e8f0;
        }
        .check-details dt { font-weight: 600; color: #4a5568; margin-top: 10px; }
        .check-details dt:first-child { margin-top: 0; }
        .check-details dd { margin-left: 0; margin-top: 5px; color: #718096; }
        .remediation {
            background: #fffaf0;
            border-left: 4px solid #ed8936;
            padding: 10px 15px;
            margin-top: 10px;
            border-radius: 0 5px 5px 0;
        }

        /* Progress bar */
        .progress-bar {
            height: 8px;
            background: #edf2f7;
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: #48bb78;
            transition: width 0.3s ease;
        }
        .progress-fill.warning { background: #ecc94b; }
        .progress-fill.danger { background: #f56565; }

        /* Executive Summary */
        .exec-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .summary-item {
            padding: 15px;
            background: #f7fafc;
            border-radius: 8px;
        }
        .summary-item h4 {
            margin-bottom: 10px;
            color: #2d3748;
        }

        /* Footer */
        .footer {
            text-align: center;
            color: #a0aec0;
            padding: 30px 20px;
            font-size: 0.9rem;
            border-top: 1px solid #edf2f7;
            margin-top: 20px;
        }
        .footer a { color: #4299e1; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }

        /* Print styles */
        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #edf2f7; }
            .header { background: #1a365d !important; -webkit-print-color-adjust: exact; }
            .stat-card { box-shadow: none; border: 1px solid #edf2f7; }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 15px; }
            .header { padding: 25px; }
            .header h1 { font-size: 1.5rem; }
            table { font-size: 0.9rem; }
            th, td { padding: 8px 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Compliance Scan Report</h1>
            <p class="subtitle">CIS Benchmark Assessment with NIST 800-53 Control Mapping</p>
            <div class="header-meta">
                <p><strong>Hostname:</strong> {{ system_info.hostname }}</p>
                <p><strong>Operating System:</strong> {{ system_info.distribution }}</p>
                <p><strong>Kernel:</strong> {{ system_info.kernel }}</p>
                <p><strong>Scan Date:</strong> {{ scan_date }}</p>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ total_checks }}</div>
                <div class="stat-label">Total Checks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-pass">{{ passed_checks }}</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-fail">{{ failed_checks }}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-rate">{{ compliance_rate }}%</div>
                <div class="stat-label">Compliance Rate</div>
                <div class="progress-bar" style="margin-top: 10px;">
                    <div class="progress-fill {% if compliance_rate < 50 %}danger{% elif compliance_rate < 80 %}warning{% endif %}"
                         style="width: {{ compliance_rate }}%;"></div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="exec-summary">
                <div class="summary-item">
                    <h4>Critical Findings</h4>
                    <p>{{ critical_failed }} critical check(s) require immediate attention.</p>
                </div>
                <div class="summary-item">
                    <h4>High Priority</h4>
                    <p>{{ high_failed }} high severity finding(s) should be addressed promptly.</p>
                </div>
                <div class="summary-item">
                    <h4>Categories Scanned</h4>
                    <p>{{ categories_count }} control categories were assessed.</p>
                </div>
            </div>
        </div>

        {% if nist_summary %}
        <div class="section">
            <h2>NIST 800-53 Control Coverage</h2>
            <table>
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Family</th>
                        <th>Description</th>
                        <th>Checks</th>
                        <th>Compliance</th>
                    </tr>
                </thead>
                <tbody>
                    {% for control in nist_summary.controls %}
                    <tr>
                        <td><strong>{{ control.control_id }}</strong></td>
                        <td>{{ control.control_family }}</td>
                        <td>{{ control.control_name }}</td>
                        <td>{{ control.checks_passed }}/{{ control.checks_total }}</td>
                        <td>
                            <div class="progress-bar" style="width: 100px; display: inline-block; vertical-align: middle;">
                                <div class="progress-fill {% if control.compliance_percentage < 50 %}danger{% elif control.compliance_percentage < 80 %}warning{% endif %}"
                                     style="width: {{ control.compliance_percentage }}%;"></div>
                            </div>
                            <span style="margin-left: 10px;">{{ control.compliance_percentage }}%</span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% for category, category_checks in checks_by_category.items() %}
        <div class="section">
            <h2>{{ category | title | replace('_', ' ') }}</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 80px;">ID</th>
                        <th>Check</th>
                        <th style="width: 90px;">Severity</th>
                        <th style="width: 80px;">Status</th>
                        <th style="width: 150px;">NIST Controls</th>
                    </tr>
                </thead>
                <tbody>
                    {% for check in category_checks %}
                    <tr>
                        <td><code>{{ check.id }}</code></td>
                        <td>
                            <strong>{{ check.name }}</strong>
                            {% if check.status == 'FAIL' %}
                            <div class="check-details">
                                <dl>
                                    <dt>Current State:</dt>
                                    <dd>{{ check.actual }}</dd>
                                    <dt>Expected:</dt>
                                    <dd>{{ check.expected }}</dd>
                                    {% if check.remediation %}
                                    <dt>Remediation:</dt>
                                    <dd class="remediation">{{ check.remediation }}</dd>
                                    {% endif %}
                                </dl>
                            </div>
                            {% endif %}
                        </td>
                        <td><span class="severity severity-{{ check.severity }}">{{ check.severity | upper }}</span></td>
                        <td><span class="badge badge-{{ check.status | lower }}">{{ check.status }}</span></td>
                        <td>
                            {% for nist in check.nist_controls %}
                            <span class="nist-tag">{{ nist.control_id }}</span>
                            {% endfor %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endfor %}

        <div class="footer">
            <p>Generated by <strong>Automated Compliance Scanner v1.0.0</strong></p>
            <p>Based on CIS Benchmarks with NIST 800-53 Rev 5 Control Mapping</p>
            <p style="margin-top: 10px;">
                Author: <a href="https://github.com/RaySmith414">Rayshaun Smith</a>
            </p>
        </div>
    </div>
</body>
</html>
'''

    def generate(self, results: Dict, output_path: str):
        """Generate HTML report from scan results"""
        # Group checks by category
        checks_by_category = {}
        for check in results.get('checks', []):
            category = check.get('category', 'other')
            if category not in checks_by_category:
                checks_by_category[category] = []
            checks_by_category[category].append(check)

        # Calculate statistics
        checks = results.get('checks', [])
        total = len(checks)
        passed = sum(1 for c in checks if c.get('status') == 'PASS')
        failed = sum(1 for c in checks if c.get('status') == 'FAIL')

        # Count by severity
        critical_failed = sum(1 for c in checks if c.get('status') == 'FAIL' and c.get('severity') == 'critical')
        high_failed = sum(1 for c in checks if c.get('status') == 'FAIL' and c.get('severity') == 'high')

        template = Template(self.template)
        html_content = template.render(
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            system_info=results.get('system_info', {}),
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            compliance_rate=round((passed / total * 100), 1) if total > 0 else 0,
            critical_failed=critical_failed,
            high_failed=high_failed,
            categories_count=len(checks_by_category),
            checks_by_category=checks_by_category,
            nist_summary=results.get('nist_summary')
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
