# Automated Compliance Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CIS Benchmarks](https://img.shields.io/badge/CIS-Benchmarks-green.svg)](https://www.cisecurity.org/cis-benchmarks)
[![NIST 800-53](https://img.shields.io/badge/NIST-800--53-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

A Python-based security compliance scanner that checks systems against CIS Benchmarks and maps findings to NIST 800-53 security controls. Designed for security analysts performing Assessment & Authorization (A&A) activities.

## Features

- **CIS Benchmark Compliance Checks**: 40+ automated checks across 6 control categories
- **NIST 800-53 Control Mapping**: Automatic mapping to federal security controls
- **Multiple Output Formats**: Console, HTML, JSON, CSV reports
- **Severity-Based Filtering**: Focus on critical/high findings
- **Remediation Guidance**: Actionable fixes for each failed check
- **Cross-Platform**: Linux and Windows support

## Quick Start

```bash
# Clone the repository
git clone https://github.com/RaySmith414/Automated-Compliance-Scanner.git
cd Automated-Compliance-Scanner

# Install dependencies
pip install -r requirements.txt

# Run a basic scan
python -m scanner.main

# Generate HTML report with NIST mappings
python -m scanner.main --output html --nist-mapping -f compliance_report.html

# Scan only critical/high severity items
python -m scanner.main --severity high

# Scan specific categories
python -m scanner.main --categories authentication network
```

## Installation

### Prerequisites
- Python 3.8 or higher
- Root/Administrator access (required for some system checks)

### From Source
```bash
git clone https://github.com/RaySmith414/Automated-Compliance-Scanner.git
cd Automated-Compliance-Scanner
pip install -r requirements.txt
```

### As a Package
```bash
pip install -e .
compliance-scanner --help
```

## Usage

### Command Line Options

```
usage: python -m scanner.main [-h] [--output {html,json,csv,console}]
                               [--output-file FILE] [--categories CATEGORIES]
                               [--severity {critical,high,medium,low,all}]
                               [--nist-mapping] [--quiet] [--version]

Automated Compliance Scanner - CIS Benchmarks & NIST 800-53

options:
  -h, --help            show this help message and exit
  --output, -o          Output format (default: console)
  --output-file, -f     Output file path
  --categories, -c      Specific categories to scan
  --severity, -s        Minimum severity to report (default: all)
  --nist-mapping        Include NIST 800-53 control mappings
  --quiet, -q           Suppress banner and progress output
  --version, -v         Show version number
```

### Examples

```bash
# Basic console scan
python -m scanner.main

# Generate HTML report
python -m scanner.main --output html -f report.html

# Generate JSON report with NIST mappings
python -m scanner.main --output json --nist-mapping -f report.json

# Scan only authentication and network controls
python -m scanner.main --categories authentication network

# Show only high and critical findings
python -m scanner.main --severity high

# Quiet mode for scripting
python -m scanner.main --quiet --output json -f results.json
```

## Sample Output

### Console Output
```
╔═══════════════════════════════════════════════════════════════╗
║         AUTOMATED COMPLIANCE SCANNER v1.0.0                   ║
║         CIS Benchmarks | NIST 800-53 Control Mapping          ║
╚═══════════════════════════════════════════════════════════════╝

Scan started: 2024-01-15 14:30:00
Operating System: LINUX

┌─────────────────────────────────────────────────────────────────┐
│ Results Summary                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Total Checks:    42                                             │
│ Passed:          35                                             │
│ Failed:          7                                              │
│ Compliance Rate: 83.3%                                          │
└─────────────────────────────────────────────────────────────────┘

┌────────────┬────────────────┬──────────────────────────────────────┬────────┬──────────┐
│ ID         │ Category       │ Check                                │ Status │ Severity │
├────────────┼────────────────┼──────────────────────────────────────┼────────┼──────────┤
│ AUTH-007   │ authentication │ Ensure SSH root login is disabled    │ PASS   │ CRITICAL │
│ NET-007    │ network        │ Ensure firewall is active            │ FAIL   │ CRITICAL │
└────────────┴────────────────┴──────────────────────────────────────┴────────┴──────────┘
```

## Control Categories

| Category | Description | Checks |
|----------|-------------|--------|
| `filesystem` | Mount options, partition security | 7 |
| `authentication` | Password policies, SSH hardening | 10 |
| `network` | Kernel parameters, firewall | 7 |
| `logging` | Audit configuration | 5 |
| `access_control` | File permissions | 6 |
| `services` | Unnecessary services | 6 |

## NIST 800-53 Control Mapping

This scanner maps findings to the following NIST 800-53 Rev 5 control families:

| Family | Name | Description |
|--------|------|-------------|
| AC | Access Control | Account management, access enforcement, least privilege |
| AU | Audit and Accountability | Audit events, audit records, audit protection |
| CM | Configuration Management | Least functionality, system inventory |
| IA | Identification and Authentication | User identification, authenticator management |
| SC | System and Communications Protection | Boundary protection, DoS protection |

See [NIST_MAPPING.md](docs/NIST_MAPPING.md) for detailed control mappings.

## Use Cases

1. **Pre-ATO Assessment**: Run before Authority to Operate reviews
2. **Continuous Monitoring**: Schedule regular compliance checks
3. **System Hardening**: Identify and remediate security gaps
4. **Audit Preparation**: Generate evidence for security audits
5. **Baseline Validation**: Verify system configurations meet standards
6. **POA&M Generation**: Create Plan of Action & Milestones items

## Project Structure

```
Automated-Compliance-Scanner/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── setup.py                     # Package installation
├── LICENSE                      # MIT License
│
├── config/
│   ├── cis_linux_benchmark.yaml     # CIS controls for Linux
│   ├── cis_windows_benchmark.yaml   # CIS controls for Windows
│   └── nist_800_53_controls.yaml    # NIST 800-53 control mappings
│
├── scanner/
│   ├── __init__.py
│   ├── main.py                  # CLI entry point
│   ├── linux_checks.py          # Linux-specific security checks
│   ├── windows_checks.py        # Windows-specific security checks
│   ├── nist_mapper.py           # Maps findings to NIST controls
│   └── utils.py                 # Helper functions
│
├── reports/
│   ├── __init__.py
│   ├── html_report.py           # HTML report generator
│   ├── json_report.py           # JSON/machine-readable output
│   ├── csv_report.py            # CSV for spreadsheet import
│   └── templates/
│       └── report_template.html # Jinja2 HTML template
│
├── tests/
│   ├── test_linux_checks.py
│   ├── test_windows_checks.py
│   └── test_nist_mapper.py
│
├── docs/
│   ├── CONTROLS_REFERENCE.md    # Explanation of each control
│   ├── NIST_MAPPING.md          # NIST 800-53 mapping details
│   └── ADDING_CHECKS.md         # Guide for adding new checks
│
└── examples/
    ├── sample_report.html       # Example HTML output
    └── sample_report.json       # Example JSON output
```

## Requirements

- Python 3.8+
- Root/Administrator access (for some system checks)
- Linux (Ubuntu 20.04+ recommended) or Windows Server 2019+

### Python Dependencies

- pyyaml >= 6.0
- jinja2 >= 3.1
- colorama >= 0.4
- rich >= 13.0
- psutil >= 5.9
- distro >= 1.8 (Linux only)

## Contributing

Contributions are welcome! Please see [ADDING_CHECKS.md](docs/ADDING_CHECKS.md) for guidance on adding new compliance checks.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Make your changes
4. Run tests (`pytest`)
5. Submit a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Rayshaun Smith**
Senior Information Security Analyst
[LinkedIn](https://www.linkedin.com/in/rayshaun-s-6927b4103/) | [GitHub](https://github.com/RaySmith414)

## Acknowledgments

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Security configuration guidelines
- [NIST 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security control framework
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting

---

*This tool is for authorized security testing only. Always obtain proper authorization before scanning systems.*

## Skills Demonstrated

This project showcases:

| Skill Area | How It's Demonstrated |
|------------|----------------------|
| NIST RMF & Compliance | Direct NIST 800-53 control mapping |
| Security Assessments | Automated CIS Benchmark scanning |
| Python Development | Clean, modular, well-documented code |
| Security Automation | Programmatic security checking |
| Technical Documentation | Comprehensive README and docs |
| Report Generation | Multiple professional output formats |
