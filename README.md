# Automated Compliance Scanner

[![CI](https://github.com/RaySmith414/Automated-Compliance-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/RaySmith414/Automated-Compliance-Scanner/actions/workflows/ci.yml)

A read-only host scanner for Linux and Windows. It checks a machine against a set of CIS Benchmark recommendations, records what it found for each one and maps every finding to NIST SP 800-53 Rev. 5, SOC 2 and ISO/IEC 27001:2022 controls. Reports come out as console tables, HTML, JSON, CSV or a POA&M worksheet.

It is built for the first pass of a control validation: run it on a host, see which settings fail and hand the system owner a worksheet with the findings already tied to control IDs.

## What it does

- Runs 41 checks on Linux and 32 on Windows across six categories: filesystem, authentication, network, logging, access control and services.
- Reports five outcomes per check, so a check that could not run is never counted as compliant.
- Maps each check to NIST SP 800-53 Rev. 5, the SOC 2 Trust Services Criteria and ISO/IEC 27001:2022 Annex A.
- Writes a POA&M worksheet with one row per failed check, a due date set by severity and the related controls filled in.
- Keeps every check definition in YAML. Titles, severities, remediation text and mappings are data, not code.
- Never changes the host. Commands run as argument lists without a shell and the scanner opens no network connections.

## Quick start

Requires Python 3.9 or newer.

```bash
git clone https://github.com/RaySmith414/Automated-Compliance-Scanner.git
cd Automated-Compliance-Scanner
python3 -m venv .venv
.venv/bin/pip install .

sudo .venv/bin/compliance-scanner                                # console report
sudo .venv/bin/compliance-scanner --output html -f report.html   # HTML report
sudo .venv/bin/compliance-scanner --output poam -f poam.csv      # POA&M worksheet
```

On Windows, open PowerShell as an administrator:

```powershell
py -m venv .venv
.venv\Scripts\pip install .
.venv\Scripts\compliance-scanner --output html -f report.html
```

Run it as root or as an administrator for a full scan. Without those rights the scanner still runs. Checks it cannot read are reported as ERROR and the report says the scan was partial.

## Usage

```text
compliance-scanner [--output {console,html,json,csv,poam}] [--output-file FILE]
                   [--categories CATEGORY ...] [--severity {critical,high,medium,low,all}]
                   [--frameworks {nist,soc2,iso27001} ...] [--find-timeout SECONDS]
                   [--list-checks] [--platform {linux,windows}] [--quiet] [--version]
```

| Option | What it does |
| --- | --- |
| `--output`, `-o` | Report format. `console` is the default. The other formats need `--output-file`. |
| `--output-file`, `-f` | File to write. |
| `--categories`, `-c` | Run only these categories: `filesystem`, `authentication`, `network`, `logging`, `access_control`, `services`. |
| `--severity`, `-s` | Run only checks at this severity or above. |
| `--frameworks` | Add control coverage tables for `nist`, `soc2` or `iso27001` to console output. |
| `--find-timeout` | Time limit in seconds per file system for file searches. Default 120. |
| `--list-checks` | Print the check catalog and exit. Add `--platform` to see the other platform's catalog. |
| `--quiet`, `-q` | Print nothing except the requested output. |

```bash
compliance-scanner --categories authentication network --severity high
compliance-scanner --frameworks nist soc2
compliance-scanner --output json -f scan.json --quiet
compliance-scanner --list-checks --platform windows
```

## Reading the results

Each check ends in one of five statuses:

| Status | Meaning | In the compliance rate |
| --- | --- | --- |
| `PASS` | The host meets the expected state. | Yes |
| `FAIL` | The host does not meet it. | Yes |
| `ERROR` | The check could not be assessed: a missing tool, no permission, a timeout or output that could not be read. | No |
| `NOT_APPLICABLE` | The control does not apply to this host. | No |
| `MANUAL` | The scanner collected evidence that a person has to judge. | No |

The compliance rate is `PASS / (PASS + FAIL)`. When nothing could be assessed the rate reads `n/a`, so an unreadable host never shows up as 0 or 100 percent.

Exit codes make the scanner usable in scripts and pipelines:

| Code | Meaning |
| --- | --- |
| 0 | Every assessed check passed and nothing errored. |
| 1 | At least one check failed. |
| 2 | At least one critical check failed. |
| 3 | Nothing failed, but at least one check could not be assessed. |
| 64 | Usage error or unsupported platform. |

## Sample output

The files in [`examples/`](examples/) come from a real scan of an Ubuntu 22.04 LTS lab host. The console report starts like this:

```text
Host: ubuntu2204-lab   OS: Ubuntu 22.04 LTS   Scan time (UTC): 2026-11-17T23:33:30Z
Checks run: 41   Passed: 34   Failed: 5   Not assessed: 0   Manual review: 1   Not applicable: 1
Compliance rate (pass / assessed): 87.2%
```

and lists what to fix:

```text
LNX-NET-007 Ensure a host firewall is active
  Found:    iptables has no rules and accepts by default
  Expected: ufw, firewalld, nftables or iptables is active with a filtering rule set
  Fix:      Enable one host firewall, for example "ufw enable" after allowing the services the host needs.
```

| File | Format |
| --- | --- |
| [`sample_report.html`](examples/sample_report.html) | HTML report with control coverage and per-check detail |
| [`sample_report.json`](examples/sample_report.json) | Full result for other tools to read |
| [`sample_report.csv`](examples/sample_report.csv), [`sample_report_summary.csv`](examples/sample_report_summary.csv) | One row per check plus a summary |
| [`sample_poam.csv`](examples/sample_poam.csv) | POA&M worksheet |
| [`sample_console.txt`](examples/sample_console.txt) | Console report |

## POA&M worksheet

`--output poam` writes one row per failed check in the column order most POA&M trackers use: ID, controls, weakness name, description, detector source, source identifier, asset, point of contact, resources, remediation plan, detection date, scheduled completion date, milestones, status, risk rating and comments.

Scheduled completion dates follow the common 30, 90 and 180 day convention: 30 days for critical and high findings, 90 for medium and 180 for low. Point of contact, resources and milestones are left blank on purpose. The worksheet is a starting point for the system owner, not a finished POA&M.

## Checks

| Category | Linux | Windows |
| --- | --- | --- |
| Filesystem | 7 | 2 |
| Authentication | 10 | 10 |
| Network | 7 | 5 |
| Logging | 5 | 5 |
| Access control | 6 | 5 |
| Services | 6 | 5 |
| **Total** | **41** | **32** |

[`docs/CHECKS.md`](docs/CHECKS.md) lists every check with its expected state and remediation. The Linux catalog is written against Ubuntu 22.04 LTS and also runs on 24.04. The Windows catalog targets Windows Server 2022 and 2025.

This is a focused subset. A full CIS Benchmark holds several hundred recommendations, so a clean scan here does not mean a host meets the whole benchmark.

CIS recommendations are cited by title. Recommendation numbers change between benchmark versions, so the `cis_id` field ships empty. Fill it in from the version your organization follows and it appears in every report. A few checks are hygiene checks that are not CIS recommendations. The check reference marks them.

## Framework mappings

[`docs/MAPPINGS.md`](docs/MAPPINGS.md) shows the controls each check maps to. Reports group results by control, so one failed check shows up under every control it gives evidence for.

The mappings are an informative crosswalk prepared for triage and reporting. They are not an official mapping published by NIST, the AICPA, ISO or CIS. Validate them against your own control set before you rely on them in an assessment.

## How it is tested

- **Unit tests.** Every check runs against a fake host: first a clean host where each check has a passing answer, then one changed fact per case. Every check has at least one case that ends in something other than `PASS`. A separate group proves that a missing tool, a timeout, a denied read or unreadable output never produces `PASS`.
- **Ubuntu containers.** CI scans stock Ubuntu 22.04 and 24.04 images in two states: a baseline with OpenSSH installed and a hardened state with the recommended settings applied. Each run compares 29 verdicts with the expected result.
- **Windows hosts.** CI scans Windows Server 2022 and 2025 runners and compares what the scanner read with separate tools (`net accounts`, `reg`, `sc` and `netsh`).
- **Catalog and docs.** Tests fail when a catalog entry has no test logic, when a mapped control is missing from the reference data or when the generated docs fall out of step with the catalogs.

The suite runs on Python 3.9 through 3.13.

```bash
python -m pip install -e ".[dev]"
ruff check .
python -m pytest
```

## Limits

- It scans the machine it runs on. There is no remote or agentless mode.
- The Linux checks are written for Ubuntu. Package checks understand `dpkg` and `rpm`, but other distributions are untested.
- Password aging checks read the system defaults in `/etc/login.defs`. They do not inspect each account.
- Inside a container the kernel module and sysctl checks describe the kernel the container shares with its host.
- File searches cover local file systems and stop at the time limit. A search that hits the limit is reported as `ERROR`.
- The Windows audit policy checks read English `auditpol` output. On other display languages they report `ERROR`.

## Project layout

```text
scanner/
  main.py               command line interface
  runner.py             runs the catalog against a host and builds the result
  probe.py              read-only access to the host (files, stats, commands)
  linux_checks.py       test logic for the Linux checks
  windows_checks.py     test logic for the Windows checks
  catalog.py            loads and validates the YAML catalogs
  model.py              statuses, summary and exit codes
  docs.py               generates docs/CHECKS.md and docs/MAPPINGS.md
  data/                 check catalogs and framework reference data (YAML)
  reports/              HTML, JSON, CSV and POA&M writers
tests/                  unit tests, container state tests and the live Windows check
docs/                   check reference, mappings and the guide for adding checks
examples/               sample reports from a real scan
```

To add a check, follow [`docs/ADDING_CHECKS.md`](docs/ADDING_CHECKS.md).

## License

MIT. See [LICENSE](LICENSE).

CIS Benchmarks are published by the Center for Internet Security. This project is independent. It is not affiliated with or endorsed by CIS, NIST, the AICPA or ISO.

## Author

Rayshaun Smith ([GitHub](https://github.com/RaySmith414))
