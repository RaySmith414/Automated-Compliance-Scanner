# Sample reports

These files are the unedited output of one scan with scanner version 2.0.0.

**The host.** A minimal Ubuntu 22.04 LTS install in an isolated lab environment, scanned as root with the Python packages Ubuntu 22.04 ships (PyYAML 5.4.1, Jinja2 3.0.3, rich 11.2.0). The lab runs on a virtual machine kernel that has no loadable module support, so the kernel version in the reports is not Ubuntu's stock kernel.

**Its state.** The host was hardened first: password aging in `/etc/login.defs`, an SSH drop-in that turns off root and password logins, journald compression and persistent storage, rsyslog enabled and `/tmp` on its own mount with `noexec`, `nosuid` and `nodev`. The network settings and the firewall were left at their defaults on purpose, so the reports show real findings.

**The result.** 41 checks: 34 passed, 5 failed, 1 needs manual review and 1 is not applicable. The compliance rate is 87.2 percent and the exit code was 2 because one critical check failed (no host firewall).

| File | Command |
| --- | --- |
| `sample_console.txt` | `compliance-scanner --frameworks nist` |
| `sample_report.html` | `compliance-scanner --output html -f sample_report.html` |
| `sample_report.json` | `compliance-scanner --output json -f sample_report.json` |
| `sample_report.csv`, `sample_report_summary.csv` | `compliance-scanner --output csv -f sample_report.csv` |
| `sample_poam.csv` | `compliance-scanner --output poam -f sample_poam.csv` |

GitHub shows the HTML file as source. Download it and open it in a browser to see the report.
