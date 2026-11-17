"""CSV reports: one row per check plus a summary file."""

import csv
from pathlib import Path
from typing import Any, Dict, List

from scanner.model import CATEGORIES

FIELDS = [
    "Check ID", "CIS ID", "Category", "Check", "Severity", "Status", "Found", "Expected", "Remediation",
    "NIST 800-53", "SOC 2", "ISO 27001",
]


def spreadsheet_safe(value: Any) -> str:
    """Stop a spreadsheet from treating collected text as a formula.

    Text from the scanned host can start with =, +, - or @. A leading apostrophe
    makes Excel and similar tools show it as plain text.
    """
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def summary_path_for(output_path: str) -> Path:
    """Path of the summary file: <name>_summary.csv next to the main file."""
    path = Path(output_path)
    return path.with_name(f"{path.stem}_summary.csv")


def _ids(check: Dict[str, Any], key: str) -> str:
    return ", ".join(control["control_id"] for control in check["frameworks"][key])


class CSVReportGenerator:
    def generate(self, result: Dict[str, Any], output_path: str) -> List[str]:
        """Write both files and return their paths."""
        main = Path(output_path)
        summary = summary_path_for(output_path)
        with open(main, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            for check in result["checks"]:
                writer.writerow({
                    "Check ID": check["id"],
                    "CIS ID": check["cis"]["id"] or "",
                    "Category": check["category"],
                    "Check": check["title"],
                    "Severity": check["severity"].upper(),
                    "Status": check["status"],
                    "Found": spreadsheet_safe(check["actual"]),
                    "Expected": spreadsheet_safe(check["expected"]),
                    "Remediation": spreadsheet_safe(check["remediation"]),
                    "NIST 800-53": _ids(check, "nist_800_53"),
                    "SOC 2": _ids(check, "soc2"),
                    "ISO 27001": _ids(check, "iso_27001"),
                })
        self._write_summary(result, summary)
        return [str(main), str(summary)]

    @staticmethod
    def _rate(value) -> str:
        return "n/a" if value is None else f"{value}%"

    def _write_summary(self, result: Dict[str, Any], path: Path) -> None:
        totals = result["summary"]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Compliance Scan Summary"])
            writer.writerow(["Scan time (UTC)", result["scan_time"]])
            writer.writerow(["Host", spreadsheet_safe(result["system_info"]["hostname"])])
            writer.writerow(["Operating system", spreadsheet_safe(result["system_info"]["distribution"])])
            writer.writerow([])
            writer.writerow(["Checks run", totals["total_checks"]])
            writer.writerow(["Passed", totals["passed"]])
            writer.writerow(["Failed", totals["failed"]])
            writer.writerow(["Not assessed (error)", totals["errors"]])
            writer.writerow(["Manual review", totals["manual"]])
            writer.writerow(["Not applicable", totals["not_applicable"]])
            writer.writerow(["Compliance rate (pass / assessed)", self._rate(totals["compliance_rate"])])
            writer.writerow([])
            writer.writerow(["Category", "Checks", "Passed", "Failed", "No verdict"])
            for category in CATEGORIES:
                checks = [c for c in result["checks"] if c["category"] == category]
                if not checks:
                    continue
                passed = sum(1 for c in checks if c["status"] == "PASS")
                failed = sum(1 for c in checks if c["status"] == "FAIL")
                writer.writerow([category, len(checks), passed, failed, len(checks) - passed - failed])
            for section in result["framework_summary"].values():
                writer.writerow([])
                writer.writerow([section["label"]])
                writer.writerow(["Control", "Name", "Passed", "Failed", "No verdict", "Compliance"])
                for control in section["controls"]:
                    writer.writerow([
                        control["control_id"], control["control_name"], control["checks_passed"],
                        control["checks_failed"], control["checks_no_verdict"],
                        self._rate(control["compliance_percentage"]),
                    ])
