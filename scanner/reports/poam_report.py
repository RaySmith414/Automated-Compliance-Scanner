"""Plan of Action and Milestones (POA&M) worksheet.

One row per failed check, in the column order most POA&M trackers use. It is a
starting worksheet for the system owner, not a completed POA&M: owners,
resources and milestones are left blank on purpose.
"""

import csv
from datetime import datetime, timedelta
from typing import Any, Dict, List

from scanner.model import SEVERITIES
from scanner.reports.csv_report import spreadsheet_safe

# Days allowed to remediate, by scanner severity. These follow the common
# 30 / 90 / 180 day convention for high, moderate and low findings.
DEFAULT_DUE_DAYS = {"critical": 30, "high": 30, "medium": 90, "low": 180}
RISK_RATING = {"critical": "High", "high": "High", "medium": "Moderate", "low": "Low"}

FIELDS = [
    "POA&M ID", "Controls", "Weakness Name", "Weakness Description", "Weakness Detector Source",
    "Weakness Source Identifier", "Asset Identifier", "Point of Contact", "Resources Required",
    "Overall Remediation Plan", "Original Detection Date", "Scheduled Completion Date",
    "Planned Milestones", "Status", "Original Risk Rating", "Comments",
]


def _source_id(check: Dict[str, Any]) -> str:
    cis_id = check["cis"]["id"]
    return f"{check['id']} (CIS {cis_id})" if cis_id else check["id"]


class POAMReportGenerator:
    def __init__(self, due_days: Dict[str, int] = None):
        self.due_days = dict(DEFAULT_DUE_DAYS, **(due_days or {}))

    def rows(self, result: Dict[str, Any]) -> List[Dict[str, str]]:
        detected = datetime.strptime(result["scan_time"], "%Y-%m-%dT%H:%M:%SZ").date()
        failed = [c for c in result["checks"] if c["status"] == "FAIL"]
        failed.sort(key=lambda c: (SEVERITIES.index(c["severity"]), c["id"]))
        rows = []
        for number, check in enumerate(failed, start=1):
            due = detected + timedelta(days=self.due_days[check["severity"]])
            rows.append({
                "POA&M ID": f"{detected:%Y}-{number:03d}",
                "Controls": ", ".join(c["control_id"] for c in check["frameworks"]["nist_800_53"]),
                "Weakness Name": check["title"],
                "Weakness Description": spreadsheet_safe(f"Found: {check['actual']}. Expected: {check['expected']}."),
                "Weakness Detector Source": f"Automated Compliance Scanner {result['scanner_version']}",
                "Weakness Source Identifier": _source_id(check),
                "Asset Identifier": spreadsheet_safe(result["system_info"]["hostname"]),
                "Point of Contact": "",
                "Resources Required": "",
                "Overall Remediation Plan": spreadsheet_safe(check["remediation"]),
                "Original Detection Date": detected.isoformat(),
                "Scheduled Completion Date": due.isoformat(),
                "Planned Milestones": "",
                "Status": "Open",
                "Original Risk Rating": RISK_RATING[check["severity"]],
                "Comments": f"Scanner severity: {check['severity']}",
            })
        return rows

    def generate(self, result: Dict[str, Any], output_path: str) -> int:
        """Write the worksheet and return the number of rows."""
        rows = self.rows(result)
        with open(output_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)
