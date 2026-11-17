"""JSON report for automation and evidence archives."""

import json
from typing import Any, Dict, List

from scanner.model import SEVERITIES

REPORT_FORMAT = "compliance-scanner-v2"


class JSONReportGenerator:
    def build(self, result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "report_format": REPORT_FORMAT,
                "tool": "Automated Compliance Scanner",
                "scanner_version": result["scanner_version"],
                "generated_at": result["scan_time"],
            },
            "platform": result["platform"],
            "privileged": result["privileged"],
            "benchmark": result["benchmark"],
            "system_info": result["system_info"],
            "summary": result["summary"],
            "checks": result["checks"],
            "framework_summary": result["framework_summary"],
            "recommendations": self._recommendations(result["checks"]),
        }

    def generate(self, result: Dict[str, Any], output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(self.build(result), handle, indent=2)
            handle.write("\n")

    @staticmethod
    def _recommendations(checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Failed checks, most severe first."""
        failed = [c for c in checks if c["status"] == "FAIL"]
        failed.sort(key=lambda c: (SEVERITIES.index(c["severity"]), c["id"]))
        return [{
            "priority": c["severity"],
            "check_id": c["id"],
            "title": c["title"],
            "current_state": c["actual"],
            "expected_state": c["expected"],
            "remediation": c["remediation"],
            "nist_800_53": [x["control_id"] for x in c["frameworks"]["nist_800_53"]],
        } for c in failed]
