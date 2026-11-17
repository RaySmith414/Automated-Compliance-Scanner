"""Result model shared by the checks, the runner and the report writers."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = ("filesystem", "authentication", "network", "logging", "access_control", "services")
FRAMEWORK_KEYS = ("nist_800_53", "soc2", "iso_27001")


class Status(str, Enum):
    """Outcome of one check.

    Only PASS and FAIL count toward the compliance rate. The other three mean
    the scanner could not give a verdict and they are reported separately.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"                    # the check could not be assessed
    NOT_APPLICABLE = "NOT_APPLICABLE"  # the control does not apply to this host
    MANUAL = "MANUAL"                  # evidence collected, a person must decide


class Unassessable(Exception):
    """Raised by a check or probe when the state cannot be read. Becomes ERROR."""


class NotApplicable(Exception):
    """Raised by a check when the control does not apply. Becomes NOT_APPLICABLE."""


@dataclass(frozen=True)
class Outcome:
    status: Status
    actual: str


def passed(actual: str) -> Outcome:
    return Outcome(Status.PASS, actual)


def failed(actual: str) -> Outcome:
    return Outcome(Status.FAIL, actual)


def manual(actual: str) -> Outcome:
    return Outcome(Status.MANUAL, actual)


@dataclass(frozen=True)
class CheckDef:
    """One catalog entry, loaded from scanner/data/checks_<platform>.yaml."""

    id: str
    function: str
    title: str
    category: str
    severity: str
    requires_root: bool
    expected: str
    remediation: str
    is_cis: bool
    cis_id: Optional[str]
    nist_800_53: List[str] = field(default_factory=list)
    soc2: List[str] = field(default_factory=list)
    iso_27001: List[str] = field(default_factory=list)


def summarize(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Count results by status and compute the compliance rate.

    The rate is PASS / (PASS + FAIL). It is None when nothing could be assessed,
    so an unreadable host never shows up as 0 percent or 100 percent.
    """
    counts = {s.value: 0 for s in Status}
    for check in checks:
        counts[check["status"]] += 1
    assessed = counts["PASS"] + counts["FAIL"]
    rate = round(counts["PASS"] / assessed * 100, 1) if assessed else None
    failed_by_severity = {sev: 0 for sev in SEVERITIES}
    for check in checks:
        if check["status"] == Status.FAIL.value:
            failed_by_severity[check["severity"]] += 1
    return {
        "total_checks": len(checks),
        "passed": counts["PASS"],
        "failed": counts["FAIL"],
        "errors": counts["ERROR"],
        "not_applicable": counts["NOT_APPLICABLE"],
        "manual": counts["MANUAL"],
        "assessed": assessed,
        "compliance_rate": rate,
        "failed_by_severity": failed_by_severity,
    }


def exit_code(checks: List[Dict[str, Any]]) -> int:
    """Process exit code for a finished scan.

    0  every assessed check passed and nothing errored
    1  at least one check failed
    2  at least one critical check failed
    3  nothing failed, but at least one check could not be assessed
    """
    statuses = [c["status"] for c in checks]
    if any(c["status"] == "FAIL" and c["severity"] == "critical" for c in checks):
        return 2
    if "FAIL" in statuses:
        return 1
    if "ERROR" in statuses:
        return 3
    return 0
