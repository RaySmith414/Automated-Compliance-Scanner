"""Scan assembly: filtering, status handling, the score and the exit code."""

import pytest

from scanner.catalog import load_checks
from scanner.linux_checks import LinuxChecks
from scanner.model import Outcome, Status, exit_code, summarize
from scanner.runner import framework_summary, run_check, run_scan, select_checks, windows_name
from tests.linux_host import hardened_probe
from tests.windows_host import hardened_windows


def check(status, severity="medium"):
    return {"status": status, "severity": severity}


def test_score_counts_only_pass_and_fail():
    summary = summarize([check("PASS"), check("PASS"), check("FAIL"), check("ERROR"), check("MANUAL"),
                         check("NOT_APPLICABLE")])
    assert summary["assessed"] == 3
    assert summary["compliance_rate"] == 66.7
    assert (summary["errors"], summary["manual"], summary["not_applicable"]) == (1, 1, 1)


def test_score_is_none_when_nothing_was_assessed():
    assert summarize([check("ERROR"), check("ERROR")])["compliance_rate"] is None
    assert summarize([])["compliance_rate"] is None


@pytest.mark.parametrize("checks, code", [
    ([check("PASS"), check("MANUAL"), check("NOT_APPLICABLE")], 0),
    ([check("PASS"), check("FAIL")], 1),
    ([check("FAIL", "critical"), check("ERROR")], 2),
    ([check("PASS"), check("ERROR")], 3),
    ([check("ERROR"), check("ERROR")], 3),
    ([], 0),
])
def test_exit_code(checks, code):
    assert exit_code(checks) == code


def test_select_checks_filters_by_category_and_severity():
    assert {c.category for c in select_checks("linux", ["network"])} == {"network"}
    critical = select_checks("linux", None, "critical")
    assert critical and {c.severity for c in critical} == {"critical"}
    high = select_checks("linux", None, "high")
    assert {c.severity for c in high} == {"critical", "high"}
    assert len(select_checks("linux")) == len(load_checks("linux"))


def test_an_exception_inside_a_check_becomes_an_error_not_a_crash():
    checker = LinuxChecks(hardened_probe())
    checker.root_only_uid0 = lambda: 1 / 0
    definition = next(c for c in load_checks("linux") if c.function == "root_only_uid0")
    result = run_check(definition, checker, True)
    assert result["status"] == "ERROR"
    assert "ZeroDivisionError" in result["actual"]


def test_a_check_that_returns_nothing_is_an_error():
    checker = LinuxChecks(hardened_probe())
    checker.root_only_uid0 = lambda: None
    definition = next(c for c in load_checks("linux") if c.function == "root_only_uid0")
    assert run_check(definition, checker, True)["status"] == "ERROR"


def test_full_linux_scan_on_the_clean_host():
    result = run_scan("linux", probe=hardened_probe())
    assert result["platform"] == "linux" and result["privileged"] is True
    assert result["summary"]["total_checks"] == len(load_checks("linux"))
    assert result["summary"]["failed"] == 0 and result["summary"]["errors"] == 0
    assert result["summary"]["compliance_rate"] == 100.0
    assert result["system_info"]["distribution"] == "Ubuntu 22.04.5 LTS"
    first = result["checks"][0]
    assert set(first) == {"id", "title", "category", "severity", "status", "actual", "expected", "remediation",
                          "cis", "frameworks"}
    assert set(first["frameworks"]) == {"nist_800_53", "soc2", "iso_27001"}


def test_unprivileged_linux_scan_marks_root_checks_as_error():
    result = run_scan("linux", probe=hardened_probe(root=False))
    errors = [c["id"] for c in result["checks"] if c["status"] == "ERROR"]
    needs_root = [c.id for c in load_checks("linux") if c.requires_root]
    assert errors == needs_root
    assert result["privileged"] is False
    assert exit_code(result["checks"]) == 3


def test_full_windows_scan_on_the_clean_host():
    result = run_scan("windows", probe=hardened_windows())
    assert result["summary"]["total_checks"] == len(load_checks("windows"))
    assert result["summary"]["failed"] == 0 and result["summary"]["errors"] == 0
    assert result["summary"]["manual"] == 1 and result["summary"]["not_applicable"] == 1


def test_framework_summary_counts_and_orders_controls():
    result = run_scan("linux", probe=hardened_probe(files={"/proc/sys/net/ipv4/ip_forward": "1\n"}))
    nist = result["framework_summary"]["nist_800_53"]
    ids = [c["control_id"] for c in nist["controls"]]
    assert ids.index("AC-2") < ids.index("AC-17") < ids.index("AU-2")   # numeric, not text, order
    sc7 = next(c for c in nist["controls"] if c["control_id"] == "SC-7")
    assert sc7["checks_failed"] == 1
    assert sc7["checks_passed"] + sc7["checks_failed"] + sc7["checks_no_verdict"] == sc7["checks_total"]
    assert 0 < sc7["compliance_percentage"] < 100


def test_framework_summary_has_no_percentage_without_a_verdict():
    checks = [{"status": "ERROR", "frameworks": {
        "nist_800_53": [{"control_id": "CM-7", "control_name": "Least Functionality"}], "soc2": [], "iso_27001": []}}]
    row = framework_summary(checks)["nist_800_53"]["controls"][0]
    assert row["compliance_percentage"] is None and row["checks_no_verdict"] == 1


def test_outcome_status_values_are_the_documented_ones():
    assert {s.value for s in Status} == {"PASS", "FAIL", "ERROR", "NOT_APPLICABLE", "MANUAL"}
    assert Outcome(Status.PASS, "x").status.value == "PASS"


@pytest.mark.parametrize("release, version, expected", [
    ("2022Server", "10.0.20348", "Windows Server 2022 (10.0.20348)"),
    ("2025Server", "10.0.26100", "Windows Server 2025 (10.0.26100)"),
    ("11", "10.0.26100", "Windows 11 (10.0.26100)"),
])
def test_windows_product_name_is_readable(release, version, expected):
    assert windows_name(release, version) == expected
