"""Run the real scanner against the machine the tests run on.

These tests use real commands. They assert properties that must hold on any
Linux host, so they are safe in CI containers and on developer machines.
"""

import platform
import re
import subprocess
import sys

import pytest

from scanner.catalog import load_checks
from scanner.model import Status
from scanner.probe import LocalProbe
from scanner.runner import run_scan

pytestmark = [pytest.mark.host, pytest.mark.skipif(platform.system() != "Linux", reason="Linux host tests")]


@pytest.fixture(scope="module")
def result():
    return run_scan("linux", find_timeout=300)


def test_every_check_returns_a_documented_status(result):
    assert len(result["checks"]) == len(load_checks("linux"))
    assert {c["status"] for c in result["checks"]} <= {s.value for s in Status}
    assert all(c["actual"] for c in result["checks"])


def test_no_check_crashed(result):
    # run_check reports an unexpected exception as "Could not assess: <ExceptionName>: ...".
    crashed = [c for c in result["checks"]
               if c["status"] == "ERROR" and re.match(r"Could not assess: [A-Z]\w*(Error|Exception)\b", c["actual"])]
    assert not crashed, crashed


def test_missing_tools_are_errors_or_not_applicable_never_pass(result):
    probe = LocalProbe()
    by_function = {check.id: check.function for check in load_checks("linux")}
    statuses = {by_function[c["id"]]: c["status"] for c in result["checks"]}
    available = (probe.read_text("/proc/filesystems") or "").split()
    for name in ("cramfs", "squashfs", "udf"):
        if name in available:
            assert statuses[f"{name}_disabled"] == "FAIL"
        elif probe.read_text("/proc/modules") is None:
            assert statuses[f"{name}_disabled"] == "PASS"   # nothing can be loaded into this kernel
        elif probe.which("modprobe") is None:
            assert statuses[f"{name}_disabled"] == "ERROR"
    if probe.which("sshd") is None:
        assert {statuses[f] for f in ("ssh_root_login_disabled", "ssh_empty_passwords_disabled",
                                      "ssh_password_authentication_review", "ssh_max_auth_tries")} == {"NOT_APPLICABLE"}
    if not probe.is_root():
        needs_root = [c.function for c in load_checks("linux") if c.requires_root]
        assert {statuses[f] for f in needs_root} <= {"ERROR", "NOT_APPLICABLE"}


def test_permission_checks_agree_with_stat(result):
    import os
    import stat as stat_module

    by_id = {c["id"]: c for c in result["checks"]}
    for check_id, path, limit in (("LNX-ACC-001", "/etc/passwd", 0o644), ("LNX-ACC-003", "/etc/group", 0o644)):
        mode = stat_module.S_IMODE(os.stat(path).st_mode)
        info = os.stat(path)
        expected = "PASS" if (mode & ~limit) == 0 and info.st_uid == 0 and info.st_gid == 0 else "FAIL"
        assert by_id[check_id]["status"] == expected, by_id[check_id]["actual"]


def test_summary_adds_up(result):
    summary = result["summary"]
    assert summary["total_checks"] == (summary["passed"] + summary["failed"] + summary["errors"]
                                       + summary["manual"] + summary["not_applicable"])
    if summary["assessed"]:
        assert summary["compliance_rate"] == round(summary["passed"] / summary["assessed"] * 100, 1)


def test_module_entry_point_runs_and_writes_json(tmp_path):
    target = tmp_path / "scan.json"
    done = subprocess.run(
        [sys.executable, "-m", "scanner", "--quiet", "--output", "json", "-f", str(target), "--find-timeout", "300"],
        capture_output=True, text=True, timeout=900)
    assert done.returncode in (0, 1, 2, 3), done.stderr
    assert done.stdout == "" and done.stderr == ""
    assert target.exists()
