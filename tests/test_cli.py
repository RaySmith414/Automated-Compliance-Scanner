"""The command line: options, files, quiet mode and exit codes."""

import json

import pytest

from scanner import __version__
from scanner import main as cli
from scanner.catalog import load_checks
from scanner.runner import run_scan as real_run_scan
from tests.linux_host import hardened_probe


@pytest.fixture
def scan(monkeypatch):
    """Point the CLI at a fake Linux host. Returns a setter for the probe."""
    state = {"probe": hardened_probe()}

    def fake_run_scan(platform, categories, min_severity, find_timeout=120):
        state["find_timeout"] = find_timeout
        return real_run_scan("linux", categories, min_severity, probe=state["probe"], find_timeout=find_timeout)

    monkeypatch.setattr(cli, "detect_platform", lambda: "linux")
    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    return state


def test_clean_host_exits_zero_and_says_so(scan, capsys):
    assert cli.main([]) == 0
    captured = capsys.readouterr()
    assert "LNX-FS-001" in captured.out
    assessed = len(load_checks("linux")) - 1   # one check is not applicable on the clean host
    assert f"All {assessed} assessed checks passed." in captured.err


def test_failed_check_exits_one(scan, capsys):
    scan["probe"] = hardened_probe(files={"/etc/login.defs": "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n"})
    assert cli.main([]) == 1
    captured = capsys.readouterr()
    assert "1 check(s) failed." in captured.err
    assert "Failed checks (1)" in captured.out and "PASS_MAX_DAYS = 99999" in captured.out


def test_critical_failure_exits_two(scan, capsys):
    scan["probe"] = hardened_probe(files={"/etc/passwd": "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\n"})
    assert cli.main([]) == 2
    assert "1 critical check(s) failed." in capsys.readouterr().err


def test_errors_without_failures_exit_three_and_never_claim_success(scan, capsys):
    scan["probe"] = hardened_probe(files={"/proc/filesystems": None})
    assert cli.main([]) == 3
    captured = capsys.readouterr()
    assert "could not be assessed" in captured.err and "not a clean result" in captured.err
    assert "passed." not in captured.err
    assert "Not assessed (3)" in captured.out


def test_unprivileged_run_warns_and_exits_three(scan, capsys):
    scan["probe"] = hardened_probe(root=False)
    assert cli.main([]) == 3
    assert "Running without root" in capsys.readouterr().err


def test_quiet_mode_prints_nothing_but_the_requested_output(scan, capsys, tmp_path):
    target = tmp_path / "out.json"
    assert cli.main(["--quiet", "--output", "json", "-f", str(target)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["total_checks"] == len(load_checks("linux"))


def test_quiet_console_output_keeps_the_report_only(scan, capsys):
    assert cli.main(["--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and "LNX-FS-001" in captured.out


@pytest.mark.parametrize("fmt, name", [("html", "r.html"), ("json", "r.json"), ("csv", "r.csv"), ("poam", "p.csv")])
def test_each_file_format_is_written(scan, capsys, tmp_path, fmt, name):
    target = tmp_path / name
    assert cli.main(["--output", fmt, "-f", str(target)]) == 0
    assert target.exists() and target.stat().st_size > 0
    assert str(target) in capsys.readouterr().err.replace("\n", "")


def test_default_file_name_is_used_when_none_is_given(scan, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--output", "poam"]) == 0
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith("poam_") and p.suffix == ".csv"]


def test_category_and_severity_filters_reach_the_scan(scan, capsys):
    assert cli.main(["--categories", "network", "--severity", "high", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert "LNX-NET-001" in out and "LNX-NET-007" in out
    assert "LNX-NET-002" not in out and "LNX-FS-001" not in out


def test_framework_tables_are_printed_on_request(scan, capsys):
    assert cli.main(["--frameworks", "soc2", "--nist-mapping", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert "NIST SP 800-53 Rev. 5: control coverage" in out and "SOC 2 Trust Services Criteria" in out
    assert "ISO/IEC 27001" not in out


def test_find_timeout_option_is_passed_through(scan, capsys):
    cli.main(["--find-timeout", "5", "--quiet"])
    assert scan["find_timeout"] == 5


def test_list_checks_prints_the_catalog_without_scanning(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: pytest.fail("must not scan"))
    assert cli.main(["--list-checks", "--platform", "windows"]) == 0
    out = capsys.readouterr().out
    assert "WIN-AUTH-001" in out and "LNX-" not in out


def test_usage_errors_do_not_look_like_scan_results(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["--output", "pdf"])
    assert raised.value.code == 64


def test_unsupported_platform(monkeypatch, capsys):
    monkeypatch.setattr(cli, "detect_platform", lambda: "unsupported")
    assert cli.main([]) == 64
    assert "Unsupported operating system" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["--version"])
    assert raised.value.code == 0
    assert __version__ in capsys.readouterr().out
