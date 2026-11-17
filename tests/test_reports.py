"""Report writers: correct numbers, safe output, files where the user asked for them."""

import csv
import json

import pytest

from scanner.catalog import load_checks
from scanner.reports import CSVReportGenerator, HTMLReportGenerator, JSONReportGenerator, POAMReportGenerator
from scanner.reports.csv_report import FIELDS, spreadsheet_safe, summary_path_for
from scanner.runner import run_scan
from tests.linux_host import hardened_probe

HOSTILE = "<script>alert('x')</script>"


@pytest.fixture
def clean_result():
    return run_scan("linux", probe=hardened_probe())


@pytest.fixture
def mixed_result():
    """One critical fail, one medium fail, one error, one manual review."""
    probe = hardened_probe(
        files={"/proc/sys/net/ipv4/ip_forward": "1\n", "/proc/filesystems": None},
        stats={"/etc/shadow": __import__("tests.conftest", fromlist=["stat"]).stat(0o604, "root", "shadow")},
    )
    from tests.conftest import ok
    probe.commands[("sshd", "-T")] = ok("permitrootlogin no\npermitemptypasswords no\npasswordauthentication yes\nmaxauthtries 4\n")
    return run_scan("linux", probe=probe)


def with_hostile_text(result):
    result["system_info"]["hostname"] = HOSTILE
    result["checks"][0]["actual"] = f"1 world writable files, for example: /tmp/{HOSTILE}"
    result["checks"][0]["status"] = "FAIL"
    return result


# ------------------------------------------------------------------------ HTML

def test_html_escapes_text_collected_from_the_host(clean_result):
    html = HTMLReportGenerator().render(with_hostile_text(clean_result))
    assert HOSTILE not in html
    assert "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;" in html
    assert "<script" not in html.lower()


def test_html_shows_every_status_and_the_real_counts(mixed_result):
    html = HTMLReportGenerator().render(mixed_result)
    summary = mixed_result["summary"]
    assert summary["failed"] == 2 and summary["errors"] == 3 and summary["manual"] == 1
    for badge in ("badge-pass", "badge-fail", "badge-error", "badge-manual", "badge-not_applicable"):
        assert badge in html
    assert f">{summary['compliance_rate']}%<" in html
    assert "could not be assessed" in html
    assert "LNX-ACC-002" in html and "mode 0604" in html


def test_html_says_partial_scan_when_not_root():
    html = HTMLReportGenerator().render(run_scan("linux", probe=hardened_probe(root=False)))
    assert "Partial scan." in html and "without root" in html


def test_html_handles_a_scan_with_no_verdicts(clean_result):
    for check in clean_result["checks"]:
        check["status"] = "ERROR"
    from scanner.model import summarize
    clean_result["summary"] = summarize(clean_result["checks"])
    html = HTMLReportGenerator().render(clean_result)
    assert ">n/a<" in html


def test_html_file_is_written(tmp_path, clean_result):
    target = tmp_path / "report.html"
    HTMLReportGenerator().generate(clean_result, str(target))
    assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


# ------------------------------------------------------------------------ JSON

def test_json_report_structure_and_recommendation_order(tmp_path, mixed_result):
    target = tmp_path / "report.json"
    JSONReportGenerator().generate(mixed_result, str(target))
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["report_metadata"]["report_format"] == "compliance-scanner-v2"
    assert data["summary"] == mixed_result["summary"]
    assert len(data["checks"]) == len(load_checks("linux"))
    priorities = [r["priority"] for r in data["recommendations"]]
    assert priorities == ["critical", "high"]
    assert data["recommendations"][0]["check_id"] == "LNX-ACC-002"
    assert data["recommendations"][0]["nist_800_53"] == ["AC-3", "AC-6", "IA-5"]


# ------------------------------------------------------------------------- CSV

@pytest.mark.parametrize("name, expected", [
    ("report.csv", "report_summary.csv"),
    ("results.out", "results_summary.csv"),
    ("results", "results_summary.csv"),
    ("my.csv.d/scan.csv", "my.csv.d/scan_summary.csv"),
    ("a.b.csv", "a.b_summary.csv"),
])
def test_summary_path_never_equals_the_main_path(name, expected):
    assert summary_path_for(name).as_posix() == expected
    assert summary_path_for(name).as_posix() != name


@pytest.mark.parametrize("name", ["report.csv", "results.out", "results"])
def test_csv_keeps_every_check_whatever_the_file_is_called(tmp_path, clean_result, name):
    target = tmp_path / name
    written = CSVReportGenerator().generate(clean_result, str(target))
    assert len(written) == 2 and written[0] != written[1]
    with open(target, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(load_checks("linux"))
    assert list(rows[0]) == FIELDS
    assert rows[0]["Check ID"] == "LNX-FS-001" and rows[0]["NIST 800-53"] == "CM-7, CM-6"
    summary = (tmp_path / summary_path_for(name).name).read_text(encoding="utf-8")
    assert "Compliance rate (pass / assessed),100.0%" in summary
    assert "NIST SP 800-53 Rev. 5" in summary


@pytest.mark.parametrize("value, expected", [
    ("=HYPERLINK(\"http://x\")", "'=HYPERLINK(\"http://x\")"),
    ("+1+1", "'+1+1"), ("-2", "'-2"), ("@SUM(A1)", "'@SUM(A1)"),
    ("mode 0644", "mode 0644"), ("", ""), (5, "5"),
])
def test_spreadsheet_safe_neutralizes_formulas(value, expected):
    assert spreadsheet_safe(value) == expected


def test_csv_neutralizes_formula_text_from_the_host(tmp_path, clean_result):
    clean_result["checks"][0]["actual"] = "=cmd|' /C calc'!A0"
    target = tmp_path / "r.csv"
    CSVReportGenerator().generate(clean_result, str(target))
    with open(target, newline="", encoding="utf-8") as handle:
        assert next(csv.DictReader(handle))["Found"].startswith("'=")


# ---------------------------------------------------------------------- POA&M

def test_poam_has_one_row_per_failed_check_with_due_dates(tmp_path, mixed_result):
    mixed_result["scan_time"] = "2026-03-01T10:00:00Z"
    target = tmp_path / "poam.csv"
    count = POAMReportGenerator().generate(mixed_result, str(target))
    with open(target, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert count == len(rows) == mixed_result["summary"]["failed"] == 2
    first, second = rows
    assert first["Weakness Source Identifier"] == "LNX-ACC-002" and first["Original Risk Rating"] == "High"
    assert first["POA&M ID"] == "2026-001" and second["POA&M ID"] == "2026-002"
    assert first["Original Detection Date"] == "2026-03-01"
    assert first["Scheduled Completion Date"] == "2026-03-31"      # critical: 30 days
    assert second["Weakness Source Identifier"] == "LNX-NET-001"
    assert second["Scheduled Completion Date"] == "2026-03-31"     # high: 30 days
    assert first["Status"] == "Open" and first["Point of Contact"] == ""
    assert first["Controls"] == "AC-3, AC-6, IA-5"


def test_poam_due_days_follow_severity(clean_result):
    clean_result["scan_time"] = "2026-01-01T00:00:00Z"
    for check, (severity, status) in zip(clean_result["checks"], [("medium", "FAIL"), ("low", "FAIL")]):
        check["severity"], check["status"] = severity, status
    rows = POAMReportGenerator().rows(clean_result)
    assert [r["Scheduled Completion Date"] for r in rows] == ["2026-04-01", "2026-06-30"]
    assert [r["Original Risk Rating"] for r in rows] == ["Moderate", "Low"]


def test_poam_is_empty_when_nothing_failed(tmp_path, clean_result):
    target = tmp_path / "poam.csv"
    assert POAMReportGenerator().generate(clean_result, str(target)) == 0
    assert target.read_text(encoding="utf-8").count("\n") == 1   # header only


# ------------------------------------------------------- CIS numbers, when set

def test_a_filled_in_cis_number_shows_in_every_report(mixed_result, tmp_path):
    failed = next(check for check in mixed_result["checks"] if check["status"] == "FAIL")
    failed["cis"]["id"] = "7.1.5"

    assert "CIS 7.1.5" in HTMLReportGenerator().render(mixed_result)

    target = tmp_path / "scan.csv"
    CSVReportGenerator().generate(mixed_result, str(target))
    with open(target, newline="", encoding="utf-8") as handle:
        rows = {row["Check ID"]: row for row in csv.DictReader(handle)}
    assert rows[failed["id"]]["CIS ID"] == "7.1.5"
    assert sum(1 for row in rows.values() if row["CIS ID"]) == 1

    poam = {row["Weakness Name"]: row for row in POAMReportGenerator().rows(mixed_result)}
    assert poam[failed["title"]]["Weakness Source Identifier"] == f"{failed['id']} (CIS 7.1.5)"

    saved = tmp_path / "scan.json"
    JSONReportGenerator().generate(mixed_result, str(saved))
    stored = json.loads(saved.read_text(encoding="utf-8"))
    assert next(c for c in stored["checks"] if c["id"] == failed["id"])["cis"]["id"] == "7.1.5"


def test_without_a_cis_number_reports_show_only_the_check_id(mixed_result):
    assert "cis-id\">" not in HTMLReportGenerator().render(mixed_result)
    for row in POAMReportGenerator().rows(mixed_result):
        assert "CIS" not in row["Weakness Source Identifier"]
