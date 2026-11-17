"""Run the catalog against a host and assemble the result document."""

import platform as platform_module
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from scanner import __version__
from scanner.catalog import describe_controls, load_benchmark, load_checks, load_frameworks
from scanner.linux_checks import DEFAULT_FIND_TIMEOUT, LinuxChecks
from scanner.model import (
    FRAMEWORK_KEYS,
    SEVERITIES,
    CheckDef,
    NotApplicable,
    Outcome,
    Status,
    Unassessable,
    summarize,
)
from scanner.probe import LocalProbe
from scanner.windows_checks import WindowsChecks


def detect_platform() -> str:
    system = platform_module.system().lower()
    return system if system in ("linux", "windows") else "unsupported"


def build_checker(platform: str, probe=None, find_timeout: int = DEFAULT_FIND_TIMEOUT):
    probe = probe or LocalProbe()
    if platform == "linux":
        return LinuxChecks(probe, find_timeout=find_timeout)
    if platform == "windows":
        return WindowsChecks(probe)
    raise ValueError(f"unsupported platform: {platform}")


def select_checks(platform: str, categories: Optional[List[str]] = None, min_severity: str = "all") -> List[CheckDef]:
    """Catalog entries for one platform, filtered by category and severity."""
    checks = load_checks(platform)
    if categories:
        checks = [c for c in checks if c.category in categories]
    if min_severity != "all":
        cutoff = SEVERITIES.index(min_severity)
        checks = [c for c in checks if SEVERITIES.index(c.severity) <= cutoff]
    return checks


def run_check(check: CheckDef, checker, privileged: bool) -> Dict[str, str]:
    """Execute one check. Every way of not getting an answer becomes ERROR."""
    if check.requires_root and not privileged:
        rights = "root" if checker.platform == "linux" else "administrator rights"
        return {"status": Status.ERROR.value, "actual": f"Could not assess: this check needs {rights}"}
    function = getattr(checker, check.function, None)
    if function is None:
        return {"status": Status.ERROR.value,
                "actual": f"Could not assess: no test is implemented for {check.function}"}
    try:
        outcome = function()
    except NotApplicable as exc:
        return {"status": Status.NOT_APPLICABLE.value, "actual": str(exc)}
    except Unassessable as exc:
        return {"status": Status.ERROR.value, "actual": f"Could not assess: {exc}"}
    except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan
        return {"status": Status.ERROR.value, "actual": f"Could not assess: {type(exc).__name__}: {exc}"}
    if not isinstance(outcome, Outcome):
        return {"status": Status.ERROR.value, "actual": "Could not assess: the check returned no outcome"}
    return {"status": outcome.status.value, "actual": outcome.actual}


def _system_info(platform: str, probe) -> Dict[str, str]:
    info = {
        "hostname": platform_module.node() or "unknown",
        "platform": platform,
        "kernel": platform_module.release() or "unknown",
        "architecture": platform_module.machine() or "unknown",
        "distribution": "unknown",
    }
    if platform == "linux":
        try:
            text = probe.read_text("/etc/os-release") or ""
        except Unassessable:
            text = ""
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                info["distribution"] = line.split("=", 1)[1].strip().strip('"')
    else:
        info["distribution"] = windows_name(platform_module.release(), platform_module.version())
    return info


def windows_name(release: str, version: str) -> str:
    """Readable product name. Python reports server editions as "2022Server"."""
    if release.endswith("Server"):
        release = f"Server {release[:-len('Server')]}"
    return f"Windows {release} ({version})".replace("  ", " ")


def framework_summary(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Per control: how many mapped checks passed, failed or gave no verdict."""
    reference = load_frameworks()
    summary: Dict[str, Any] = {}
    for key in FRAMEWORK_KEYS:
        controls: Dict[str, Dict[str, Any]] = {}
        for check in checks:
            for control in check["frameworks"][key]:
                row = controls.setdefault(control["control_id"], {
                    **control, "checks_total": 0, "checks_passed": 0, "checks_failed": 0, "checks_no_verdict": 0,
                })
                row["checks_total"] += 1
                if check["status"] == "PASS":
                    row["checks_passed"] += 1
                elif check["status"] == "FAIL":
                    row["checks_failed"] += 1
                else:
                    row["checks_no_verdict"] += 1
        for row in controls.values():
            assessed = row["checks_passed"] + row["checks_failed"]
            row["compliance_percentage"] = round(row["checks_passed"] / assessed * 100, 1) if assessed else None
        ordered = sorted(controls.values(), key=lambda r: _control_sort_key(r["control_id"]))
        summary[key] = {"label": reference[key]["label"], "controls_assessed": len(ordered), "controls": ordered}
    return summary


def _control_sort_key(control_id: str):
    import re

    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", control_id)]


def run_scan(platform: Optional[str] = None, categories: Optional[List[str]] = None, min_severity: str = "all",
             probe=None, find_timeout: int = DEFAULT_FIND_TIMEOUT) -> Dict[str, Any]:
    platform = platform or detect_platform()
    probe = probe or LocalProbe()
    checker = build_checker(platform, probe, find_timeout)
    privileged = checker.is_privileged()
    results: List[Dict[str, Any]] = []
    for check in select_checks(platform, categories, min_severity):
        verdict = run_check(check, checker, privileged)
        results.append({
            "id": check.id,
            "title": check.title,
            "category": check.category,
            "severity": check.severity,
            "status": verdict["status"],
            "actual": verdict["actual"],
            "expected": check.expected,
            "remediation": check.remediation,
            "cis": {"is_cis_recommendation": check.is_cis, "id": check.cis_id},
            "frameworks": {key: describe_controls(key, getattr(check, key)) for key in FRAMEWORK_KEYS},
        })
    return {
        "scanner_version": __version__,
        "scan_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform,
        "privileged": privileged,
        "benchmark": load_benchmark(platform),
        "system_info": _system_info(platform, probe),
        "summary": summarize(results),
        "checks": results,
        "framework_summary": framework_summary(results),
    }
