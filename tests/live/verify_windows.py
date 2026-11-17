#!/usr/bin/env python3
"""Run the scanner on a live Windows host and cross-check what it reports.

The unit tests prove the decisions made in Python from recorded PowerShell
output. This script proves the other half on a real machine: that every query
returns data the scanner can read and that the values agree with what separate
Windows tools (net accounts, reg, sc, netsh) say about the same settings.

It is meant for the Windows job in CI and assumes an English language image and
a session with administrator rights. It changes nothing on the host.

    python tests/live/verify_windows.py
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

VALID = {"PASS", "FAIL", "ERROR", "NOT_APPLICABLE", "MANUAL"}

# ERROR is acceptable only when the host state really cannot be read.
ACCEPTABLE_ERRORS = (
    "Could not assess: WinRM is stopped and no policy value is set",
)


def tool(*argv):
    done = subprocess.run(list(argv), capture_output=True, text=True, errors="replace", timeout=120)
    return done.returncode, done.stdout


def net_accounts():
    """Values from `net accounts`, a tool the scanner does not use."""
    _, text = tool("net", "accounts")
    wanted = {
        "Minimum password age (days)": "MinimumPasswordAge",
        "Maximum password age (days)": "MaximumPasswordAge",
        "Minimum password length": "MinimumPasswordLength",
        "Length of password history maintained": "PasswordHistorySize",
        "Lockout threshold": "LockoutBadCount",
    }
    words = {"never": 0, "none": 0, "unlimited": -1}
    found = {}
    for line in text.splitlines():
        label, _, value = line.partition(":")
        key = wanted.get(label.strip())
        if key:
            value = value.strip()
            found[key] = words.get(value.lower(), int(value) if value.lstrip("-").isdigit() else value)
    return found


def registry_dword(key, name):
    code, text = tool("reg", "query", key, "/v", name)
    if code != 0:
        return None
    match = re.search(rf"{re.escape(name)}\s+REG_DWORD\s+0x([0-9a-fA-F]+)", text)
    return int(match.group(1), 16) if match else None


def service_start_type(name):
    code, text = tool("sc.exe", "qc", name)
    if code != 0:
        return None
    match = re.search(r"START_TYPE\s*:\s*\d+\s+(\S+)", text)
    return match.group(1).upper() if match else None


def firewall_profiles_off():
    _, text = tool("netsh", "advfirewall", "show", "allprofiles", "state")
    off, profile = [], None
    for line in text.splitlines():
        heading = re.match(r"^(Domain|Private|Public) Profile Settings", line.strip())
        if heading:
            profile = heading.group(1)
        state = re.match(r"^State\s+(ON|OFF)", line.strip())
        if state and profile and state.group(1) == "OFF":
            off.append(profile)
    return sorted(off)


def reported_number(check, label):
    match = re.search(rf"{label} = (-?\d+)", check["actual"])
    return int(match.group(1)) if match else None


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    target = Path(tempfile.mkdtemp()) / "scan.json"
    done = subprocess.run([sys.executable, "-m", "scanner", "--quiet", "--output", "json", "-f", str(target)],
                          capture_output=True, text=True, errors="replace", timeout=1800)
    print(f"scanner exit code: {done.returncode}")
    problems = []
    if done.returncode not in (0, 1, 2, 3):
        print(done.stdout, done.stderr)
        problems.append(f"unexpected exit code {done.returncode}")
        return report(problems)
    result = json.loads(target.read_text(encoding="utf-8"))
    info, summary = result["system_info"], result["summary"]
    print(f"{info['distribution']}  privileged: {result['privileged']}")
    print({key: value for key, value in summary.items() if not isinstance(value, dict)})
    print()
    checks = {check["id"]: check for check in result["checks"]}
    for check in result["checks"]:
        print(f"{check['id']:13} {check['status']:15} {check['actual']}")
    print()

    if result["platform"] != "windows":
        problems.append(f"platform is {result['platform']}")
    if not result["privileged"]:
        problems.append("the session has no administrator rights, so this run proves nothing about the privileged checks")
    for check in result["checks"]:
        if check["status"] not in VALID:
            problems.append(f"{check['id']}: unknown status {check['status']}")
        if check["status"] == "ERROR" and not check["actual"].startswith(ACCEPTABLE_ERRORS):
            problems.append(f"{check['id']}: {check['actual']}")

    print("Cross-checks against separate tools:")

    def compare(what, scanner_value, other_value, other_tool):
        agree = scanner_value == other_value
        print(f"  {'ok ' if agree else 'BAD'} {what}: scanner {scanner_value!r}, {other_tool} {other_value!r}")
        if not agree:
            problems.append(f"{what}: scanner says {scanner_value!r} but {other_tool} says {other_value!r}")

    accounts = net_accounts()
    for check_id, key in (("WIN-AUTH-001", "PasswordHistorySize"), ("WIN-AUTH-002", "MaximumPasswordAge"),
                          ("WIN-AUTH-003", "MinimumPasswordAge"), ("WIN-AUTH-004", "MinimumPasswordLength"),
                          ("WIN-AUTH-006", "LockoutBadCount")):
        compare(f"{check_id} {key}", reported_number(checks[check_id], key), accounts.get(key), "net accounts")

    system_policies = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    for check_id, key, name in (("WIN-ACC-001", system_policies, "EnableLUA"),
                                ("WIN-ACC-002", system_policies, "ConsentPromptBehaviorAdmin"),
                                ("WIN-ACC-004", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM")):
        compare(f"{check_id} {name}", reported_number(checks[check_id], name), registry_dword(key, name), "reg query")

    for check_id, name in (("WIN-SVC-004", "RemoteRegistry"), ("WIN-SVC-005", "SNMP"), ("WIN-SVC-001", "TlntSvr")):
        start_type = service_start_type(name)
        compare(f"{check_id} {name} absent or disabled", checks[check_id]["status"] == "PASS",
                start_type in (None, "DISABLED"), "sc qc")

    firewall = checks["WIN-NET-001"]
    scanner_off = sorted(re.findall(r"Domain|Private|Public", firewall["actual"])) if firewall["status"] == "FAIL" else []
    compare("WIN-NET-001 firewall profiles that are off", scanner_off, firewall_profiles_off(), "netsh")

    return report(problems)


def report(problems) -> int:
    if problems:
        print("\nPROBLEMS:\n  " + "\n  ".join(problems))
        return 1
    print("\nevery query returned readable data and the cross-checks agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
