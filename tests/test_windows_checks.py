"""Windows check logic, tested against recorded PowerShell output.

These tests prove the decisions made in Python. They cannot prove that the
PowerShell queries return what they should on a live host. The Windows job in
CI runs the scanner on a real Windows Server image for that.
"""

import json

import pytest

from scanner import windows_checks as wc
from scanner.catalog import load_checks
from scanner.runner import run_check
from scanner.windows_checks import WindowsChecks, has_write_rights
from tests.conftest import FakeProbe, fail, ok, timed_out
from tests.windows_host import (
    DEFAULT_ACL,
    DNS_CLIENT,
    LANMAN,
    LSA,
    POLICY,
    RDP_LISTENER,
    SYSTEM_POLICIES,
    TS_POLICY,
    WINRM_POLICY,
    audit_row,
    hardened_windows,
    reg,
    reg_missing,
    registry_key,
    service,
    svc,
)

CHECKS = {check.function: check for check in load_checks("windows")}


def verdict(function, probe):
    checker = WindowsChecks(probe)
    return run_check(CHECKS[function], checker, checker.is_privileged())


def policy(**changes):
    values = dict(POLICY)
    for key, value in changes.items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = str(value)
    return {"secedit.exe": ok(json.dumps(values))}


# ------------------------------------------------------------- the clean host

EXPECTED_ON_CLEAN_HOST = {check.function: "PASS" for check in load_checks("windows")}
EXPECTED_ON_CLEAN_HOST["administrators_group_review"] = "MANUAL"
EXPECTED_ON_CLEAN_HOST["print_spooler_on_domain_controller"] = "NOT_APPLICABLE"


@pytest.mark.parametrize("function", sorted(CHECKS))
def test_clean_host(function):
    result = verdict(function, hardened_windows())
    assert result["status"] == EXPECTED_ON_CLEAN_HOST[function], result["actual"]


# ------------------------------------------------------------------ one change

CASES = [
    # --- volumes and ACLs
    ("fixed_volumes_use_ntfs", {"Get-Volume": ok(json.dumps([{"drive": "C", "fs": "NTFS"}, {"drive": "E", "fs": "FAT32"}]))},
     "FAIL", "E: (FAT32)"),
    ("fixed_volumes_use_ntfs", {"Get-Volume": ok("not json")}, "ERROR", "not JSON"),
    ("fixed_volumes_use_ntfs", {"Get-Volume": ok("[]")}, "ERROR", "no fixed volume"),
    ("fixed_volumes_use_ntfs", {"Get-Volume": fail(1, stderr="Get-Volume : Access denied\n")}, "ERROR", "Access denied"),
    ("system_config_acl", {"System32\\config": ok(json.dumps(DEFAULT_ACL + [
        {"sid": "S-1-1-0", "type": "Allow", "rights": 1245631}]))}, "FAIL", "Everyone"),       # Modify
    ("system_config_acl", {"System32\\config": ok(json.dumps(DEFAULT_ACL + [
        {"sid": "S-1-5-11", "type": "Allow", "rights": 268435456}]))}, "FAIL", "Authenticated Users"),  # GENERIC_ALL
    ("system_config_acl", {"System32\\config": ok(json.dumps(DEFAULT_ACL + [
        {"sid": "S-1-1-0", "type": "Deny", "rights": 2032127}]))}, "PASS", "none gives write access"),
    ("system_config_acl", {"System32\\config": ok("[]")}, "ERROR", "came back empty"),
    # --- password and lockout policy
    ("password_history", policy(PasswordHistorySize=5), "FAIL", "= 5"),
    ("password_history", policy(PasswordHistorySize=None), "ERROR", "no PasswordHistorySize"),
    ("password_history", {"secedit.exe": fail(1, stderr="secedit : Access is denied.\n")}, "ERROR", "Access is denied"),
    ("password_max_age", policy(MaximumPasswordAge=-1), "FAIL", "never expire"),
    ("password_max_age", policy(MaximumPasswordAge=400), "FAIL", "= 400"),
    ("password_min_age", policy(MinimumPasswordAge=0), "FAIL", "= 0"),
    ("password_min_length", policy(MinimumPasswordLength=8), "FAIL", "= 8"),
    ("password_complexity", policy(PasswordComplexity=0), "FAIL", "= 0"),
    ("password_complexity", policy(PasswordComplexity="yes"), "ERROR", "not a number"),
    ("lockout_threshold", policy(LockoutBadCount=0), "FAIL", "never lock"),
    ("lockout_threshold", policy(LockoutBadCount=10), "FAIL", "= 10"),
    ("lockout_duration", policy(LockoutBadCount=0, LockoutDuration=None), "FAIL", "no lockout threshold"),
    ("lockout_duration", policy(LockoutDuration=5), "FAIL", "5 minutes"),
    ("lockout_duration", policy(LockoutDuration=-1), "PASS", "until an administrator"),
    ("guest_account_disabled", policy(EnableGuestAccount=1), "FAIL", "= 1"),
    ("administrator_renamed", policy(NewAdministratorName='"Administrator"'), "FAIL", "still named"),
    # --- remote desktop
    ("rdp_nla_required", {registry_key(RDP_LISTENER, "UserAuthentication"): reg(0)}, "FAIL", "= 0 (RDP-Tcp listener)"),
    ("rdp_nla_required", {registry_key(TS_POLICY, "UserAuthentication"): reg(0)}, "FAIL", "= 0 (policy)"),
    ("rdp_nla_required", {registry_key(RDP_LISTENER, "UserAuthentication"): reg_missing()}, "FAIL", "is not set"),
    ("rdp_nla_required", {registry_key(TS_POLICY, "UserAuthentication"): timed_out()}, "ERROR", "timed out"),
    # --- network
    ("firewall_profiles_enabled", {"Get-NetFirewallProfile": ok(json.dumps([
        {"name": "Domain", "enabled": "True"}, {"name": "Public", "enabled": "False"}]))}, "FAIL", "Public"),
    ("firewall_profiles_enabled", {"Get-NetFirewallProfile": ok(json.dumps([
        {"name": "Domain", "enabled": "NotConfigured"}]))}, "FAIL", "Domain"),
    ("firewall_profiles_enabled", {"Get-NetFirewallProfile": ok("[]")}, "ERROR", "no profiles"),
    ("smbv1_disabled", {"Get-SmbServerConfiguration": ok("true")}, "FAIL", "= True"),
    ("smbv1_disabled", {"Get-SmbServerConfiguration": fail(1, stderr="Access is denied.\n")}, "ERROR", "Access is denied"),
    ("smbv1_disabled", {"Get-SmbServerConfiguration": ok("")}, "ERROR", "no data"),
    ("netbios_disabled", {"Win32_NetworkAdapterConfiguration": ok(json.dumps([
        {"adapter": "Ethernet", "option": 2}, {"adapter": "Wi-Fi", "option": 0}]))}, "FAIL", "Wi-Fi"),
    ("netbios_disabled", {"Win32_NetworkAdapterConfiguration": ok("[]")}, "NOT_APPLICABLE", "no IP-enabled"),
    ("llmnr_disabled", {registry_key(DNS_CLIENT, "EnableMulticast"): reg_missing()}, "FAIL", "on by default"),
    ("llmnr_disabled", {registry_key(DNS_CLIENT, "EnableMulticast"): reg(1)}, "FAIL", "= 1"),
    ("winrm_requires_encryption", {service("WinRM"): svc(True, "Stopped", "Disabled")}, "NOT_APPLICABLE", "disabled"),
    ("winrm_requires_encryption", {registry_key(WINRM_POLICY, "AllowUnencryptedTraffic"): reg(1)}, "FAIL", "(policy)"),
    ("winrm_requires_encryption", {registry_key(WINRM_POLICY, "AllowUnencryptedTraffic"): reg_missing(),
                                   "WSMan:": ok('"true"')}, "FAIL", "AllowUnencrypted = true"),
    ("winrm_requires_encryption", {registry_key(WINRM_POLICY, "AllowUnencryptedTraffic"): reg_missing()},
     "PASS", "AllowUnencrypted = false"),
    ("winrm_requires_encryption", {registry_key(WINRM_POLICY, "AllowUnencryptedTraffic"): reg_missing(),
                                   service("WinRM"): svc(True, "Stopped", "Manual")}, "ERROR", "WinRM is stopped"),
    # --- audit policy and logs
    ("audit_logon", {wc.AUDIT_LOGON: audit_row("Logon", wc.AUDIT_LOGON, "Success")}, "FAIL", "Audit Logon: Success"),
    ("audit_logon", {wc.AUDIT_LOGON: audit_row("Logon", wc.AUDIT_LOGON, "No Auditing")}, "FAIL", "No Auditing"),
    ("audit_logon", {wc.AUDIT_LOGON: audit_row("Anmelden", wc.AUDIT_LOGON, "Erfolg und Fehler")}, "ERROR", "does not recognize"),
    ("audit_user_account_management", {wc.AUDIT_USER_ACCOUNT_MANAGEMENT: fail(
        1, stderr="Error 0x00000522 occurred:\nA required privilege is not held by the client.\n")}, "ERROR", "privilege"),
    ("audit_sensitive_privilege_use", {wc.AUDIT_SENSITIVE_PRIVILEGE_USE: ok("")}, "ERROR", "no row"),
    ("security_log_size", {"Get-WinEvent -ListLog Security": ok(str(20 * 1024 * 1024))}, "FAIL", "20480 KB"),
    ("event_log_service_running", {service("EventLog"): svc(True, "Stopped", "Automatic")}, "FAIL", "Stopped"),
    # --- UAC and access
    ("uac_enabled", {registry_key(SYSTEM_POLICIES, "EnableLUA"): reg(0)}, "FAIL", "= 0"),
    ("uac_enabled", {registry_key(SYSTEM_POLICIES, "EnableLUA"): reg_missing()}, "FAIL", "is not set"),
    ("uac_admin_prompt", {registry_key(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin"): reg(5)}, "FAIL", "= 5"),
    ("uac_admin_prompt", {registry_key(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin"): reg(0)}, "FAIL", "= 0"),
    ("uac_admin_prompt", {registry_key(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin"): reg(1)}, "PASS", "= 1"),
    ("administrators_group_review", {"Get-LocalGroupMember": fail(
        1, stderr="Get-LocalGroupMember : Failed to compare two elements in the array.\n")}, "ERROR", "Failed to compare"),
    ("anonymous_sam_enumeration_restricted", {registry_key(LSA, "RestrictAnonymousSAM"): reg(0)}, "FAIL", "= 0"),
    ("null_session_shares_restricted", {registry_key(LANMAN, "NullSessionShares"): reg(["public", ""])},
     "FAIL", "public"),
    ("null_session_shares_restricted", {registry_key(LANMAN, "NullSessionShares"): reg_missing()}, "PASS", "is not set"),
    ("null_session_shares_restricted", {registry_key(LANMAN, "NullSessionShares"): fail(1, stderr="Access denied\n")},
     "ERROR", "Access denied"),
    # --- services
    ("telnet_service_disabled", {service("TlntSvr"): svc(True, "Running", "Automatic")}, "FAIL", "Automatic"),
    ("telnet_service_disabled", {service("TlntSvr"): svc(True, "Stopped", "Disabled")}, "PASS", "Disabled"),
    ("telnet_service_disabled", {service("TlntSvr"): ok("")}, "ERROR", "no data"),
    ("ftp_service_disabled", {service("FTPSVC"): svc(True, "Stopped", "Manual")}, "FAIL", "Manual"),
    ("print_spooler_on_domain_controller", {"Win32_ComputerSystem": ok("5")}, "FAIL", "Automatic"),
    ("print_spooler_on_domain_controller", {"Win32_ComputerSystem": ok("4"),
                                            service("Spooler"): svc(True, "Stopped", "Disabled")}, "PASS", "Disabled"),
    ("remote_registry_disabled", {service("RemoteRegistry"): svc(True, "Stopped", "Manual")}, "FAIL", "Manual"),
    ("snmp_service_disabled", {service("SNMP"): svc(True, "Running", "Automatic")}, "FAIL", "Automatic"),
]


@pytest.mark.parametrize("function, changes, status, fragment", CASES,
                         ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_one_change(function, changes, status, fragment):
    result = verdict(function, hardened_windows(changes))
    assert result["status"] == status, result["actual"]
    assert fragment in result["actual"], result["actual"]


def test_every_check_has_a_failing_or_blocking_case():
    covered = {case[0] for case in CASES if case[2] != "PASS"}
    assert covered == set(CHECKS), sorted(set(CHECKS) - covered)


# ------------------------------------------------- no answer is never a PASS

def test_without_powershell_every_check_is_an_error():
    probe = FakeProbe(tools=set())
    statuses = {function: verdict(function, probe)["status"] for function in CHECKS}
    assert set(statuses.values()) == {"ERROR"}, statuses


def test_queries_that_fail_never_produce_a_pass():
    for broken in (fail(1, stderr="Access is denied."), timed_out(), ok(""), ok("garbage")):
        answers = {needle: broken for needle in hardened_windows().scripts}
        answers["IsInRole"] = ok("true")
        probe = hardened_windows(answers)
        statuses = {function: verdict(function, probe)["status"] for function in CHECKS}
        assert "PASS" not in statuses.values(), (broken, {f: s for f, s in statuses.items() if s == "PASS"})


def test_checks_that_need_administrator_rights_report_error_without_them():
    probe = hardened_windows({"IsInRole": ok("false")})
    result = verdict("password_history", probe)
    assert result["status"] == "ERROR"
    assert "administrator rights" in result["actual"]
    assert verdict("uac_enabled", probe)["status"] == "PASS"


def test_security_policy_is_exported_once_per_scan():
    probe = hardened_windows()
    checker = WindowsChecks(probe)
    for function in ("password_history", "password_min_length", "lockout_threshold", "guest_account_disabled"):
        run_check(CHECKS[function], checker, True)
    assert sum(1 for call in probe.calls if "secedit.exe" in call[-1]) == 1


@pytest.mark.parametrize("rights, expected", [
    (1179817, False),     # ReadAndExecute
    (1179785, False),     # Read
    (2032127, True),      # FullControl
    (1245631, True),      # Modify
    (278, True),          # Write
    (268435456, True),    # GENERIC_ALL
    (-1610612736, False),  # GENERIC_READ | GENERIC_EXECUTE as a signed 32-bit value
    (1073741824, True),   # GENERIC_WRITE
])
def test_has_write_rights(rights, expected):
    assert has_write_rights(rights) is expected


def test_windows_and_linux_ids_do_not_collide():
    linux = {check.id for check in load_checks("linux")}
    windows = {check.id for check in load_checks("windows")}
    assert not linux & windows


# ------------------------------------------- quirks of Windows PowerShell 5.1

def test_array_wrapped_by_powershell_5_1_is_unwrapped():
    wrapped = json.dumps({"value": [{"drive": "C", "fs": "NTFS"}, {"drive": "D", "fs": "FAT32"}], "Count": 2})
    result = verdict("fixed_volumes_use_ntfs", hardened_windows({"Get-Volume": ok(wrapped)}))
    assert result["status"] == "FAIL"
    assert "D: (FAT32)" in result["actual"]


def test_a_registry_value_named_like_the_wrapper_is_left_alone():
    assert wc._unwrap({"found": True, "value": [1]}) == {"found": True, "value": [1]}
    assert wc._unwrap({"value": 3, "Count": 1}) == {"value": 3, "Count": 1}


def test_failed_query_reports_the_message_not_the_position_lines():
    stderr = ("Get-SmbServerConfiguration : Access is denied.\r\n"
              "At line:3 char:8\r\n"
              "+ [bool](Get-SmbServerConfiguration).EnableSMB1Protocol | ConvertTo-Json\r\n"
              "+        ~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n"
              "    + CategoryInfo          : PermissionDenied: (MSFT_SmbServerConfiguration:ROOT/Microsoft/...)\r\n"
              "    + FullyQualifiedErrorId : Windows System Error 5,Get-SmbServerConfiguration\r\n")
    result = verdict("smbv1_disabled", hardened_windows({"Get-SmbServerConfiguration": fail(1, stderr=stderr)}))
    assert result["status"] == "ERROR"
    assert result["actual"].endswith("Get-SmbServerConfiguration : Access is denied.")


# --------------------------------------------------- locating PowerShell safely

def _fake_system_root(tmp_path, *system_dirs):
    for system_dir in system_dirs:
        folder = tmp_path / system_dir / "WindowsPowerShell" / "v1.0"
        folder.mkdir(parents=True)
        (folder / "powershell.exe").write_text("", encoding="utf-8")
    return str(tmp_path)


def test_powershell_is_an_absolute_path_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(wc.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", _fake_system_root(tmp_path, "System32"))
    found = wc.powershell_executable()
    assert found.startswith(str(tmp_path)) and "System32" in found


def test_powershell_prefers_the_64_bit_view(tmp_path, monkeypatch):
    monkeypatch.setattr(wc.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", _fake_system_root(tmp_path, "System32", "Sysnative"))
    assert "Sysnative" in wc.powershell_executable()


def test_powershell_falls_back_to_the_bare_name_elsewhere(tmp_path, monkeypatch):
    monkeypatch.setenv("SystemRoot", _fake_system_root(tmp_path, "System32"))
    monkeypatch.setattr(wc.os, "name", "posix")
    assert wc.powershell_executable() == "powershell"
    monkeypatch.setattr(wc.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "missing"))
    assert wc.powershell_executable() == "powershell"
