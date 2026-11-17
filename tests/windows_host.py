"""A fake Windows Server where every Windows check has a clean answer.

PowerShell output is JSON, so the fake answers each script by matching a
fragment of its text. Tests start from this host and change one answer.
"""

import json

from scanner import windows_checks as wc
from tests.conftest import FakeProbe, ok

POLICY = {
    "MinimumPasswordAge": "1",
    "MaximumPasswordAge": "60",
    "MinimumPasswordLength": "14",
    "PasswordComplexity": "1",
    "PasswordHistorySize": "24",
    "LockoutBadCount": "5",
    "ResetLockoutCount": "15",
    "LockoutDuration": "15",
    "NewAdministratorName": '"localadm"',
    "NewGuestName": '"Guest"',
    "EnableAdminAccount": "0",
    "EnableGuestAccount": "0",
}

AUDIT_HEADER = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"


def audit_row(name, guid, setting="Success and Failure"):
    return ok(f"\r\n{AUDIT_HEADER}SRV01,System,{name},{guid},{setting},\r\n")


def registry_key(path, name):
    return f"$p = '{path}'; $n = '{name}'"


def reg(value):
    return ok(json.dumps({"found": True, "value": value}))


def reg_missing():
    return ok(json.dumps({"found": False}))


def service(name):
    return f"Get-Service -Name '{name}'"


def svc(exists=True, status="Stopped", start_type="Disabled"):
    return ok(json.dumps({"exists": exists, "status": status, "start_type": start_type} if exists else {"exists": False}))


SYSTEM_POLICIES = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
TS_POLICY = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
RDP_LISTENER = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
DNS_CLIENT = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
WINRM_POLICY = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
LSA = r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
LANMAN = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

DEFAULT_ACL = [
    {"sid": "S-1-5-18", "type": "Allow", "rights": 2032127},      # SYSTEM, FullControl
    {"sid": "S-1-5-32-544", "type": "Allow", "rights": 2032127},  # Administrators, FullControl
    {"sid": "S-1-5-32-545", "type": "Allow", "rights": 1179817},  # Users, ReadAndExecute
]


def hardened_windows(changes=None) -> FakeProbe:
    answers = {
        "IsInRole": ok("true"),
        "secedit.exe": ok(json.dumps(POLICY)),
        "Get-Volume": ok(json.dumps([{"drive": "C", "fs": "NTFS"}])),
        "System32\\config": ok(json.dumps(DEFAULT_ACL)),
        registry_key(TS_POLICY, "UserAuthentication"): reg_missing(),
        registry_key(RDP_LISTENER, "UserAuthentication"): reg(1),
        "Get-NetFirewallProfile": ok(json.dumps([{"name": n, "enabled": "True"} for n in ("Domain", "Private", "Public")])),
        "Get-SmbServerConfiguration": ok("false"),
        "Win32_NetworkAdapterConfiguration": ok(json.dumps([{"adapter": "Ethernet", "option": 2}])),
        registry_key(DNS_CLIENT, "EnableMulticast"): reg(0),
        service("WinRM"): svc(True, "Running", "Automatic"),
        registry_key(WINRM_POLICY, "AllowUnencryptedTraffic"): reg(0),
        "WSMan:": ok('"false"'),
        wc.AUDIT_LOGON: audit_row("Logon", wc.AUDIT_LOGON),
        wc.AUDIT_USER_ACCOUNT_MANAGEMENT: audit_row("User Account Management", wc.AUDIT_USER_ACCOUNT_MANAGEMENT),
        wc.AUDIT_SENSITIVE_PRIVILEGE_USE: audit_row("Sensitive Privilege Use", wc.AUDIT_SENSITIVE_PRIVILEGE_USE),
        "Get-WinEvent -ListLog Security": ok(str(196608 * 1024)),
        service("EventLog"): svc(True, "Running", "Automatic"),
        registry_key(SYSTEM_POLICIES, "EnableLUA"): reg(1),
        registry_key(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin"): reg(2),
        "Get-LocalGroupMember": ok(json.dumps([{"name": "SRV01\\localadm", "kind": "User"}])),
        registry_key(LSA, "RestrictAnonymousSAM"): reg(1),
        registry_key(LANMAN, "NullSessionShares"): reg([]),
        service("TlntSvr"): svc(False),
        service("FTPSVC"): svc(False),
        "Win32_ComputerSystem": ok("3"),
        service("Spooler"): svc(True, "Running", "Automatic"),
        service("RemoteRegistry"): svc(True, "Stopped", "Disabled"),
        service("SNMP"): svc(False),
    }
    answers.update(changes or {})
    return FakeProbe(scripts=answers, tools={"powershell"})
