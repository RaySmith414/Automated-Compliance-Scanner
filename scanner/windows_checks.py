"""Windows check logic.

Titles, severities, remediation text and framework mappings live in
scanner/data/checks_windows.yaml. This module holds only the test for each
check. The rules in scanner/linux_checks.py apply here too: a state that could
not be read is never reported as PASS or as a default value.

Every query runs through PowerShell and returns JSON, so the decision logic in
Python can be tested with recorded output on any platform.
"""

import csv
import io
import json
import os
from typing import Any, Dict, List, Optional

from scanner.model import NotApplicable, Outcome, Unassessable, failed, manual, passed


def powershell_executable() -> str:
    """Path of Windows PowerShell.

    On Windows this is the absolute path under %SystemRoot%. A bare name would let
    a powershell.exe planted in the working directory run with the scanner's
    rights, because Windows searches that directory before PATH. Sysnative comes
    first so that a 32-bit Python on 64-bit Windows still reads the 64-bit
    registry view.
    """
    root = os.environ.get("SystemRoot")
    if os.name == "nt" and root:
        for system_dir in ("Sysnative", "System32"):
            candidate = os.path.join(root, system_dir, "WindowsPowerShell", "v1.0", "powershell.exe")
            if os.path.isfile(candidate):
                return candidate
    return "powershell"


POWERSHELL = [powershell_executable(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]

# SIDs that are the same on every Windows language edition.
SID_EVERYONE = "S-1-1-0"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_USERS = "S-1-5-32-545"
BROAD_SIDS = {SID_EVERYONE: "Everyone", SID_AUTHENTICATED_USERS: "Authenticated Users", SID_USERS: "Users"}

# FileSystemRights bits that let a principal change a folder or its content.
WRITE_RIGHTS = (
    0x2          # WriteData / CreateFiles
    | 0x4        # AppendData / CreateDirectories
    | 0x10       # WriteExtendedAttributes
    | 0x40       # DeleteSubdirectoriesAndFiles
    | 0x100      # WriteAttributes
    | 0x10000    # Delete
    | 0x40000    # ChangePermissions
    | 0x80000    # TakeOwnership
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)

# Advanced audit policy subcategory GUIDs (identical on every language edition).
AUDIT_LOGON = "{0CCE9215-69AE-11D9-BED3-505054503030}"
AUDIT_USER_ACCOUNT_MANAGEMENT = "{0CCE9235-69AE-11D9-BED3-505054503030}"
AUDIT_SENSITIVE_PRIVILEGE_USE = "{0CCE9228-69AE-11D9-BED3-505054503030}"

PS_IS_ADMIN = (
    "[bool](([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) | ConvertTo-Json"
)

PS_SECURITY_POLICY = r"""
$ErrorActionPreference = 'Stop'
$f = Join-Path $env:TEMP ('secpol_' + [guid]::NewGuid().ToString('N') + '.inf')
try {
  secedit.exe /export /cfg $f /areas SECURITYPOLICY | Out-Null
  if (-not (Test-Path -LiteralPath $f)) { throw 'secedit produced no file' }
  $map = @{}
  foreach ($line in Get-Content -LiteralPath $f) {
    if ($line -match '^\s*([^=\[\]]+?)\s*=\s*(.*)$') { $map[$matches[1].Trim()] = $matches[2].Trim() }
  }
  $map | ConvertTo-Json -Compress
} finally {
  if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
}
"""

PS_REGISTRY_VALUE = r"""
$ErrorActionPreference = 'Stop'
$p = '%(path)s'; $n = '%(name)s'
if (-not (Test-Path -LiteralPath $p)) { @{found=$false} | ConvertTo-Json -Compress; exit 0 }
$item = Get-ItemProperty -LiteralPath $p
if ($null -eq $item.PSObject.Properties[$n]) { @{found=$false} | ConvertTo-Json -Compress; exit 0 }
@{found=$true; value=$item.$n} | ConvertTo-Json -Compress
"""

PS_SERVICE = r"""
$s = Get-Service -Name '%(name)s' -ErrorAction SilentlyContinue
if ($null -eq $s) { @{exists=$false} | ConvertTo-Json -Compress }
else { @{exists=$true; status=$s.Status.ToString(); start_type=$s.StartType.ToString()} | ConvertTo-Json -Compress }
"""

PS_VOLUMES = r"""
$ErrorActionPreference = 'Stop'
$v = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | ForEach-Object {
  $fs = if ($_.FileSystem) { [string]$_.FileSystem } else { [string]$_.FileSystemType }
  @{drive=[string]$_.DriveLetter; fs=$fs} })
ConvertTo-Json -InputObject $v -Compress
"""

PS_CONFIG_ACL = r"""
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath (Join-Path $env:SystemRoot 'System32\config')
$out = @(foreach ($ace in $acl.Access) {
  $sid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
         catch { [string]$ace.IdentityReference }
  @{sid=$sid; type=[string]$ace.AccessControlType; rights=[int]$ace.FileSystemRights}
})
ConvertTo-Json -InputObject $out -Compress
"""

PS_FIREWALL = r"""
$ErrorActionPreference = 'Stop'
$p = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  @{name=[string]$_.Name; enabled=[string]$_.Enabled} })
ConvertTo-Json -InputObject $p -Compress
"""

PS_SMB1 = r"""
$ErrorActionPreference = 'Stop'
[bool](Get-SmbServerConfiguration).EnableSMB1Protocol | ConvertTo-Json
"""

PS_NETBIOS = r"""
$ErrorActionPreference = 'Stop'
$a = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' | ForEach-Object {
  @{adapter=[string]$_.Description; option=[int]$_.TcpipNetbiosOptions} })
ConvertTo-Json -InputObject $a -Compress
"""

PS_WINRM_ALLOW_UNENCRYPTED = r"""
$ErrorActionPreference = 'Stop'
[string](Get-Item -Path WSMan:\localhost\Service\AllowUnencrypted).Value | ConvertTo-Json
"""

PS_AUDITPOL = "auditpol.exe /get /subcategory:'%(guid)s' /r"

PS_SECURITY_LOG_SIZE = r"""
$ErrorActionPreference = 'Stop'
[long](Get-WinEvent -ListLog Security).MaximumSizeInBytes | ConvertTo-Json
"""

PS_ADMINISTRATORS = r"""
$ErrorActionPreference = 'Stop'
$m = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
  @{name=[string]$_.Name; kind=[string]$_.ObjectClass} })
ConvertTo-Json -InputObject $m -Compress
"""

PS_DOMAIN_ROLE = r"""
$ErrorActionPreference = 'Stop'
[int](Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole | ConvertTo-Json
"""


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _error_detail(result) -> str:
    """The message line of a failed command, without the position lines PowerShell adds."""
    lines = [line.strip() for line in result.stderr.splitlines()]
    message = " ".join(line for line in lines
                       if line and not line.startswith(("#< CLIXML", "<Objs", "At line:", "+ ")))
    return (message or _last_line(result.stdout))[:300]


def _unwrap(data: Any) -> Any:
    """Windows PowerShell 5.1 can serialize an array as {"value": [...], "Count": n}."""
    if isinstance(data, dict) and set(data) == {"value", "Count"} and isinstance(data["value"], list):
        return data["value"]
    return data


def _as_int(value: Any, what: str) -> int:
    try:
        return int(str(value).strip().strip('"'))
    except (TypeError, ValueError) as exc:
        raise Unassessable(f"{what} is not a number: {value!r}") from exc


def has_write_rights(rights: int) -> bool:
    """True when a FileSystemRights value includes any right that modifies data."""
    return bool(rights & WRITE_RIGHTS)


class WindowsChecks:
    """One method per `function` in checks_windows.yaml."""

    platform = "windows"

    def __init__(self, probe):
        self.probe = probe
        self._policy: Optional[Dict[str, str]] = None
        self._admin: Optional[bool] = None

    # ----------------------------------------------------------- shared readers

    def _ps_json(self, script: str, what: str, timeout: int = 60) -> Any:
        result = self.probe.run(POWERSHELL + [script], timeout=timeout)
        if result.missing:
            raise Unassessable("PowerShell is not available")
        if result.timed_out:
            raise Unassessable(f"{what} timed out")
        if not result.ok:
            detail = _error_detail(result)
            raise Unassessable(f"{what} failed" + (f": {detail}" if detail else ""))
        text = result.stdout.strip()
        if not text:
            raise Unassessable(f"{what} returned no data")
        try:
            return _unwrap(json.loads(text))
        except ValueError as exc:
            raise Unassessable(f"{what} returned output that is not JSON") from exc

    def is_privileged(self) -> bool:
        if self._admin is None:
            try:
                self._admin = bool(self._ps_json(PS_IS_ADMIN, "the administrator check"))
            except Unassessable:
                self._admin = False
        return self._admin

    def _security_policy(self) -> Dict[str, str]:
        if self._policy is None:
            data = self._ps_json(PS_SECURITY_POLICY, "the security policy export (secedit)")
            if not isinstance(data, dict):
                raise Unassessable("the security policy export returned an unexpected shape")
            self._policy = {str(k): str(v) for k, v in data.items()}
        return self._policy

    def _policy_int(self, key: str) -> Optional[int]:
        raw = self._security_policy().get(key)
        return None if raw is None else _as_int(raw, key)

    def _registry(self, path: str, name: str) -> Optional[Any]:
        """Registry value. None when the key or the value does not exist."""
        data = self._ps_json(PS_REGISTRY_VALUE % {"path": path, "name": name}, f"reading {name} from the registry")
        if not isinstance(data, dict) or "found" not in data:
            raise Unassessable(f"reading {name} from the registry returned an unexpected shape")
        return data.get("value") if data["found"] else None

    def _service(self, name: str) -> Dict[str, Any]:
        data = self._ps_json(PS_SERVICE % {"name": name}, f"the {name} service query")
        if not isinstance(data, dict) or "exists" not in data:
            raise Unassessable(f"the {name} service query returned an unexpected shape")
        return data

    def _service_disabled(self, name: str, label: str) -> Outcome:
        service = self._service(name)
        if not service["exists"]:
            return passed(f"the {label} service is not installed")
        actual = f"{label} service start type: {service.get('start_type')}, status: {service.get('status')}"
        return passed(actual) if service.get("start_type") == "Disabled" else failed(actual)

    def _audit_setting(self, guid: str, label: str) -> Outcome:
        result = self.probe.run(POWERSHELL + [PS_AUDITPOL % {"guid": guid}], timeout=60).require_ran()
        if not result.ok:
            detail = _error_detail(result)
            raise Unassessable("auditpol failed" + (f": {detail}" if detail else ""))
        rows = [row for row in csv.reader(io.StringIO(result.stdout)) if row]
        if len(rows) < 2 or len(rows[1]) < 5:
            raise Unassessable("auditpol returned no row for the subcategory")
        setting = rows[1][4].strip()
        if setting == "Success and Failure":
            return passed(f"{label}: {setting}")
        if setting in ("Success", "Failure", "No Auditing"):
            return failed(f"{label}: {setting}")
        raise Unassessable(f"auditpol returned a setting this scanner does not recognize: {setting!r}")

    # --------------------------------------------------------------- filesystem

    def fixed_volumes_use_ntfs(self) -> Outcome:
        volumes = self._ps_json(PS_VOLUMES, "the volume query")
        if not isinstance(volumes, list):
            raise Unassessable("the volume query returned an unexpected shape")
        if not volumes:
            raise Unassessable("no fixed volume with a drive letter was reported")
        other = [f"{v.get('drive')}: ({v.get('fs') or 'unknown'})" for v in volumes
                 if str(v.get("fs", "")).upper() not in ("NTFS", "REFS")]
        if other:
            return failed(f"volumes not on NTFS or ReFS: {', '.join(other)}")
        return passed(f"{len(volumes)} fixed volumes, all NTFS or ReFS")

    def system_config_acl(self) -> Outcome:
        entries = self._ps_json(PS_CONFIG_ACL, "reading the ACL of System32\\config")
        if not isinstance(entries, list) or not entries:
            raise Unassessable("the ACL of System32\\config came back empty")
        broad = []
        for entry in entries:
            if entry.get("type") != "Allow" or entry.get("sid") not in BROAD_SIDS:
                continue
            if has_write_rights(_as_int(entry.get("rights"), "FileSystemRights")):
                broad.append(BROAD_SIDS[entry["sid"]])
        if broad:
            return failed(f"write access granted to: {', '.join(sorted(set(broad)))}")
        return passed(f"{len(entries)} ACL entries, none gives write access to Everyone, Users or Authenticated Users")

    # ----------------------------------------------------------- authentication

    def password_history(self) -> Outcome:
        value = self._policy_int("PasswordHistorySize")
        if value is None:
            raise Unassessable("the security policy export has no PasswordHistorySize")
        actual = f"PasswordHistorySize = {value}"
        return passed(actual) if value >= 24 else failed(actual)

    def password_max_age(self) -> Outcome:
        value = self._policy_int("MaximumPasswordAge")
        if value is None:
            raise Unassessable("the security policy export has no MaximumPasswordAge")
        if value <= 0:
            return failed(f"MaximumPasswordAge = {value} (passwords never expire)")
        actual = f"MaximumPasswordAge = {value}"
        return passed(actual) if value <= 365 else failed(actual)

    def password_min_age(self) -> Outcome:
        value = self._policy_int("MinimumPasswordAge")
        if value is None:
            raise Unassessable("the security policy export has no MinimumPasswordAge")
        actual = f"MinimumPasswordAge = {value}"
        return passed(actual) if value >= 1 else failed(actual)

    def password_min_length(self) -> Outcome:
        value = self._policy_int("MinimumPasswordLength")
        if value is None:
            raise Unassessable("the security policy export has no MinimumPasswordLength")
        actual = f"MinimumPasswordLength = {value}"
        return passed(actual) if value >= 14 else failed(actual)

    def password_complexity(self) -> Outcome:
        value = self._policy_int("PasswordComplexity")
        if value is None:
            raise Unassessable("the security policy export has no PasswordComplexity")
        actual = f"PasswordComplexity = {value}"
        return passed(actual) if value == 1 else failed(actual)

    def lockout_threshold(self) -> Outcome:
        value = self._policy_int("LockoutBadCount")
        if value is None:
            raise Unassessable("the security policy export has no LockoutBadCount")
        if value == 0:
            return failed("LockoutBadCount = 0 (accounts never lock)")
        actual = f"LockoutBadCount = {value}"
        return passed(actual) if 1 <= value <= 5 else failed(actual)

    def lockout_duration(self) -> Outcome:
        threshold = self._policy_int("LockoutBadCount")
        if threshold is None:
            raise Unassessable("the security policy export has no LockoutBadCount")
        if threshold == 0:
            return failed("no lockout threshold is set, so a lockout duration never applies")
        value = self._policy_int("LockoutDuration")
        if value is None:
            raise Unassessable("the security policy export has no LockoutDuration")
        if value == -1:
            return passed("LockoutDuration = -1 (locked until an administrator clears it)")
        actual = f"LockoutDuration = {value} minutes"
        return passed(actual) if value >= 15 else failed(actual)

    def guest_account_disabled(self) -> Outcome:
        value = self._policy_int("EnableGuestAccount")
        if value is None:
            raise Unassessable("the security policy export has no EnableGuestAccount")
        actual = f"EnableGuestAccount = {value}"
        return passed(actual) if value == 0 else failed(actual)

    def administrator_renamed(self) -> Outcome:
        raw = self._security_policy().get("NewAdministratorName")
        if raw is None:
            raise Unassessable("the security policy export has no NewAdministratorName")
        name = raw.strip().strip('"')
        if name.lower() == "administrator":
            return failed("the built-in administrator account is still named Administrator")
        return passed("the built-in administrator account has been renamed")

    def rdp_nla_required(self) -> Outcome:
        policy = self._registry(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication")
        if policy is not None:
            value, source = _as_int(policy, "UserAuthentication"), "policy"
        else:
            listener = self._registry(
                r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
            if listener is None:
                return failed("UserAuthentication is not set for the RDP-Tcp listener or in policy")
            value, source = _as_int(listener, "UserAuthentication"), "RDP-Tcp listener"
        actual = f"UserAuthentication = {value} ({source})"
        return passed(actual) if value == 1 else failed(actual)

    # ------------------------------------------------------------------ network

    def firewall_profiles_enabled(self) -> Outcome:
        profiles = self._ps_json(PS_FIREWALL, "the firewall profile query")
        if not isinstance(profiles, list) or not profiles:
            raise Unassessable("the firewall profile query returned no profiles")
        off = [str(p.get("name")) for p in profiles if str(p.get("enabled")).lower() not in ("true", "1")]
        if off:
            return failed(f"firewall profiles not enabled: {', '.join(off)}")
        return passed(f"enabled profiles: {', '.join(str(p.get('name')) for p in profiles)}")

    def smbv1_disabled(self) -> Outcome:
        enabled = self._ps_json(PS_SMB1, "the SMB server configuration query")
        if not isinstance(enabled, bool):
            raise Unassessable("the SMB server configuration query returned an unexpected value")
        return failed("EnableSMB1Protocol = True") if enabled else passed("EnableSMB1Protocol = False")

    def netbios_disabled(self) -> Outcome:
        adapters = self._ps_json(PS_NETBIOS, "the network adapter query")
        if not isinstance(adapters, list):
            raise Unassessable("the network adapter query returned an unexpected shape")
        if not adapters:
            raise NotApplicable("no IP-enabled network adapter is present")
        on = [str(a.get("adapter")) for a in adapters if _as_int(a.get("option"), "TcpipNetbiosOptions") != 2]
        if on:
            return failed(f"NetBIOS over TCP/IP is not disabled on: {', '.join(on)}")
        return passed(f"NetBIOS over TCP/IP is disabled on all {len(adapters)} IP-enabled adapters")

    def llmnr_disabled(self) -> Outcome:
        value = self._registry(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast")
        if value is None:
            return failed("the EnableMulticast policy value is not set, so LLMNR is on by default")
        number = _as_int(value, "EnableMulticast")
        actual = f"EnableMulticast = {number}"
        return passed(actual) if number == 0 else failed(actual)

    def winrm_requires_encryption(self) -> Outcome:
        service = self._service("WinRM")
        if not service["exists"] or service.get("start_type") == "Disabled":
            raise NotApplicable("the WinRM service is not installed or is disabled")
        policy = self._registry(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic")
        if policy is not None:
            number = _as_int(policy, "AllowUnencryptedTraffic")
            actual = f"AllowUnencryptedTraffic = {number} (policy)"
            return passed(actual) if number == 0 else failed(actual)
        if service.get("status") != "Running":
            raise Unassessable("WinRM is stopped and no policy value is set, so the live setting cannot be read")
        value = str(self._ps_json(PS_WINRM_ALLOW_UNENCRYPTED, "reading the WinRM service configuration")).lower()
        if value == "false":
            return passed("AllowUnencrypted = false")
        if value == "true":
            return failed("AllowUnencrypted = true")
        raise Unassessable(f"the WinRM setting came back as {value!r}")

    # ------------------------------------------------------------------ logging

    def audit_logon(self) -> Outcome:
        return self._audit_setting(AUDIT_LOGON, "Audit Logon")

    def audit_user_account_management(self) -> Outcome:
        return self._audit_setting(AUDIT_USER_ACCOUNT_MANAGEMENT, "Audit User Account Management")

    def audit_sensitive_privilege_use(self) -> Outcome:
        return self._audit_setting(AUDIT_SENSITIVE_PRIVILEGE_USE, "Audit Sensitive Privilege Use")

    def security_log_size(self) -> Outcome:
        size_kb = _as_int(self._ps_json(PS_SECURITY_LOG_SIZE, "the Security log query"), "MaximumSizeInBytes") // 1024
        actual = f"Security log maximum size: {size_kb} KB"
        return passed(actual) if size_kb >= 196608 else failed(actual)

    def event_log_service_running(self) -> Outcome:
        service = self._service("EventLog")
        if not service["exists"]:
            return failed("the EventLog service is not installed")
        actual = f"EventLog service status: {service.get('status')}"
        return passed(actual) if service.get("status") == "Running" else failed(actual)

    # ----------------------------------------------------------- access control

    def uac_enabled(self) -> Outcome:
        value = self._registry(r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        if value is None:
            return failed("EnableLUA is not set")
        number = _as_int(value, "EnableLUA")
        actual = f"EnableLUA = {number}"
        return passed(actual) if number == 1 else failed(actual)

    def uac_admin_prompt(self) -> Outcome:
        value = self._registry(
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
        if value is None:
            return failed("ConsentPromptBehaviorAdmin is not set")
        number = _as_int(value, "ConsentPromptBehaviorAdmin")
        actual = f"ConsentPromptBehaviorAdmin = {number}"
        return passed(actual) if number in (1, 2) else failed(actual)

    def administrators_group_review(self) -> Outcome:
        members = self._ps_json(PS_ADMINISTRATORS, "the Administrators group query")
        if not isinstance(members, list):
            raise Unassessable("the Administrators group query returned an unexpected shape")
        names = [str(m.get("name")) for m in members]
        return manual(f"{len(names)} members of the local Administrators group to review: {', '.join(names) or 'none'}")

    def anonymous_sam_enumeration_restricted(self) -> Outcome:
        value = self._registry(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM")
        if value is None:
            return failed("RestrictAnonymousSAM is not set")
        number = _as_int(value, "RestrictAnonymousSAM")
        actual = f"RestrictAnonymousSAM = {number}"
        return passed(actual) if number == 1 else failed(actual)

    def null_session_shares_restricted(self) -> Outcome:
        value = self._registry(r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionShares")
        if value is None:
            return passed("NullSessionShares is not set")
        shares: List[str] = [str(v) for v in (value if isinstance(value, list) else [value]) if str(v).strip()]
        if shares:
            return failed(f"shares open to anonymous access: {', '.join(shares)}")
        return passed("NullSessionShares is empty")

    # ----------------------------------------------------------------- services

    def telnet_service_disabled(self) -> Outcome:
        return self._service_disabled("TlntSvr", "Telnet")

    def ftp_service_disabled(self) -> Outcome:
        return self._service_disabled("FTPSVC", "Microsoft FTP")

    def print_spooler_on_domain_controller(self) -> Outcome:
        role = _as_int(self._ps_json(PS_DOMAIN_ROLE, "the domain role query"), "DomainRole")
        if role not in (4, 5):
            raise NotApplicable("this host is not a domain controller")
        return self._service_disabled("Spooler", "Print Spooler")

    def remote_registry_disabled(self) -> Outcome:
        return self._service_disabled("RemoteRegistry", "Remote Registry")

    def snmp_service_disabled(self) -> Outcome:
        return self._service_disabled("SNMP", "SNMP")
