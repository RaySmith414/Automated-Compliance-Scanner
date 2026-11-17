"""Linux check logic.

Titles, severities, remediation text and framework mappings live in
scanner/data/checks_linux.yaml. This module holds only the test for each check.

Rules every check follows:
  * Read the real state through the probe. Never substitute a default for a
    value that could not be read.
  * Return passed() or failed() only when the state was read.
  * Raise Unassessable when it could not be read (tool missing, timeout,
    permission). The runner reports that as ERROR.
  * Raise NotApplicable when the control does not apply to this host.
  * Return manual() when evidence was collected but a person has to judge it.
"""

import re
from typing import Dict, List, Optional

from scanner.model import NotApplicable, Outcome, Unassessable, failed, manual, passed

DEFAULT_FIND_TIMEOUT = 120
SAMPLE_LIMIT = 5

_TRUE_WORDS = {"yes", "true", "1", "on"}

# Mounts that hold no files of their own. `df` hides these as well.
PSEUDO_FILESYSTEMS = {
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "pstore", "bpf", "tracefs", "debugfs",
    "mqueue", "hugetlbfs", "fusectl", "configfs", "autofs", "binfmt_misc", "nsfs", "rpc_pipefs", "efivarfs",
    "selinuxfs", "fuse",
}
# Remote file systems are out of scope for a host scan, as with `df --local`.
NETWORK_FILESYSTEMS = {
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "lustre", "afs", "ncpfs", "davfs", "beegfs",
}


# --------------------------------------------------------------------------
# Pure helpers (unit tested directly)
# --------------------------------------------------------------------------

def mode_within(mode: int, limit: int) -> bool:
    """True when `mode` grants no permission bit beyond `limit`.

    This is a bitwise test. Comparing the two numbers would accept 0604 as
    "more restrictive" than 0640 although it lets everyone read the file.
    """
    return (mode & ~limit & 0o7777) == 0


def parse_login_defs(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0]] = parts[1].strip()
    return values


def parse_assignments(text: str) -> Dict[str, str]:
    """Parse KEY=VALUE lines (shell style or systemd unit style)."""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def parse_sshd_config(text: str) -> Dict[str, str]:
    """Parse `sshd -T` output: one lowercase keyword and its value per line."""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        key = parts[0].lower()
        if key not in values:
            values[key] = parts[1].strip() if len(parts) == 2 else ""
    return values


def _unescape_mount(path: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def parse_mountinfo(text: str) -> Dict[str, Dict[str, object]]:
    """Map mount point to its mount options and file system type.

    Later lines win, which matches what is visible when mounts are stacked.
    """
    mounts: Dict[str, Dict[str, object]] = {}
    for line in text.splitlines():
        parts = line.split()
        if "-" not in parts:
            continue
        sep = parts.index("-")
        if sep < 6 or sep + 1 >= len(parts):
            continue
        mounts[_unescape_mount(parts[4])] = {
            "options": set(parts[5].split(",")),
            "fstype": parts[sep + 1],
        }
    return mounts


def parse_filesystems(text: str) -> List[str]:
    """File system types the running kernel can mount right now."""
    return [line.split()[-1] for line in text.splitlines() if line.strip()]


def parse_passwd_uid0(text: str) -> List[str]:
    names = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 3 and fields[2].strip() == "0":
            names.append(fields[0])
    return names


def _sample(items: List[str]) -> str:
    shown = ", ".join(items[:SAMPLE_LIMIT])
    more = len(items) - SAMPLE_LIMIT
    return shown + (f" (and {more} more)" if more > 0 else "")


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

class LinuxChecks:
    """One method per `function` in checks_linux.yaml."""

    platform = "linux"

    def __init__(self, probe, find_timeout: int = DEFAULT_FIND_TIMEOUT):
        self.probe = probe
        self.find_timeout = find_timeout
        self._sshd: Optional[Dict[str, str]] = None
        self._package_tool: Optional[str] = None

    def is_privileged(self) -> bool:
        return self.probe.is_root()

    # ----------------------------------------------------------- shared readers

    def _login_defs(self) -> Dict[str, str]:
        text = self.probe.read_text("/etc/login.defs")
        if text is None:
            raise Unassessable("/etc/login.defs does not exist")
        return parse_login_defs(text)

    def _login_defs_int(self, key: str) -> Optional[int]:
        raw = self._login_defs().get(key)
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError as exc:
            raise Unassessable(f"{key} in /etc/login.defs is not a number: {raw!r}") from exc

    def _sshd_config(self) -> Dict[str, str]:
        if self._sshd is not None:
            return self._sshd
        sshd = self.probe.which("sshd")
        if sshd is None:
            raise NotApplicable("OpenSSH server is not installed")
        result = self.probe.run([sshd, "-T"]).require_ran()
        if not result.ok or not result.stdout.strip():
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise Unassessable("sshd -T failed" + (f": {detail[-1]}" if detail else ""))
        self._sshd = parse_sshd_config(result.stdout)
        return self._sshd

    def _sshd_value(self, keyword: str) -> str:
        value = self._sshd_config().get(keyword)
        if value is None:
            raise Unassessable(f"sshd -T did not report {keyword}")
        return value

    def _sysctl(self, key: str) -> str:
        """Value of a kernel parameter from the running kernel."""
        text = self.probe.read_text("/proc/sys/" + key.replace(".", "/"))
        if text is None:
            raise Unassessable(f"{key} is not present under /proc/sys")
        return text.strip()

    def _ipv6_enabled(self) -> bool:
        return self.probe.exists("/proc/sys/net/ipv6/conf/all")

    def _tmp_mount(self) -> Optional[Dict[str, object]]:
        return self._mounts().get("/tmp")

    def _installed(self, names: List[str]) -> List[str]:
        """Subset of `names` that is installed, using dpkg or rpm."""
        if self._package_tool is None:
            if self.probe.which("dpkg-query"):
                self._package_tool = "dpkg-query"
            elif self.probe.which("rpm"):
                self._package_tool = "rpm"
            else:
                raise Unassessable("no supported package manager found (dpkg or rpm)")
        installed = []
        for name in names:
            if self._package_tool == "dpkg-query":
                result = self.probe.run(["dpkg-query", "-W", "-f", "${db:Status-Status}", name]).require_ran()
                is_installed = result.ok and result.stdout.strip() == "installed"
            else:
                result = self.probe.run(["rpm", "-q", name]).require_ran()
                is_installed = result.ok
            # Both tools exit 1 for "no such package". Anything else is a broken query.
            if result.returncode not in (0, 1):
                raise Unassessable(f"{self._package_tool} failed with exit code {result.returncode}")
            if is_installed:
                installed.append(name)
        return installed

    def _mounts(self) -> Dict[str, Dict[str, object]]:
        text = self.probe.read_text("/proc/self/mountinfo")
        if text is None:
            raise Unassessable("/proc/self/mountinfo is not readable")
        return parse_mountinfo(text)

    def _local_mounts(self) -> List[str]:
        """Mount points of local file systems, the same set `df --local` reports."""
        mounts = [point for point, info in self._mounts().items()
                  if info["fstype"] not in PSEUDO_FILESYSTEMS and info["fstype"] not in NETWORK_FILESYSTEMS
                  and not str(info["fstype"]).startswith("fuse.")]
        # Inside a chroot the root directory is not a mount point of its own.
        return mounts if "/" in mounts else ["/"] + mounts

    def _find(self, expression: List[str]) -> List[str]:
        """Run find on every local file system. A timeout is never a clean result."""
        found = set()
        for mount in self._local_mounts():
            result = self.probe.run(["find", mount, "-xdev", *expression, "-print0"], timeout=self.find_timeout)
            if result.missing:
                raise Unassessable("find is not installed")
            if result.timed_out:
                raise Unassessable(
                    f"the search of {mount} did not finish within {self.find_timeout} seconds "
                    "(raise it with --find-timeout)"
                )
            if result.returncode not in (0, 1):
                raise Unassessable(f"find failed on {mount} with exit code {result.returncode}")
            found.update(path for path in result.stdout.split("\0") if path)
        return sorted(found)

    # --------------------------------------------------------------- filesystem

    def _module_disabled(self, name: str) -> Outcome:
        """Can the kernel mount this file system type, now or by loading a module?"""
        filesystems = self.probe.read_text("/proc/filesystems")
        if filesystems is None:
            raise Unassessable("/proc/filesystems is not readable")
        if name in parse_filesystems(filesystems):
            return failed(f"{name} is available in the running kernel (listed in /proc/filesystems)")
        modules = self.probe.read_text("/proc/modules")
        if modules is None:
            return passed(f"{name} is not built in and this kernel has no loadable module support")
        if any(line.split()[0] == name for line in modules.splitlines() if line.strip()):
            return failed(f"the {name} module is loaded")
        modprobe = self.probe.which("modprobe")
        if modprobe is None:
            raise Unassessable("modprobe is not installed, so kernel module policy cannot be read")
        result = self.probe.run([modprobe, "-n", "-v", name]).require_ran()
        output = result.stdout.strip()
        first = output.splitlines()[0].strip() if output else ""
        combined = (result.stdout + "\n" + result.stderr).lower()
        if re.match(r"install\s+(/usr)?/bin/(true|false)\b", first):
            return passed(f"loading {name} is disabled ({first})")
        if result.returncode != 0 and re.search(rf"module\s+{re.escape(name)}\s+not found", combined):
            return passed(f"the {name} module does not exist for this kernel")
        if first.startswith("insmod"):
            return failed(f"the {name} module can be loaded ({first})")
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise Unassessable("unexpected modprobe output" + (f": {detail[-1]}" if detail else ""))

    def cramfs_disabled(self) -> Outcome:
        return self._module_disabled("cramfs")

    def squashfs_disabled(self) -> Outcome:
        return self._module_disabled("squashfs")

    def udf_disabled(self) -> Outcome:
        return self._module_disabled("udf")

    def tmp_separate_mount(self) -> Outcome:
        mount = self._tmp_mount()
        if mount is None:
            return failed("/tmp is not a separate mount")
        return passed(f"/tmp is a separate {mount['fstype']} mount")

    def _tmp_option(self, option: str) -> Outcome:
        mount = self._tmp_mount()
        if mount is None:
            return failed(f"/tmp is not a separate mount, so {option} cannot be set")
        options = sorted(mount["options"])
        if option in mount["options"]:
            return passed(f"/tmp mount options: {','.join(options)}")
        return failed(f"{option} is missing from the /tmp mount options: {','.join(options)}")

    def tmp_noexec(self) -> Outcome:
        return self._tmp_option("noexec")

    def tmp_nodev(self) -> Outcome:
        return self._tmp_option("nodev")

    def tmp_nosuid(self) -> Outcome:
        return self._tmp_option("nosuid")

    # ----------------------------------------------------------- authentication

    def password_max_days(self) -> Outcome:
        days = self._login_defs_int("PASS_MAX_DAYS")
        if days is None:
            return failed("PASS_MAX_DAYS is not set in /etc/login.defs")
        if 1 <= days <= 365:
            return passed(f"PASS_MAX_DAYS = {days}")
        return failed(f"PASS_MAX_DAYS = {days}")

    def password_min_days(self) -> Outcome:
        days = self._login_defs_int("PASS_MIN_DAYS")
        if days is None:
            return failed("PASS_MIN_DAYS is not set in /etc/login.defs")
        return passed(f"PASS_MIN_DAYS = {days}") if days >= 1 else failed(f"PASS_MIN_DAYS = {days}")

    def password_warn_age(self) -> Outcome:
        days = self._login_defs_int("PASS_WARN_AGE")
        if days is None:
            return failed("PASS_WARN_AGE is not set in /etc/login.defs")
        return passed(f"PASS_WARN_AGE = {days}") if days >= 7 else failed(f"PASS_WARN_AGE = {days}")

    def inactive_password_lock(self) -> Outcome:
        raw = None
        defaults = self.probe.read_text("/etc/default/useradd")
        if defaults is not None:
            raw = parse_assignments(defaults).get("INACTIVE")
        if raw is None:
            useradd = self.probe.which("useradd")
            if useradd is None:
                raise Unassessable("useradd is not installed and /etc/default/useradd has no INACTIVE value")
            result = self.probe.run([useradd, "-D"]).require_ran()
            if not result.ok:
                raise Unassessable("useradd -D failed")
            raw = parse_assignments(result.stdout).get("INACTIVE")
        if raw is None:
            raise Unassessable("the useradd defaults do not report INACTIVE")
        try:
            days = int(raw)
        except ValueError as exc:
            raise Unassessable(f"INACTIVE is not a number: {raw!r}") from exc
        if days < 0:
            return failed(f"INACTIVE = {days} (inactive accounts are never locked)")
        return passed(f"INACTIVE = {days}") if days <= 30 else failed(f"INACTIVE = {days}")

    def root_only_uid0(self) -> Outcome:
        text = self.probe.read_text("/etc/passwd")
        if text is None:
            raise Unassessable("/etc/passwd does not exist")
        names = parse_passwd_uid0(text)
        if names == ["root"]:
            return passed("root is the only UID 0 account")
        if not names:
            return failed("no account has UID 0")
        return failed(f"UID 0 accounts: {', '.join(names)}")

    def root_console_restricted(self) -> Outcome:
        pam = self.probe.read_text("/etc/pam.d/login")
        in_use = pam is not None and any(
            "pam_securetty" in line and not line.strip().startswith("#") for line in pam.splitlines()
        )
        if not in_use:
            raise NotApplicable(
                "pam_securetty is not enabled in /etc/pam.d/login, so /etc/securetty is not consulted on this host"
            )
        securetty = self.probe.read_text("/etc/securetty")
        if securetty is None:
            return failed(
                "pam_securetty is enabled but /etc/securetty does not exist, so root may log in on any terminal")
        terminals = [line.strip() for line in securetty.splitlines()
                     if line.strip() and not line.strip().startswith("#")]
        if not terminals:
            return passed("/etc/securetty is empty, so root cannot log in on any terminal directly")
        return manual(f"{len(terminals)} terminals are listed in /etc/securetty: {_sample(terminals)}")

    def ssh_root_login_disabled(self) -> Outcome:
        value = self._sshd_value("permitrootlogin")
        return passed("PermitRootLogin no") if value == "no" else failed(f"PermitRootLogin {value}")

    def ssh_empty_passwords_disabled(self) -> Outcome:
        value = self._sshd_value("permitemptypasswords")
        return passed("PermitEmptyPasswords no") if value == "no" else failed(f"PermitEmptyPasswords {value}")

    def ssh_password_authentication_review(self) -> Outcome:
        value = self._sshd_value("passwordauthentication")
        if value == "no":
            return passed("PasswordAuthentication no")
        return manual(f"PasswordAuthentication {value}. Confirm that site policy allows password logins over SSH")

    def ssh_max_auth_tries(self) -> Outcome:
        raw = self._sshd_value("maxauthtries")
        try:
            tries = int(raw)
        except ValueError as exc:
            raise Unassessable(f"MaxAuthTries is not a number: {raw!r}") from exc
        return passed(f"MaxAuthTries {tries}") if tries <= 4 else failed(f"MaxAuthTries {tries}")

    # ------------------------------------------------------------------ network

    def _sysctl_all_equal(self, keys: List[str], wanted: str, ipv6_keys: Optional[List[str]] = None) -> Outcome:
        readings = [(key, self._sysctl(key)) for key in keys]
        note = ""
        if ipv6_keys:
            if self._ipv6_enabled():
                readings += [(key, self._sysctl(key)) for key in ipv6_keys]
            else:
                note = "; IPv6 is not enabled"
        actual = ", ".join(f"{key} = {value}" for key, value in readings) + note
        return passed(actual) if all(value == wanted for _, value in readings) else failed(actual)

    def ip_forwarding_disabled(self) -> Outcome:
        return self._sysctl_all_equal(["net.ipv4.ip_forward"], "0", ["net.ipv6.conf.all.forwarding"])

    def send_redirects_disabled(self) -> Outcome:
        return self._sysctl_all_equal(
            ["net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"], "0")

    def source_route_rejected(self) -> Outcome:
        return self._sysctl_all_equal(
            ["net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route"], "0",
            ["net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route"])

    def icmp_redirects_rejected(self) -> Outcome:
        return self._sysctl_all_equal(
            ["net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects"], "0",
            ["net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects"])

    def icmp_broadcast_ignored(self) -> Outcome:
        return self._sysctl_all_equal(["net.ipv4.icmp_echo_ignore_broadcasts"], "1")

    def syn_cookies_enabled(self) -> Outcome:
        return self._sysctl_all_equal(["net.ipv4.tcp_syncookies"], "1")

    def firewall_active(self) -> Outcome:
        inactive: List[str] = []
        unreadable: List[str] = []
        tools = 0

        ufw = self.probe.which("ufw")
        if ufw:
            tools += 1
            result = self.probe.run([ufw, "status"]).require_ran()
            if result.ok and re.search(r"^Status:\s*active", result.stdout, re.M):
                return passed("ufw is active")
            (inactive if result.ok else unreadable).append("ufw is inactive" if result.ok else "ufw status failed")

        firewall_cmd = self.probe.which("firewall-cmd")
        if firewall_cmd:
            tools += 1
            result = self.probe.run([firewall_cmd, "--state"]).require_ran()
            if result.ok and "running" in result.stdout:
                return passed("firewalld is running")
            inactive.append("firewalld is not running")

        nft = self.probe.which("nft")
        if nft:
            tools += 1
            result = self.probe.run([nft, "list", "ruleset"]).require_ran()
            if result.ok and re.search(r"hook\s+input", result.stdout):
                return passed("nftables has a rule set with an input hook")
            (inactive if result.ok else unreadable).append(
                "nftables has no input chain" if result.ok else "nft list ruleset failed")

        iptables = self.probe.which("iptables")
        if iptables:
            tools += 1
            result = self.probe.run([iptables, "-S"]).require_ran()
            if result.ok:
                lines = result.stdout.splitlines()
                rules = [line for line in lines if line.startswith("-A")]
                drops = [line for line in lines if re.match(r"-P (INPUT|FORWARD) DROP", line)]
                if rules or drops:
                    return passed(f"iptables has {len(rules)} rules and {len(drops)} default-drop policies")
                inactive.append("iptables has no rules and accepts by default")
            else:
                unreadable.append("iptables -S failed")

        if tools == 0:
            return failed("no firewall tool is installed (ufw, firewalld, nftables or iptables)")
        if unreadable:
            raise Unassessable("; ".join(unreadable + inactive))
        return failed("; ".join(inactive))

    # ------------------------------------------------------------------ logging

    def rsyslog_installed(self) -> Outcome:
        if self._installed(["rsyslog"]):
            return passed("rsyslog is installed")
        return failed("rsyslog is not installed")

    def rsyslog_enabled(self) -> Outcome:
        if not self._installed(["rsyslog"]):
            return failed("rsyslog is not installed")
        systemctl = self.probe.which("systemctl")
        if systemctl is None:
            raise Unassessable("systemctl is not installed")
        result = self.probe.run([systemctl, "is-enabled", "rsyslog"]).require_ran()
        state = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        if state in ("enabled", "enabled-runtime", "alias", "static"):
            return passed(f"rsyslog unit state: {state}")
        if state in ("disabled", "masked", "masked-runtime", "indirect"):
            return failed(f"rsyslog unit state: {state}")
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise Unassessable("systemctl is-enabled gave no usable answer" + (f": {detail[-1]}" if detail else ""))

    def _journald_setting(self, key: str) -> Optional[str]:
        main = self.probe.read_text("/etc/systemd/journald.conf")
        present = main is not None or any(
            self.probe.exists(p) for p in ("/usr/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald"))
        if not present:
            raise NotApplicable("systemd-journald is not installed")
        value = parse_assignments(main or "").get(key)
        dropins: Dict[str, str] = {}
        for directory in ("/usr/lib/systemd/journald.conf.d", "/run/systemd/journald.conf.d",
                          "/etc/systemd/journald.conf.d"):
            for name in self.probe.list_dir(directory):
                if name.endswith(".conf"):
                    dropins[name] = f"{directory}/{name}"   # later directories override earlier ones
        for name in sorted(dropins):
            text = self.probe.read_text(dropins[name])
            if text is not None and key in parse_assignments(text):
                value = parse_assignments(text)[key]
        return value

    def journald_compress(self) -> Outcome:
        value = self._journald_setting("Compress")
        if value is None:
            return failed("Compress is not set in the journald configuration")
        return passed(f"Compress={value}") if value.lower() in _TRUE_WORDS else failed(f"Compress={value}")

    def journald_persistent(self) -> Outcome:
        value = self._journald_setting("Storage")
        if value is None:
            return failed("Storage is not set in the journald configuration")
        return passed(f"Storage={value}") if value.lower() == "persistent" else failed(f"Storage={value}")

    def var_log_permissions(self) -> Outcome:
        info = self.probe.stat("/var/log")
        if info is None:
            raise Unassessable("/var/log does not exist")
        actual = f"mode {info.mode:04o}, owner {info.owner}:{info.group}"
        good = info.uid == 0 and (info.gid == 0 or info.group in ("adm", "syslog")) and mode_within(info.mode, 0o775)
        return passed(actual) if good else failed(actual)

    # ----------------------------------------------------------- access control

    def _file_permissions(self, path: str, limit: int, groups: List[str]) -> Outcome:
        info = self.probe.stat(path)
        if info is None:
            raise Unassessable(f"{path} does not exist")
        actual = f"mode {info.mode:04o}, owner {info.owner}:{info.group}"
        group_ok = info.gid == 0 or info.group in groups
        good = info.uid == 0 and group_ok and mode_within(info.mode, limit)
        return passed(actual) if good else failed(actual)

    def passwd_permissions(self) -> Outcome:
        return self._file_permissions("/etc/passwd", 0o644, [])

    def shadow_permissions(self) -> Outcome:
        return self._file_permissions("/etc/shadow", 0o640, ["shadow"])

    def group_permissions(self) -> Outcome:
        return self._file_permissions("/etc/group", 0o644, [])

    def no_world_writable_files(self) -> Outcome:
        files = self._find(["-type", "f", "-perm", "-0002"])
        if not files:
            return passed("no world writable files on local file systems")
        return failed(f"{len(files)} world writable files, for example: {_sample(files)}")

    def no_unowned_files(self) -> Outcome:
        paths = self._find(["(", "-nouser", "-o", "-nogroup", ")"])
        if not paths:
            return passed("every file and directory on local file systems has an owner and a group")
        return failed(f"{len(paths)} paths without a valid owner or group, for example: {_sample(paths)}")

    def suid_sgid_review(self) -> Outcome:
        files = self._find(["-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"])
        if not files:
            return passed("no SUID or SGID files on local file systems")
        return manual(f"{len(files)} SUID or SGID files to compare with your baseline, for example: {_sample(files)}")

    # ----------------------------------------------------------------- services

    def _must_be_absent(self, label: str, packages: List[str]) -> Outcome:
        installed = self._installed(packages)
        if installed:
            return failed(f"{label} installed: {', '.join(installed)}")
        return passed(f"no {label} package is installed")

    def _absent_unless_required(self, label: str, packages: List[str]) -> Outcome:
        installed = self._installed(packages)
        if installed:
            return manual(f"{label} installed: {', '.join(installed)}. Confirm that this host needs it")
        return passed(f"no {label} package is installed")

    def xinetd_not_installed(self) -> Outcome:
        return self._must_be_absent("xinetd", ["xinetd"])

    def telnet_server_not_installed(self) -> Outcome:
        return self._must_be_absent("telnet server", ["telnetd", "inetutils-telnetd", "telnetd-ssl", "telnet-server"])

    def ftp_server_not_installed(self) -> Outcome:
        return self._must_be_absent("FTP server", ["vsftpd", "proftpd-basic", "proftpd-core", "proftpd", "pure-ftpd"])

    def http_server_review(self) -> Outcome:
        return self._absent_unless_required(
            "web server", ["apache2", "nginx", "nginx-core", "nginx-full", "nginx-light", "lighttpd", "httpd"])

    def ldap_server_review(self) -> Outcome:
        return self._absent_unless_required("LDAP server", ["slapd", "openldap-servers"])

    def nfs_server_review(self) -> Outcome:
        return self._absent_unless_required("NFS server", ["nfs-kernel-server"])
