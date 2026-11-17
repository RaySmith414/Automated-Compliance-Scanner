"""Linux check logic, exercised through the same path the scanner uses.

Each case starts from a clean fake host, changes one fact and states the
verdict that must follow. The tests cover the failure modes that used to be
reported as PASS: missing tools, timeouts, unreadable state and numeric
permission comparisons.
"""

import pytest

from scanner.catalog import load_checks
from scanner.linux_checks import (
    LinuxChecks,
    mode_within,
    parse_assignments,
    parse_filesystems,
    parse_login_defs,
    parse_mountinfo,
    parse_passwd_uid0,
    parse_sshd_config,
)
from scanner.runner import run_check
from tests.conftest import denied, fail, missing, ok, stat, timed_out
from tests.linux_host import FILESYSTEMS, MOUNTINFO, PAM_LOGIN, PASSWD, SSHD_T, hardened_probe

CHECKS = {check.function: check for check in load_checks("linux")}
ALL_TOOLS = {"modprobe", "sshd", "dpkg-query", "systemctl", "ufw", "find", "useradd"}


def verdict(function, probe, find_timeout=120):
    checker = LinuxChecks(probe, find_timeout=find_timeout)
    return run_check(CHECKS[function], checker, checker.is_privileged())


def find_results(world=(), unowned=(), suid=(), mounts=("/",)):
    def run(argv):
        if "-0002" in argv:
            items = world
        elif "-nouser" in argv:
            items = unowned
        else:
            items = suid
        return ok("".join(path + "\0" for path in items) if argv[1] in mounts else "")
    return run


# ---------------------------------------------------------------- pure helpers

@pytest.mark.parametrize("mode, limit, expected", [
    (0o640, 0o640, True),
    (0o600, 0o640, True),
    (0o400, 0o640, True),
    (0o000, 0o640, True),
    (0o604, 0o640, False),   # world readable: numerically smaller than 0640, still wrong
    (0o444, 0o640, False),
    (0o606, 0o640, False),
    (0o641, 0o640, False),
    (0o660, 0o640, False),
    (0o644, 0o644, True),
    (0o446, 0o644, False),
    (0o4644, 0o644, False),  # setuid bit is not allowed either
    (0o755, 0o775, True),
    (0o777, 0o775, False),
])
def test_mode_within_is_bitwise(mode, limit, expected):
    assert mode_within(mode, limit) is expected


def test_parse_login_defs_ignores_comments_and_keeps_last_token():
    values = parse_login_defs("# c\nPASS_MAX_DAYS\t90  # trailing\nPASS_MIN_DAYS 1\n\nUMASK\t\t027\n")
    assert values == {"PASS_MAX_DAYS": "90", "PASS_MIN_DAYS": "1", "UMASK": "027"}


def test_parse_assignments_handles_sections_quotes_and_comments():
    text = '[Journal]\n#Compress=no\nCompress=yes\nStorage="persistent"\n; other\nBAD LINE\n'
    assert parse_assignments(text) == {"Compress": "yes", "Storage": "persistent"}


def test_parse_sshd_config_lowercases_and_keeps_first_value():
    values = parse_sshd_config("PermitRootLogin no\nhostkey /a\nhostkey /b\nport 22\n")
    assert values["permitrootlogin"] == "no"
    assert values["hostkey"] == "/a"


def test_parse_mountinfo_reads_options_and_type():
    mounts = parse_mountinfo(MOUNTINFO)
    assert mounts["/tmp"]["fstype"] == "tmpfs"
    assert {"noexec", "nodev", "nosuid"} <= mounts["/tmp"]["options"]
    assert "/var" not in mounts


def test_parse_mountinfo_decodes_escaped_spaces_and_prefers_later_mount():
    text = ("40 28 8:2 / /mnt/my\\040disk rw,relatime - ext4 /dev/sdb1 rw\n"
            "41 28 0:40 / /tmp rw,relatime - tmpfs tmpfs rw\n"
            "42 41 0:41 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n")
    mounts = parse_mountinfo(text)
    assert "/mnt/my disk" in mounts
    assert "noexec" in mounts["/tmp"]["options"]


def test_parse_filesystems_lists_built_in_and_loaded_types():
    assert parse_filesystems("nodev\tsysfs\n\text4\nnodev\tproc\n\tsquashfs\n") == ["sysfs", "ext4", "proc", "squashfs"]


def test_local_mounts_skip_pseudo_and_network_file_systems():
    text = MOUNTINFO + ("50 28 0:50 / /mnt/share rw,relatime - nfs4 nas:/export rw\n"
                        "51 28 0:51 / /run/user/1000/gvfs rw - fuse.gvfsd-fuse gvfsd-fuse rw\n"
                        "52 28 8:17 / /data rw,relatime - xfs /dev/sdb1 rw\n")
    checker = LinuxChecks(hardened_probe(files={"/proc/self/mountinfo": text}))
    assert checker._local_mounts() == ["/", "/tmp", "/data"]


def test_local_mounts_fall_back_to_root_inside_a_chroot():
    text = "23 28 0:22 / /proc rw,nosuid - proc proc rw\n36 28 0:31 / /tmp rw,nosuid - tmpfs tmpfs rw\n"
    checker = LinuxChecks(hardened_probe(files={"/proc/self/mountinfo": text}))
    assert checker._local_mounts() == ["/", "/tmp"]


def test_parse_passwd_uid0_lists_every_uid_zero_account():
    assert parse_passwd_uid0(PASSWD + "toor:x:0:0::/root:/bin/sh\n") == ["root", "toor"]


# ------------------------------------------------------------- the clean host

EXPECTED_ON_CLEAN_HOST = {check.function: "PASS" for check in load_checks("linux")}
EXPECTED_ON_CLEAN_HOST["root_console_restricted"] = "NOT_APPLICABLE"


@pytest.mark.parametrize("function", sorted(CHECKS))
def test_clean_host(function):
    result = verdict(function, hardened_probe())
    assert result["status"] == EXPECTED_ON_CLEAN_HOST[function], result["actual"]


def test_every_catalog_function_is_covered_by_the_clean_host():
    assert set(EXPECTED_ON_CLEAN_HOST) == {check.function for check in load_checks("linux")}


# ------------------------------------------------------------------ one change

def without(*tools):
    return ALL_TOOLS - set(tools)


CASES = [
    # --- kernel modules
    ("cramfs_disabled", lambda: hardened_probe(commands={("modprobe", "-n", "-v"): ok(
        "insmod /lib/modules/6.8.0-45-generic/kernel/fs/cramfs/cramfs.ko.zst \n")}), "FAIL", "can be loaded"),
    ("cramfs_disabled", lambda: hardened_probe(files={"/proc/modules": "cramfs 61440 0 - Live 0x0\n"}),
     "FAIL", "is loaded"),
    ("cramfs_disabled", lambda: hardened_probe(commands={("modprobe", "-n", "-v"): fail(
        1, stderr="modprobe: FATAL: Module cramfs not found in directory /lib/modules/6.8.0-45-generic\n")}),
     "PASS", "does not exist"),
    ("cramfs_disabled", lambda: hardened_probe(commands={("modprobe", "-n", "-v"): ok("install /bin/true \n")}),
     "PASS", "disabled"),
    ("squashfs_disabled", lambda: hardened_probe(files={"/proc/filesystems": FILESYSTEMS + "\tsquashfs\n"}),
     "FAIL", "available in the running kernel"),
    ("squashfs_disabled", lambda: hardened_probe(commands={("modprobe", "-n", "-v"): ok("")}),
     "ERROR", "unexpected modprobe output"),
    ("squashfs_disabled", lambda: hardened_probe(files={"/proc/filesystems": None}), "ERROR", "/proc/filesystems"),
    ("udf_disabled", lambda: hardened_probe(tools=without("modprobe")), "ERROR", "modprobe is not installed"),
    ("udf_disabled", lambda: hardened_probe(files={"/proc/modules": None}), "PASS", "no loadable module support"),
    ("udf_disabled", lambda: hardened_probe(files={"/proc/modules": None, "/proc/filesystems": FILESYSTEMS + "nodev\tudf\n"}),
     "FAIL", "available in the running kernel"),
    ("udf_disabled", lambda: hardened_probe(commands={("modprobe", "-n", "-v"): timed_out()}), "ERROR", "timed out"),
    ("udf_disabled", lambda: hardened_probe(commands={("modprobe", "-n", "-v"): fail(1, stderr="weird failure\n")}),
     "ERROR", "unexpected modprobe output"),
    # --- /tmp
    ("tmp_separate_mount", lambda: hardened_probe(files={"/proc/self/mountinfo": MOUNTINFO.rsplit("\n", 2)[0] + "\n"}),
     "FAIL", "not a separate mount"),
    ("tmp_noexec", lambda: hardened_probe(files={"/proc/self/mountinfo": MOUNTINFO.rsplit("\n", 2)[0] + "\n"}),
     "FAIL", "noexec cannot be set"),
    ("tmp_noexec", lambda: hardened_probe(files={"/proc/self/mountinfo": MOUNTINFO.replace(",noexec", "")}),
     "FAIL", "noexec is missing"),
    ("tmp_nodev", lambda: hardened_probe(files={"/proc/self/mountinfo": MOUNTINFO.replace(",nodev", "", 3)}),
     "FAIL", "nodev is missing"),
    ("tmp_nosuid", lambda: hardened_probe(files={"/proc/self/mountinfo": None}), "ERROR", "mountinfo"),
    # --- password policy
    ("password_max_days", lambda: hardened_probe(files={"/etc/login.defs": "PASS_MAX_DAYS 99999\n"}),
     "FAIL", "PASS_MAX_DAYS = 99999"),
    ("password_max_days", lambda: hardened_probe(files={"/etc/login.defs": "PASS_MAX_DAYS 0\n"}), "FAIL", "= 0"),
    ("password_max_days", lambda: hardened_probe(files={"/etc/login.defs": "UMASK 027\n"}), "FAIL", "is not set"),
    ("password_max_days", lambda: hardened_probe(files={"/etc/login.defs": None}), "ERROR", "does not exist"),
    ("password_max_days", lambda: hardened_probe(files={"/etc/login.defs": "PASS_MAX_DAYS ninety\n"}),
     "ERROR", "not a number"),
    ("password_max_days", lambda: hardened_probe(files={"/etc/login.defs": denied("/etc/login.defs")}),
     "ERROR", "no permission"),
    ("password_min_days", lambda: hardened_probe(files={"/etc/login.defs": "PASS_MIN_DAYS 0\n"}), "FAIL", "= 0"),
    ("password_warn_age", lambda: hardened_probe(files={"/etc/login.defs": "PASS_WARN_AGE 3\n"}), "FAIL", "= 3"),
    ("inactive_password_lock", lambda: hardened_probe(files={"/etc/default/useradd": "INACTIVE=-1\n"}),
     "FAIL", "never locked"),
    ("inactive_password_lock", lambda: hardened_probe(files={"/etc/default/useradd": "INACTIVE=45\n"}),
     "FAIL", "INACTIVE = 45"),
    ("inactive_password_lock", lambda: hardened_probe(
        files={"/etc/default/useradd": None},
        commands={("useradd", "-D"): ok("GROUP=100\nHOME=/home\nINACTIVE=30\nEXPIRE=\n")}), "PASS", "INACTIVE = 30"),
    ("inactive_password_lock", lambda: hardened_probe(files={"/etc/default/useradd": None}, tools=without("useradd")),
     "ERROR", "useradd is not installed"),
    # --- accounts
    ("root_only_uid0", lambda: hardened_probe(files={"/etc/passwd": PASSWD + "toor:x:0:0::/root:/bin/sh\n"}),
     "FAIL", "root, toor"),
    ("root_only_uid0", lambda: hardened_probe(files={"/etc/passwd": None}), "ERROR", "does not exist"),
    ("root_console_restricted", lambda: hardened_probe(
        files={"/etc/pam.d/login": PAM_LOGIN + "auth required pam_securetty.so\n"}), "FAIL", "does not exist"),
    ("root_console_restricted", lambda: hardened_probe(
        files={"/etc/pam.d/login": PAM_LOGIN + "auth required pam_securetty.so\n",
               "/etc/securetty": "# consoles\ntty1\nttyS0\n"}), "MANUAL", "2 terminals"),
    ("root_console_restricted", lambda: hardened_probe(
        files={"/etc/pam.d/login": PAM_LOGIN + "#auth required pam_securetty.so\n"}), "NOT_APPLICABLE", "not enabled"),
    # --- sshd
    ("ssh_root_login_disabled", lambda: hardened_probe(tools=without("sshd")), "NOT_APPLICABLE", "not installed"),
    ("ssh_root_login_disabled", lambda: hardened_probe(root=False), "ERROR", "needs root"),
    ("ssh_root_login_disabled", lambda: hardened_probe(commands={("sshd", "-T"): fail(
        255, stderr="sshd: no hostkeys available -- exiting.\n")}), "ERROR", "no hostkeys"),
    ("ssh_root_login_disabled", lambda: hardened_probe(commands={("sshd", "-T"): ok(
        SSHD_T.replace("permitrootlogin no", "permitrootlogin prohibit-password"))}), "FAIL", "prohibit-password"),
    ("ssh_root_login_disabled", lambda: hardened_probe(commands={("sshd", "-T"): ok("port 22\n")}),
     "ERROR", "did not report permitrootlogin"),
    ("ssh_empty_passwords_disabled", lambda: hardened_probe(commands={("sshd", "-T"): ok(
        SSHD_T.replace("permitemptypasswords no", "permitemptypasswords yes"))}), "FAIL", "yes"),
    ("ssh_password_authentication_review", lambda: hardened_probe(commands={("sshd", "-T"): ok(
        SSHD_T.replace("passwordauthentication no", "passwordauthentication yes"))}), "MANUAL", "site policy"),
    ("ssh_max_auth_tries", lambda: hardened_probe(commands={("sshd", "-T"): ok(
        SSHD_T.replace("maxauthtries 4", "maxauthtries 6"))}), "FAIL", "MaxAuthTries 6"),
    ("ssh_max_auth_tries", lambda: hardened_probe(tools=without("sshd")), "NOT_APPLICABLE", "not installed"),
    # --- kernel network parameters
    ("ip_forwarding_disabled", lambda: hardened_probe(files={"/proc/sys/net/ipv4/ip_forward": "1\n"}),
     "FAIL", "net.ipv4.ip_forward = 1"),
    ("ip_forwarding_disabled", lambda: hardened_probe(files={"/proc/sys/net/ipv6/conf/all/forwarding": "1\n"}),
     "FAIL", "net.ipv6.conf.all.forwarding = 1"),
    ("ip_forwarding_disabled", lambda: hardened_probe(
        files={"/proc/sys/net/ipv6/conf/all/forwarding": None}, existing=set()), "PASS", "IPv6 is not enabled"),
    ("ip_forwarding_disabled", lambda: hardened_probe(files={"/proc/sys/net/ipv4/ip_forward": None}),
     "ERROR", "net.ipv4.ip_forward is not present"),
    ("send_redirects_disabled", lambda: hardened_probe(
        files={"/proc/sys/net/ipv4/conf/default/send_redirects": "1\n"}), "FAIL", "default.send_redirects = 1"),
    ("source_route_rejected", lambda: hardened_probe(
        files={"/proc/sys/net/ipv6/conf/default/accept_source_route": "1\n"}), "FAIL", "ipv6.conf.default"),
    ("icmp_redirects_rejected", lambda: hardened_probe(
        files={"/proc/sys/net/ipv4/conf/all/accept_redirects": "1\n"}), "FAIL", "all.accept_redirects = 1"),
    ("icmp_broadcast_ignored", lambda: hardened_probe(
        files={"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts": "0\n"}), "FAIL", "= 0"),
    ("syn_cookies_enabled", lambda: hardened_probe(files={"/proc/sys/net/ipv4/tcp_syncookies": "0\n"}), "FAIL", "= 0"),
    # --- firewall
    ("firewall_active", lambda: hardened_probe(commands={("ufw", "status"): ok("Status: inactive\n")}),
     "FAIL", "ufw is inactive"),
    ("firewall_active", lambda: hardened_probe(tools=without("ufw")), "FAIL", "no firewall tool"),
    ("firewall_active", lambda: hardened_probe(root=False), "ERROR", "needs root"),
    ("firewall_active", lambda: hardened_probe(
        tools=without("ufw") | {"nft"},
        commands={("nft", "list", "ruleset"): ok("table inet filter {\n\tchain input {\n\t\ttype filter hook input "
                                               "priority filter; policy drop;\n\t}\n}\n")}), "PASS", "nftables"),
    ("firewall_active", lambda: hardened_probe(
        tools=without("ufw") | {"iptables"},
        commands={("iptables", "-S"): ok("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n")}),
     "PASS", "iptables has 1 rules"),
    ("firewall_active", lambda: hardened_probe(
        tools=without("ufw") | {"iptables"},
        commands={("iptables", "-S"): ok("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n")}),
     "FAIL", "accepts by default"),
    ("firewall_active", lambda: hardened_probe(
        tools=without("ufw") | {"iptables"},
        commands={("iptables", "-S"): fail(4, stderr="iptables: Permission denied (you must be root)\n")}),
     "ERROR", "iptables -S failed"),
    ("firewall_active", lambda: hardened_probe(
        tools=ALL_TOOLS | {"iptables"},
        commands={("ufw", "status"): ok("Status: inactive\n"), ("iptables", "-S"): fail(4)}),
     "ERROR", "iptables -S failed; ufw is inactive"),
    # --- logging
    ("rsyslog_installed", lambda: hardened_probe(commands={("dpkg-query",): fail(1)}), "FAIL", "not installed"),
    ("rsyslog_installed", lambda: hardened_probe(tools=without("dpkg-query")), "ERROR", "no supported package manager"),
    ("rsyslog_installed", lambda: hardened_probe(
        tools=without("dpkg-query") | {"rpm"}, commands={("rpm", "-q", "rsyslog"): ok("rsyslog-8.2102.0-117.el9.x86_64\n")}),
     "PASS", "is installed"),
    ("rsyslog_enabled", lambda: hardened_probe(commands={("dpkg-query",): fail(1)}), "FAIL", "not installed"),
    ("rsyslog_enabled", lambda: hardened_probe(commands={("systemctl", "is-enabled", "rsyslog"): fail(1, "disabled\n")}),
     "FAIL", "disabled"),
    ("rsyslog_enabled", lambda: hardened_probe(tools=without("systemctl")), "ERROR", "systemctl is not installed"),
    ("rsyslog_enabled", lambda: hardened_probe(commands={("systemctl", "is-enabled", "rsyslog"): fail(
        1, stderr="Failed to get unit file state for rsyslog.service: Connection refused\n")}), "ERROR", "Connection refused"),
    ("journald_compress", lambda: hardened_probe(files={"/etc/systemd/journald.conf": "[Journal]\n#Compress=yes\n"}),
     "FAIL", "is not set"),
    ("journald_compress", lambda: hardened_probe(
        dirs={"/etc/systemd/journald.conf.d": ["90-local.conf"]},
        files={"/etc/systemd/journald.conf.d/90-local.conf": "[Journal]\nCompress=no\n"}), "FAIL", "Compress=no"),
    ("journald_compress", lambda: hardened_probe(
        files={"/etc/systemd/journald.conf": "[Journal]\n", "/etc/systemd/journald.conf.d/10-cis.conf": "[Journal]\nCompress=yes\n"},
        dirs={"/etc/systemd/journald.conf.d": ["10-cis.conf"]}), "PASS", "Compress=yes"),
    ("journald_persistent", lambda: hardened_probe(files={"/etc/systemd/journald.conf": "[Journal]\nStorage=auto\n"}),
     "FAIL", "Storage=auto"),
    ("journald_persistent", lambda: hardened_probe(files={"/etc/systemd/journald.conf": None}),
     "NOT_APPLICABLE", "not installed"),
    ("var_log_permissions", lambda: hardened_probe(stats={"/var/log": stat(0o777, "root", "syslog")}), "FAIL", "0777"),
    ("var_log_permissions", lambda: hardened_probe(stats={"/var/log": stat(0o755, "bob", "bob")}), "FAIL", "bob"),
    ("var_log_permissions", lambda: hardened_probe(stats={"/var/log": None}), "ERROR", "does not exist"),
    # --- file permissions: the cases a numeric comparison gets wrong
    ("shadow_permissions", lambda: hardened_probe(stats={"/etc/shadow": stat(0o604, "root", "shadow")}), "FAIL", "0604"),
    ("shadow_permissions", lambda: hardened_probe(stats={"/etc/shadow": stat(0o444, "root", "shadow")}), "FAIL", "0444"),
    ("shadow_permissions", lambda: hardened_probe(stats={"/etc/shadow": stat(0o600, "root", "root")}), "PASS", "0600"),
    ("shadow_permissions", lambda: hardened_probe(stats={"/etc/shadow": stat(0o640, "root", "users")}), "FAIL", "users"),
    ("shadow_permissions", lambda: hardened_probe(stats={"/etc/shadow": stat(0o640, "bob", "shadow")}), "FAIL", "bob"),
    ("shadow_permissions", lambda: hardened_probe(stats={"/etc/shadow": None}), "ERROR", "does not exist"),
    ("passwd_permissions", lambda: hardened_probe(stats={"/etc/passwd": stat(0o646)}), "FAIL", "0646"),
    ("passwd_permissions", lambda: hardened_probe(stats={"/etc/passwd": stat(0o444)}), "PASS", "0444"),
    ("group_permissions", lambda: hardened_probe(stats={"/etc/group": stat(0o664)}), "FAIL", "0664"),
    # --- file system searches
    ("no_world_writable_files", lambda: hardened_probe(commands={("find",): find_results(
        world=["/srv/a", "/srv/b"])}), "FAIL", "2 world writable files"),
    ("no_world_writable_files", lambda: hardened_probe(commands={("find",): timed_out()}), "ERROR", "did not finish"),
    ("no_world_writable_files", lambda: hardened_probe(commands={("find",): fail(2)}), "ERROR", "exit code 2"),
    ("no_world_writable_files", lambda: hardened_probe(commands={("find",): fail(1)}), "PASS", "no world writable"),
    ("no_world_writable_files", lambda: hardened_probe(tools=without("find")), "ERROR", "find is not installed"),
    ("no_world_writable_files", lambda: hardened_probe(files={"/proc/self/mountinfo": None}), "ERROR", "mountinfo"),
    ("no_world_writable_files", lambda: hardened_probe(root=False), "ERROR", "needs root"),
    ("no_unowned_files", lambda: hardened_probe(commands={("find",): find_results(
        unowned=["/run/x", "/run/x"], mounts=("/", "/tmp"))}), "FAIL", "1 paths without"),
    ("no_unowned_files", lambda: hardened_probe(commands={("find",): timed_out("/partial\0")}), "ERROR", "did not finish"),
    ("suid_sgid_review", lambda: hardened_probe(commands={("find",): find_results(
        suid=["/usr/bin/sudo", "/usr/bin/passwd"])}), "MANUAL", "2 SUID or SGID files"),
    ("suid_sgid_review", lambda: hardened_probe(commands={("find",): timed_out()}), "ERROR", "did not finish"),
    # --- services
    ("xinetd_not_installed", lambda: hardened_probe(commands={("dpkg-query",): ok("installed")}), "FAIL", "xinetd"),
    ("telnet_server_not_installed", lambda: hardened_probe(commands={("dpkg-query", "-W", "-f", "${db:Status-Status}",
                                                                      "telnetd"): ok("installed")}), "FAIL", "telnetd"),
    ("telnet_server_not_installed", lambda: hardened_probe(commands={("dpkg-query", "-W", "-f", "${db:Status-Status}",
                                                                      "telnetd"): ok("config-files")}),
     "PASS", "no telnet server"),
    ("ftp_server_not_installed", lambda: hardened_probe(tools=without("dpkg-query")), "ERROR", "package manager"),
    ("http_server_review", lambda: hardened_probe(commands={("dpkg-query", "-W", "-f", "${db:Status-Status}",
                                                             "nginx"): ok("installed")}), "MANUAL", "nginx"),
    ("ldap_server_review", lambda: hardened_probe(commands={("dpkg-query",): timed_out()}), "ERROR", "timed out"),
    ("nfs_server_review", lambda: hardened_probe(commands={("dpkg-query", "-W", "-f", "${db:Status-Status}",
                                                            "nfs-kernel-server"): ok("installed")}), "MANUAL", "NFS"),
]


@pytest.mark.parametrize("function, build, status, fragment", CASES,
                         ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_one_change(function, build, status, fragment):
    result = verdict(function, build())
    assert result["status"] == status, result["actual"]
    assert fragment in result["actual"], result["actual"]


def test_every_check_has_a_failing_or_blocking_case():
    covered = {case[0] for case in CASES if case[2] != "PASS"}
    assert covered == set(CHECKS), sorted(set(CHECKS) - covered)


# ------------------------------------------------- no answer is never a PASS

def test_a_host_where_nothing_can_be_read_has_no_pass_at_all():
    from tests.conftest import FakeProbe

    empty = FakeProbe(root=True)
    statuses = {function: verdict(function, empty)["status"] for function in CHECKS}
    assert "PASS" not in statuses.values(), {f: s for f, s in statuses.items() if s == "PASS"}
    assert set(statuses.values()) <= {"ERROR", "NOT_APPLICABLE", "FAIL"}


def test_tools_that_time_out_or_fail_never_produce_a_pass():
    for broken in (timed_out(), fail(127, stderr="command not found"), missing()):
        probe = hardened_probe(commands={
            ("modprobe", "-n", "-v"): broken, ("sshd", "-T"): broken, ("dpkg-query",): broken,
            ("systemctl", "is-enabled", "rsyslog"): broken, ("ufw", "status"): broken,
            ("find",): broken,
        })
        command_checks = [
            "cramfs_disabled", "squashfs_disabled", "udf_disabled", "ssh_root_login_disabled",
            "ssh_empty_passwords_disabled", "ssh_password_authentication_review", "ssh_max_auth_tries",
            "rsyslog_installed", "rsyslog_enabled", "no_world_writable_files", "no_unowned_files", "suid_sgid_review",
            "xinetd_not_installed", "telnet_server_not_installed", "ftp_server_not_installed", "http_server_review",
            "ldap_server_review", "nfs_server_review",
        ]
        for function in command_checks:
            status = verdict(function, probe)["status"]
            assert status == "ERROR", (function, broken, status)


def test_actual_text_never_reports_a_value_that_was_not_read():
    probe = hardened_probe(tools=without("sshd"), files={"/etc/login.defs": None, "/etc/default/useradd": None},
                           commands={("useradd", "-D"): fail(1)})
    for function in ("ssh_max_auth_tries", "password_max_days", "inactive_password_lock"):
        actual = verdict(function, probe)["actual"]
        assert not any(token in actual for token in ("= 6", "99999", "= -1", "= 0")), actual


def test_find_timeout_setting_reaches_the_probe():
    seen = []

    class Recorder(type(hardened_probe())):
        def run(self, argv, timeout=30):
            seen.append((argv[0].rsplit("/", 1)[-1], timeout))
            return super().run(argv, timeout)

    probe = hardened_probe()
    probe.__class__ = Recorder
    verdict("no_world_writable_files", probe, find_timeout=7)
    assert ("find", 7) in seen


def test_sshd_config_is_read_once_per_scan():
    probe = hardened_probe()
    checker = LinuxChecks(probe)
    for function in ("ssh_root_login_disabled", "ssh_empty_passwords_disabled", "ssh_max_auth_tries"):
        run_check(CHECKS[function], checker, True)
    assert sum(1 for call in probe.calls if call[0].endswith("sshd")) == 1
