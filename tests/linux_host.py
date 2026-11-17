"""A fake Ubuntu host where every Linux check has a clean answer.

Tests start from this host and change one fact to prove that a check reacts to
it. The command output below follows the format seen on Ubuntu 22.04 and
24.04 systems.
"""

from tests.conftest import FakeProbe, fail, ok, stat

SSHD_T = """port 22
permitrootlogin no
permitemptypasswords no
passwordauthentication no
maxauthtries 4
pubkeyauthentication yes
x11forwarding no
"""

MOUNTINFO = """22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
36 28 0:31 / /tmp rw,nosuid,nodev,noexec,relatime shared:18 - tmpfs tmpfs rw,size=2097152k
"""

FILESYSTEMS = """nodev\tsysfs
nodev\ttmpfs
nodev\tproc
\text3
\text4
\tvfat
"""

LOGIN_DEFS = """# /etc/login.defs
PASS_MAX_DAYS\t365
PASS_MIN_DAYS\t1
PASS_WARN_AGE\t7
UMASK 027
"""

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
"""

PAM_LOGIN = """auth       optional   pam_faildelay.so  delay=3000000
auth       requisite  pam_nologin.so
session    required   pam_loginuid.so
"""

JOURNALD = """[Journal]
Storage=persistent
Compress=yes
#Seal=yes
"""

MODULES = """ext4 1011712 1 - Live 0x0000000000000000
nf_tables 372736 0 - Live 0x0000000000000000
"""

SYSCTL = {
    "/proc/sys/net/ipv4/ip_forward": "0\n",
    "/proc/sys/net/ipv6/conf/all/forwarding": "0\n",
    "/proc/sys/net/ipv4/conf/all/send_redirects": "0\n",
    "/proc/sys/net/ipv4/conf/default/send_redirects": "0\n",
    "/proc/sys/net/ipv4/conf/all/accept_source_route": "0\n",
    "/proc/sys/net/ipv4/conf/default/accept_source_route": "0\n",
    "/proc/sys/net/ipv6/conf/all/accept_source_route": "0\n",
    "/proc/sys/net/ipv6/conf/default/accept_source_route": "0\n",
    "/proc/sys/net/ipv4/conf/all/accept_redirects": "0\n",
    "/proc/sys/net/ipv4/conf/default/accept_redirects": "0\n",
    "/proc/sys/net/ipv6/conf/all/accept_redirects": "0\n",
    "/proc/sys/net/ipv6/conf/default/accept_redirects": "0\n",
    "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts": "1\n",
    "/proc/sys/net/ipv4/tcp_syncookies": "1\n",
}

INSTALLED = {"rsyslog"}


def dpkg_query(argv):
    package = argv[-1]
    return ok("installed") if package in INSTALLED else fail(1, stderr=f"dpkg-query: no packages found matching {package}")


def hardened_probe(**changes) -> FakeProbe:
    """Build the clean host. Keyword arguments replace whole sections."""
    files = {
        "/etc/login.defs": LOGIN_DEFS,
        "/etc/default/useradd": "# useradd defaults\nINACTIVE=30\n",
        "/etc/passwd": PASSWD,
        "/etc/pam.d/login": PAM_LOGIN,
        "/etc/systemd/journald.conf": JOURNALD,
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n',
        "/proc/modules": MODULES,
        "/proc/filesystems": FILESYSTEMS,
        "/proc/self/mountinfo": MOUNTINFO,
        **SYSCTL,
    }
    stats = {
        "/var/log": stat(0o775, "root", "syslog"),
        "/etc/passwd": stat(0o644),
        "/etc/shadow": stat(0o640, "root", "shadow"),
        "/etc/group": stat(0o644),
    }
    commands = {
        ("modprobe", "-n", "-v"): ok("install /bin/false \n"),
        ("sshd", "-T"): ok(SSHD_T),
        ("dpkg-query",): dpkg_query,
        ("systemctl", "is-enabled", "rsyslog"): ok("enabled\n"),
        ("ufw", "status"): ok("Status: active\n\nTo                         Action      From\n"),
        ("find",): ok(""),
    }
    probe = FakeProbe(
        files=files, stats=stats, commands=commands,
        tools={"modprobe", "sshd", "dpkg-query", "systemctl", "ufw", "find", "useradd"},
        existing={"/proc/sys/net/ipv6/conf/all"},
    )
    for section, value in changes.items():
        current = getattr(probe, section)
        if isinstance(current, dict):
            current.update(value)
            for key in [k for k, v in current.items() if v is None]:
                del current[key]
        else:
            setattr(probe, section, value)
    return probe
