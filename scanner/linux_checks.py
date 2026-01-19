"""
Linux CIS Benchmark Compliance Checks
Based on CIS Benchmark for Ubuntu Linux 22.04 LTS

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import os
import subprocess
import re
import stat
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class LinuxComplianceChecker:
    """Performs CIS Benchmark compliance checks on Linux systems"""

    def __init__(self):
        self.results = {
            'system_info': self._get_system_info(),
            'scan_time': None,
            'checks': []
        }

        # Define all checks with metadata
        self.checks = {
            'filesystem': [
                ('FS-001', 'Ensure mounting of cramfs is disabled', 'high', self.check_cramfs_disabled),
                ('FS-002', 'Ensure mounting of squashfs is disabled', 'medium', self.check_squashfs_disabled),
                ('FS-003', 'Ensure mounting of udf is disabled', 'low', self.check_udf_disabled),
                ('FS-004', 'Ensure /tmp is a separate partition', 'high', self.check_tmp_partition),
                ('FS-005', 'Ensure noexec option set on /tmp', 'high', self.check_tmp_noexec),
                ('FS-006', 'Ensure nodev option set on /tmp', 'medium', self.check_tmp_nodev),
                ('FS-007', 'Ensure nosuid option set on /tmp', 'medium', self.check_tmp_nosuid),
            ],
            'authentication': [
                ('AUTH-001', 'Ensure password expiration is 365 days or less', 'high', self.check_password_max_days),
                ('AUTH-002', 'Ensure minimum days between password changes', 'medium', self.check_password_min_days),
                ('AUTH-003', 'Ensure password expiration warning is 7 days', 'low', self.check_password_warn_age),
                ('AUTH-004', 'Ensure inactive password lock is 30 days or less', 'medium', self.check_inactive_lock),
                ('AUTH-005', 'Ensure root is the only UID 0 account', 'critical', self.check_root_only_uid0),
                ('AUTH-006', 'Ensure root login is restricted to console', 'high', self.check_root_console_only),
                ('AUTH-007', 'Ensure SSH root login is disabled', 'critical', self.check_ssh_root_login),
                ('AUTH-008', 'Ensure SSH PermitEmptyPasswords is disabled', 'critical', self.check_ssh_empty_passwords),
                ('AUTH-009', 'Ensure SSH PasswordAuthentication is configured', 'medium', self.check_ssh_password_auth),
                ('AUTH-010', 'Ensure SSH MaxAuthTries is 4 or less', 'medium', self.check_ssh_max_auth_tries),
            ],
            'network': [
                ('NET-001', 'Ensure IP forwarding is disabled', 'high', self.check_ip_forwarding),
                ('NET-002', 'Ensure packet redirect sending is disabled', 'medium', self.check_send_redirects),
                ('NET-003', 'Ensure source routed packets are not accepted', 'medium', self.check_source_route),
                ('NET-004', 'Ensure ICMP redirects are not accepted', 'medium', self.check_icmp_redirects),
                ('NET-005', 'Ensure broadcast ICMP requests are ignored', 'medium', self.check_icmp_broadcast),
                ('NET-006', 'Ensure TCP SYN Cookies are enabled', 'high', self.check_syn_cookies),
                ('NET-007', 'Ensure firewall is active', 'critical', self.check_firewall_active),
            ],
            'logging': [
                ('LOG-001', 'Ensure rsyslog is installed', 'high', self.check_rsyslog_installed),
                ('LOG-002', 'Ensure rsyslog service is enabled', 'high', self.check_rsyslog_enabled),
                ('LOG-003', 'Ensure journald is configured to compress logs', 'low', self.check_journald_compress),
                ('LOG-004', 'Ensure journald is configured to write to persistent storage', 'medium', self.check_journald_persistent),
                ('LOG-005', 'Ensure permissions on /var/log are configured', 'medium', self.check_var_log_permissions),
            ],
            'access_control': [
                ('AC-001', 'Ensure permissions on /etc/passwd are configured', 'high', self.check_passwd_permissions),
                ('AC-002', 'Ensure permissions on /etc/shadow are configured', 'critical', self.check_shadow_permissions),
                ('AC-003', 'Ensure permissions on /etc/group are configured', 'high', self.check_group_permissions),
                ('AC-004', 'Ensure no world-writable files exist', 'high', self.check_world_writable),
                ('AC-005', 'Ensure no unowned files exist', 'medium', self.check_unowned_files),
                ('AC-006', 'Ensure SUID/SGID files are reviewed', 'high', self.check_suid_sgid_files),
            ],
            'services': [
                ('SVC-001', 'Ensure xinetd is not installed', 'medium', self.check_xinetd_not_installed),
                ('SVC-002', 'Ensure telnet server is not installed', 'critical', self.check_telnet_not_installed),
                ('SVC-003', 'Ensure FTP server is not installed', 'high', self.check_ftp_not_installed),
                ('SVC-004', 'Ensure HTTP server is not installed (unless required)', 'medium', self.check_http_not_installed),
                ('SVC-005', 'Ensure LDAP server is not installed (unless required)', 'medium', self.check_ldap_not_installed),
                ('SVC-006', 'Ensure NFS is not installed (unless required)', 'medium', self.check_nfs_not_installed),
            ]
        }

    def _get_system_info(self) -> Dict:
        """Gather system information"""
        try:
            import distro
            dist_info = f"{distro.name()} {distro.version()}"
        except ImportError:
            dist_info = "Unknown Linux Distribution"

        try:
            hostname = os.uname().nodename
            kernel = os.uname().release
            arch = os.uname().machine
        except Exception:
            hostname = "Unknown"
            kernel = "Unknown"
            arch = "Unknown"

        return {
            'hostname': hostname,
            'kernel': kernel,
            'distribution': dist_info,
            'architecture': arch
        }

    def _run_command(self, command: str) -> tuple:
        """Execute a shell command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, '', 'Command timed out'
        except Exception as e:
            return -1, '', str(e)

    def _check_sysctl(self, param: str, expected: str) -> bool:
        """Check a sysctl parameter value"""
        code, output, _ = self._run_command(f"sysctl -n {param} 2>/dev/null")
        return output == expected

    def _check_module_disabled(self, module: str) -> bool:
        """Check if a kernel module is disabled"""
        code, output, _ = self._run_command(f"modprobe -n -v {module} 2>&1")
        if 'install /bin/true' in output or 'install /bin/false' in output:
            return True
        code2, output2, _ = self._run_command(f"lsmod | grep {module}")
        return code2 != 0 and output2 == ''

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed"""
        # Check Debian/Ubuntu
        code, _, _ = self._run_command(f"dpkg -s {package} 2>/dev/null | grep -q 'Status: install'")
        if code == 0:
            return True
        # Check RHEL/CentOS
        code, _, _ = self._run_command(f"rpm -q {package} 2>/dev/null")
        return code == 0

    def _check_ssh_config(self, param: str, expected: str) -> bool:
        """Check SSH configuration parameter"""
        code, output, _ = self._run_command(f"sshd -T 2>/dev/null | grep -i '^{param}'")
        if output:
            value = output.split()[-1].lower()
            return value == expected.lower()
        return False

    def _check_file_permissions(self, filepath: str, max_mode: int) -> bool:
        """Check that file permissions don't exceed max_mode"""
        try:
            file_stat = os.stat(filepath)
            actual_mode = stat.S_IMODE(file_stat.st_mode)
            return actual_mode <= max_mode
        except (FileNotFoundError, PermissionError):
            return False

    # ==================== FILESYSTEM CHECKS ====================

    def check_cramfs_disabled(self) -> Dict:
        """CIS 1.1.1.1 - Ensure mounting of cramfs is disabled"""
        passed = self._check_module_disabled('cramfs')
        return {
            'passed': passed,
            'actual': 'Module disabled' if passed else 'Module may be loadable',
            'expected': 'cramfs module should be disabled',
            'remediation': 'Add "install cramfs /bin/true" to /etc/modprobe.d/cramfs.conf'
        }

    def check_squashfs_disabled(self) -> Dict:
        """CIS 1.1.1.3 - Ensure mounting of squashfs is disabled"""
        passed = self._check_module_disabled('squashfs')
        return {
            'passed': passed,
            'actual': 'Module disabled' if passed else 'Module may be loadable',
            'expected': 'squashfs module should be disabled',
            'remediation': 'Add "install squashfs /bin/true" to /etc/modprobe.d/squashfs.conf'
        }

    def check_udf_disabled(self) -> Dict:
        """CIS 1.1.1.4 - Ensure mounting of udf is disabled"""
        passed = self._check_module_disabled('udf')
        return {
            'passed': passed,
            'actual': 'Module disabled' if passed else 'Module may be loadable',
            'expected': 'udf module should be disabled',
            'remediation': 'Add "install udf /bin/true" to /etc/modprobe.d/udf.conf'
        }

    def check_tmp_partition(self) -> Dict:
        """CIS 1.1.2 - Ensure /tmp is a separate partition"""
        code, output, _ = self._run_command("findmnt -n /tmp")
        passed = code == 0 and '/tmp' in output
        return {
            'passed': passed,
            'actual': output if output else '/tmp is not a separate partition',
            'expected': '/tmp should be a separate partition',
            'remediation': 'Configure /tmp as a separate partition or use tmpfs'
        }

    def check_tmp_noexec(self) -> Dict:
        """CIS 1.1.3 - Ensure noexec option set on /tmp"""
        code, output, _ = self._run_command("findmnt -n /tmp | grep noexec")
        passed = code == 0
        return {
            'passed': passed,
            'actual': 'noexec set' if passed else 'noexec not set',
            'expected': '/tmp should have noexec option',
            'remediation': 'Add noexec option to /tmp mount in /etc/fstab'
        }

    def check_tmp_nodev(self) -> Dict:
        """CIS 1.1.4 - Ensure nodev option set on /tmp"""
        code, output, _ = self._run_command("findmnt -n /tmp | grep nodev")
        passed = code == 0
        return {
            'passed': passed,
            'actual': 'nodev set' if passed else 'nodev not set',
            'expected': '/tmp should have nodev option',
            'remediation': 'Add nodev option to /tmp mount in /etc/fstab'
        }

    def check_tmp_nosuid(self) -> Dict:
        """CIS 1.1.5 - Ensure nosuid option set on /tmp"""
        code, output, _ = self._run_command("findmnt -n /tmp | grep nosuid")
        passed = code == 0
        return {
            'passed': passed,
            'actual': 'nosuid set' if passed else 'nosuid not set',
            'expected': '/tmp should have nosuid option',
            'remediation': 'Add nosuid option to /tmp mount in /etc/fstab'
        }

    # ==================== AUTHENTICATION CHECKS ====================

    def check_password_max_days(self) -> Dict:
        """CIS 5.5.1.1 - Ensure password expiration is 365 days or less"""
        code, output, _ = self._run_command("grep ^PASS_MAX_DAYS /etc/login.defs")
        try:
            days = int(output.split()[-1]) if output else 99999
            passed = days <= 365
        except (ValueError, IndexError):
            days = 'Unable to parse'
            passed = False
        return {
            'passed': passed,
            'actual': f'PASS_MAX_DAYS = {days}',
            'expected': 'PASS_MAX_DAYS <= 365',
            'remediation': 'Set PASS_MAX_DAYS to 365 or less in /etc/login.defs'
        }

    def check_password_min_days(self) -> Dict:
        """CIS 5.5.1.2 - Ensure minimum days between password changes"""
        code, output, _ = self._run_command("grep ^PASS_MIN_DAYS /etc/login.defs")
        try:
            days = int(output.split()[-1]) if output else 0
            passed = days >= 1
        except (ValueError, IndexError):
            days = 'Unable to parse'
            passed = False
        return {
            'passed': passed,
            'actual': f'PASS_MIN_DAYS = {days}',
            'expected': 'PASS_MIN_DAYS >= 1',
            'remediation': 'Set PASS_MIN_DAYS to 1 or more in /etc/login.defs'
        }

    def check_password_warn_age(self) -> Dict:
        """CIS 5.5.1.3 - Ensure password expiration warning is 7 days"""
        code, output, _ = self._run_command("grep ^PASS_WARN_AGE /etc/login.defs")
        try:
            days = int(output.split()[-1]) if output else 0
            passed = days >= 7
        except (ValueError, IndexError):
            days = 'Unable to parse'
            passed = False
        return {
            'passed': passed,
            'actual': f'PASS_WARN_AGE = {days}',
            'expected': 'PASS_WARN_AGE >= 7',
            'remediation': 'Set PASS_WARN_AGE to 7 or more in /etc/login.defs'
        }

    def check_inactive_lock(self) -> Dict:
        """CIS 5.5.1.4 - Ensure inactive password lock is 30 days or less"""
        code, output, _ = self._run_command("useradd -D | grep INACTIVE")
        try:
            days = int(output.split('=')[-1]) if output and '=' in output else -1
            passed = 0 < days <= 30
        except (ValueError, IndexError):
            days = 'Unable to parse'
            passed = False
        return {
            'passed': passed,
            'actual': f'INACTIVE = {days}',
            'expected': 'INACTIVE between 1 and 30',
            'remediation': 'Run: useradd -D -f 30'
        }

    def check_root_only_uid0(self) -> Dict:
        """CIS 5.4.3 - Ensure root is the only UID 0 account"""
        code, output, _ = self._run_command("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
        uid0_accounts = output.split('\n') if output else []
        uid0_accounts = [a for a in uid0_accounts if a]
        passed = uid0_accounts == ['root']
        return {
            'passed': passed,
            'actual': f'UID 0 accounts: {", ".join(uid0_accounts) if uid0_accounts else "none"}',
            'expected': 'Only root should have UID 0',
            'remediation': 'Remove or change UID of any non-root UID 0 accounts'
        }

    def check_root_console_only(self) -> Dict:
        """CIS 5.4.4 - Ensure root login is restricted to console"""
        securetty_exists = os.path.exists('/etc/securetty')
        return {
            'passed': securetty_exists,
            'actual': '/etc/securetty exists' if securetty_exists else '/etc/securetty not found',
            'expected': '/etc/securetty should exist and restrict root login',
            'remediation': 'Create /etc/securetty with allowed consoles'
        }

    def check_ssh_root_login(self) -> Dict:
        """CIS 5.2.10 - Ensure SSH root login is disabled"""
        passed = self._check_ssh_config('permitrootlogin', 'no')
        code, output, _ = self._run_command("sshd -T 2>/dev/null | grep -i permitrootlogin")
        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': 'PermitRootLogin no',
            'remediation': 'Set PermitRootLogin no in /etc/ssh/sshd_config'
        }

    def check_ssh_empty_passwords(self) -> Dict:
        """CIS 5.2.11 - Ensure SSH PermitEmptyPasswords is disabled"""
        passed = self._check_ssh_config('permitemptypasswords', 'no')
        code, output, _ = self._run_command("sshd -T 2>/dev/null | grep -i permitemptypasswords")
        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': 'PermitEmptyPasswords no',
            'remediation': 'Set PermitEmptyPasswords no in /etc/ssh/sshd_config'
        }

    def check_ssh_password_auth(self) -> Dict:
        """CIS 5.2.12 - Ensure SSH PasswordAuthentication is configured"""
        # Note: Some environments require password auth, so we just check it's explicitly configured
        code, output, _ = self._run_command("sshd -T 2>/dev/null | grep -i passwordauthentication")
        has_config = bool(output)
        return {
            'passed': has_config,
            'actual': output if output else 'PasswordAuthentication not explicitly configured',
            'expected': 'PasswordAuthentication should be explicitly configured',
            'remediation': 'Set PasswordAuthentication yes or no explicitly in /etc/ssh/sshd_config'
        }

    def check_ssh_max_auth_tries(self) -> Dict:
        """CIS 5.2.7 - Ensure SSH MaxAuthTries is set to 4 or less"""
        code, output, _ = self._run_command("sshd -T 2>/dev/null | grep -i maxauthtries")
        try:
            value = int(output.split()[-1]) if output else 6
            passed = value <= 4
        except (ValueError, IndexError):
            value = 'Unable to parse'
            passed = False
        return {
            'passed': passed,
            'actual': f'MaxAuthTries = {value}',
            'expected': 'MaxAuthTries <= 4',
            'remediation': 'Set MaxAuthTries 4 in /etc/ssh/sshd_config'
        }

    # ==================== NETWORK CHECKS ====================

    def check_ip_forwarding(self) -> Dict:
        """CIS 3.1.1 - Ensure IP forwarding is disabled"""
        ipv4 = self._check_sysctl('net.ipv4.ip_forward', '0')
        ipv6 = self._check_sysctl('net.ipv6.conf.all.forwarding', '0')
        passed = ipv4 and ipv6
        return {
            'passed': passed,
            'actual': f'IPv4 forwarding: {"disabled" if ipv4 else "enabled"}, IPv6: {"disabled" if ipv6 else "enabled"}',
            'expected': 'IP forwarding should be disabled',
            'remediation': 'Set net.ipv4.ip_forward=0 and net.ipv6.conf.all.forwarding=0 in /etc/sysctl.conf'
        }

    def check_send_redirects(self) -> Dict:
        """CIS 3.1.2 - Ensure packet redirect sending is disabled"""
        all_redirect = self._check_sysctl('net.ipv4.conf.all.send_redirects', '0')
        default_redirect = self._check_sysctl('net.ipv4.conf.default.send_redirects', '0')
        passed = all_redirect and default_redirect
        return {
            'passed': passed,
            'actual': f'all: {"0" if all_redirect else "1"}, default: {"0" if default_redirect else "1"}',
            'expected': 'send_redirects = 0 for all and default',
            'remediation': 'Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.conf'
        }

    def check_source_route(self) -> Dict:
        """CIS 3.2.1 - Ensure source routed packets are not accepted"""
        all_sr = self._check_sysctl('net.ipv4.conf.all.accept_source_route', '0')
        default_sr = self._check_sysctl('net.ipv4.conf.default.accept_source_route', '0')
        passed = all_sr and default_sr
        return {
            'passed': passed,
            'actual': f'all: {"0" if all_sr else "1"}, default: {"0" if default_sr else "1"}',
            'expected': 'accept_source_route = 0',
            'remediation': 'Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.conf'
        }

    def check_icmp_redirects(self) -> Dict:
        """CIS 3.2.2 - Ensure ICMP redirects are not accepted"""
        all_redir = self._check_sysctl('net.ipv4.conf.all.accept_redirects', '0')
        default_redir = self._check_sysctl('net.ipv4.conf.default.accept_redirects', '0')
        passed = all_redir and default_redir
        return {
            'passed': passed,
            'actual': f'all: {"0" if all_redir else "1"}, default: {"0" if default_redir else "1"}',
            'expected': 'accept_redirects = 0',
            'remediation': 'Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.conf'
        }

    def check_icmp_broadcast(self) -> Dict:
        """CIS 3.2.5 - Ensure broadcast ICMP requests are ignored"""
        passed = self._check_sysctl('net.ipv4.icmp_echo_ignore_broadcasts', '1')
        return {
            'passed': passed,
            'actual': 'Broadcast ICMP ignored' if passed else 'Broadcast ICMP accepted',
            'expected': 'icmp_echo_ignore_broadcasts = 1',
            'remediation': 'Set net.ipv4.icmp_echo_ignore_broadcasts=1 in /etc/sysctl.conf'
        }

    def check_syn_cookies(self) -> Dict:
        """CIS 3.2.8 - Ensure TCP SYN Cookies are enabled"""
        passed = self._check_sysctl('net.ipv4.tcp_syncookies', '1')
        return {
            'passed': passed,
            'actual': 'SYN cookies enabled' if passed else 'SYN cookies disabled',
            'expected': 'tcp_syncookies = 1',
            'remediation': 'Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.conf'
        }

    def check_firewall_active(self) -> Dict:
        """CIS 3.4.1.1 - Ensure firewall is active"""
        # Check for ufw, firewalld, or iptables
        code_ufw, _, _ = self._run_command("ufw status | grep -q 'Status: active'")
        code_firewalld, _, _ = self._run_command("systemctl is-active firewalld 2>/dev/null")
        code_iptables, output_iptables, _ = self._run_command("iptables -L -n 2>/dev/null | grep -c '^'")

        ufw_active = code_ufw == 0
        firewalld_active = code_firewalld == 0
        iptables_rules = int(output_iptables) > 8 if output_iptables.isdigit() else False

        passed = ufw_active or firewalld_active or iptables_rules
        return {
            'passed': passed,
            'actual': f'ufw: {ufw_active}, firewalld: {firewalld_active}, iptables rules: {iptables_rules}',
            'expected': 'At least one firewall should be active',
            'remediation': 'Enable ufw: sudo ufw enable'
        }

    # ==================== LOGGING CHECKS ====================

    def check_rsyslog_installed(self) -> Dict:
        """CIS 4.2.1.1 - Ensure rsyslog is installed"""
        passed = self._check_package_installed('rsyslog')
        return {
            'passed': passed,
            'actual': 'rsyslog installed' if passed else 'rsyslog not installed',
            'expected': 'rsyslog should be installed',
            'remediation': 'Install rsyslog: apt install rsyslog'
        }

    def check_rsyslog_enabled(self) -> Dict:
        """CIS 4.2.1.2 - Ensure rsyslog service is enabled"""
        code, output, _ = self._run_command("systemctl is-enabled rsyslog 2>/dev/null")
        passed = output == 'enabled'
        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': 'rsyslog should be enabled',
            'remediation': 'Enable rsyslog: systemctl enable rsyslog'
        }

    def check_journald_compress(self) -> Dict:
        """CIS 4.2.2.1 - Ensure journald is configured to compress logs"""
        code, output, _ = self._run_command("grep -E '^Compress=' /etc/systemd/journald.conf 2>/dev/null")
        passed = 'Compress=yes' in output if output else False
        return {
            'passed': passed,
            'actual': output if output else 'Compress not configured',
            'expected': 'Compress=yes in journald.conf',
            'remediation': 'Set Compress=yes in /etc/systemd/journald.conf'
        }

    def check_journald_persistent(self) -> Dict:
        """CIS 4.2.2.2 - Ensure journald is configured to write to persistent storage"""
        code, output, _ = self._run_command("grep -E '^Storage=' /etc/systemd/journald.conf 2>/dev/null")
        passed = 'Storage=persistent' in output if output else False
        return {
            'passed': passed,
            'actual': output if output else 'Storage not configured',
            'expected': 'Storage=persistent in journald.conf',
            'remediation': 'Set Storage=persistent in /etc/systemd/journald.conf'
        }

    def check_var_log_permissions(self) -> Dict:
        """CIS 4.2.3 - Ensure permissions on /var/log are configured"""
        passed = self._check_file_permissions('/var/log', 0o755)
        code, output, _ = self._run_command("stat -c '%a' /var/log 2>/dev/null")
        return {
            'passed': passed,
            'actual': f'Permissions: {output}' if output else 'Unable to determine',
            'expected': 'Permissions should be 755 or more restrictive',
            'remediation': 'Set correct permissions: chmod 755 /var/log'
        }

    # ==================== ACCESS CONTROL CHECKS ====================

    def check_passwd_permissions(self) -> Dict:
        """CIS 6.1.2 - Ensure permissions on /etc/passwd are configured"""
        passed = self._check_file_permissions('/etc/passwd', 0o644)
        code, output, _ = self._run_command("stat -c '%a %U %G' /etc/passwd 2>/dev/null")
        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': '644 root root',
            'remediation': 'Run: chmod 644 /etc/passwd && chown root:root /etc/passwd'
        }

    def check_shadow_permissions(self) -> Dict:
        """CIS 6.1.3 - Ensure permissions on /etc/shadow are configured"""
        passed = self._check_file_permissions('/etc/shadow', 0o640)
        code, output, _ = self._run_command("stat -c '%a %U %G' /etc/shadow 2>/dev/null")
        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': '640 root shadow (or more restrictive)',
            'remediation': 'Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow'
        }

    def check_group_permissions(self) -> Dict:
        """CIS 6.1.4 - Ensure permissions on /etc/group are configured"""
        passed = self._check_file_permissions('/etc/group', 0o644)
        code, output, _ = self._run_command("stat -c '%a %U %G' /etc/group 2>/dev/null")
        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': '644 root root',
            'remediation': 'Run: chmod 644 /etc/group && chown root:root /etc/group'
        }

    def check_world_writable(self) -> Dict:
        """CIS 6.1.10 - Ensure no world-writable files exist"""
        code, output, _ = self._run_command(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | head -10"
        )
        files = output.split('\n') if output else []
        files = [f for f in files if f]
        passed = len(files) == 0
        return {
            'passed': passed,
            'actual': f'{len(files)} world-writable files found' + (f': {", ".join(files[:5])}' if files else ''),
            'expected': 'No world-writable files',
            'remediation': 'Remove world-writable permission: chmod o-w <file>'
        }

    def check_unowned_files(self) -> Dict:
        """CIS 6.1.11 - Ensure no unowned files exist"""
        code, output, _ = self._run_command(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null | head -10"
        )
        files = output.split('\n') if output else []
        files = [f for f in files if f]
        passed = len(files) == 0
        return {
            'passed': passed,
            'actual': f'{len(files)} unowned files found' + (f': {", ".join(files[:5])}' if files else ''),
            'expected': 'No unowned files',
            'remediation': 'Assign ownership to files: chown <owner>:<group> <file>'
        }

    def check_suid_sgid_files(self) -> Dict:
        """CIS 6.1.13 - Audit SUID/SGID executables"""
        code, output, _ = self._run_command(
            "df --local -P 2>/dev/null | awk 'NR!=1 {print $6}' | "
            "xargs -I '{}' find '{}' -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | wc -l"
        )
        count = int(output) if output and output.isdigit() else 0
        # This is informational - some SUID files are expected
        return {
            'passed': True,  # Informational check
            'actual': f'{count} SUID/SGID files found (review recommended)',
            'expected': 'SUID/SGID files should be reviewed periodically',
            'remediation': 'Review SUID/SGID files and remove unnecessary permissions'
        }

    # ==================== SERVICES CHECKS ====================

    def check_xinetd_not_installed(self) -> Dict:
        """CIS 2.1.1 - Ensure xinetd is not installed"""
        installed = self._check_package_installed('xinetd')
        return {
            'passed': not installed,
            'actual': 'xinetd installed' if installed else 'xinetd not installed',
            'expected': 'xinetd should not be installed',
            'remediation': 'Remove xinetd: apt remove xinetd'
        }

    def check_telnet_not_installed(self) -> Dict:
        """CIS 2.2.18 - Ensure telnet server is not installed"""
        installed = self._check_package_installed('telnetd') or self._check_package_installed('telnet-server')
        return {
            'passed': not installed,
            'actual': 'telnet server installed' if installed else 'telnet server not installed',
            'expected': 'telnet server should not be installed',
            'remediation': 'Remove telnet server: apt remove telnetd'
        }

    def check_ftp_not_installed(self) -> Dict:
        """CIS 2.2.9 - Ensure FTP server is not installed"""
        installed = self._check_package_installed('vsftpd') or self._check_package_installed('proftpd')
        return {
            'passed': not installed,
            'actual': 'FTP server installed' if installed else 'FTP server not installed',
            'expected': 'FTP server should not be installed (use SFTP)',
            'remediation': 'Remove FTP server: apt remove vsftpd'
        }

    def check_http_not_installed(self) -> Dict:
        """CIS 2.2.10 - Ensure HTTP server is not installed"""
        installed = self._check_package_installed('apache2') or self._check_package_installed('nginx')
        return {
            'passed': not installed,
            'actual': 'HTTP server installed' if installed else 'HTTP server not installed',
            'expected': 'HTTP server should not be installed unless required',
            'remediation': 'Remove if not needed: apt remove apache2 nginx'
        }

    def check_ldap_not_installed(self) -> Dict:
        """CIS 2.2.5 - Ensure LDAP server is not installed"""
        installed = self._check_package_installed('slapd')
        return {
            'passed': not installed,
            'actual': 'LDAP server installed' if installed else 'LDAP server not installed',
            'expected': 'LDAP server should not be installed unless required',
            'remediation': 'Remove if not needed: apt remove slapd'
        }

    def check_nfs_not_installed(self) -> Dict:
        """CIS 2.2.7 - Ensure NFS is not installed"""
        installed = self._check_package_installed('nfs-kernel-server')
        return {
            'passed': not installed,
            'actual': 'NFS server installed' if installed else 'NFS server not installed',
            'expected': 'NFS server should not be installed unless required',
            'remediation': 'Remove if not needed: apt remove nfs-kernel-server'
        }

    # ==================== RUNNER ====================

    def run_all_checks(self, categories: Optional[List[str]] = None, min_severity: str = 'all') -> Dict:
        """Run all compliance checks and return results"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        min_sev_level = severity_order.get(min_severity, 999)

        self.results['scan_time'] = datetime.now().isoformat()
        self.results['checks'] = []

        categories_to_scan = categories if categories else self.checks.keys()

        for category in categories_to_scan:
            if category not in self.checks:
                continue

            for check_id, check_name, severity, check_func in self.checks[category]:
                # Filter by severity
                if min_severity != 'all' and severity_order.get(severity, 999) > min_sev_level:
                    continue

                try:
                    result = check_func()
                    self.results['checks'].append({
                        'id': check_id,
                        'category': category,
                        'name': check_name,
                        'severity': severity,
                        'status': 'PASS' if result['passed'] else 'FAIL',
                        'actual': result.get('actual', ''),
                        'expected': result.get('expected', ''),
                        'remediation': result.get('remediation', '')
                    })
                except Exception as e:
                    self.results['checks'].append({
                        'id': check_id,
                        'category': category,
                        'name': check_name,
                        'severity': severity,
                        'status': 'ERROR',
                        'actual': f'Error running check: {str(e)}',
                        'expected': '',
                        'remediation': ''
                    })

        return self.results
