# Controls Reference Guide

This document provides detailed explanations of each compliance check performed by the Automated Compliance Scanner.

## Filesystem Controls

### FS-001: Ensure mounting of cramfs is disabled
**CIS Reference**: 1.1.1.1
**Severity**: High
**NIST Controls**: CM-7, SC-28

The cramfs filesystem is a compressed read-only Linux filesystem embedded in small footprint systems. Disabling cramfs reduces the attack surface by preventing potentially malicious cramfs images from being mounted.

**Check Method**: Verifies that the cramfs kernel module is blacklisted or not loadable.

**Remediation**:
```bash
echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
```

### FS-002: Ensure mounting of squashfs is disabled
**CIS Reference**: 1.1.1.3
**Severity**: Medium
**NIST Controls**: CM-7, SC-28

The squashfs filesystem is used for snap packages on Ubuntu. If snap is not used, this should be disabled.

**Remediation**:
```bash
echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
```

### FS-003: Ensure mounting of udf is disabled
**CIS Reference**: 1.1.1.4
**Severity**: Low
**NIST Controls**: CM-7, SC-28

The udf filesystem is used for DVDs and other optical media. Unless needed, it should be disabled.

### FS-004: Ensure /tmp is a separate partition
**CIS Reference**: 1.1.2
**Severity**: High
**NIST Controls**: SC-4, SC-28

Having /tmp as a separate partition allows for mount options that enhance security and prevents /tmp from filling up the root filesystem.

### FS-005: Ensure noexec option set on /tmp
**CIS Reference**: 1.1.3
**Severity**: High
**NIST Controls**: AC-6, CM-7

The noexec option prevents execution of binaries from /tmp, mitigating many common attack vectors.

### FS-006: Ensure nodev option set on /tmp
**CIS Reference**: 1.1.4
**Severity**: Medium
**NIST Controls**: AC-6, CM-7

The nodev option prevents creation of device files in /tmp.

### FS-007: Ensure nosuid option set on /tmp
**CIS Reference**: 1.1.5
**Severity**: Medium
**NIST Controls**: AC-6, CM-7

The nosuid option prevents setuid programs from being executed from /tmp.

---

## Authentication Controls

### AUTH-001: Ensure password expiration is 365 days or less
**CIS Reference**: 5.5.1.1
**Severity**: High
**NIST Controls**: IA-5

Regular password changes reduce the window of opportunity for attackers using compromised credentials.

**Check Method**: Examines PASS_MAX_DAYS in /etc/login.defs

**Remediation**:
```bash
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
```

### AUTH-002: Ensure minimum days between password changes
**CIS Reference**: 5.5.1.2
**Severity**: Medium
**NIST Controls**: IA-5

Prevents users from immediately changing back to old passwords.

### AUTH-003: Ensure password expiration warning is 7 days
**CIS Reference**: 5.5.1.3
**Severity**: Low
**NIST Controls**: IA-5

Gives users adequate notice to change their password.

### AUTH-004: Ensure inactive password lock is 30 days or less
**CIS Reference**: 5.5.1.4
**Severity**: Medium
**NIST Controls**: IA-5, AC-2

Automatically disables accounts that haven't been used.

### AUTH-005: Ensure root is the only UID 0 account
**CIS Reference**: 5.4.3
**Severity**: Critical
**NIST Controls**: AC-6, IA-2

Only the root account should have UID 0. Additional UID 0 accounts are a security risk.

**Check Method**: Scans /etc/passwd for accounts with UID 0

### AUTH-006: Ensure root login is restricted to console
**CIS Reference**: 5.4.4
**Severity**: High
**NIST Controls**: AC-6, AC-17

Limits where root can log in directly.

### AUTH-007: Ensure SSH root login is disabled
**CIS Reference**: 5.2.10
**Severity**: Critical
**NIST Controls**: AC-6, AC-17, IA-2

Disabling direct root login via SSH ensures accountability as users must log in with personal accounts first.

**Check Method**: Examines sshd configuration for PermitRootLogin

**Remediation**:
```bash
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### AUTH-008: Ensure SSH PermitEmptyPasswords is disabled
**CIS Reference**: 5.2.11
**Severity**: Critical
**NIST Controls**: IA-5, IA-2

Empty passwords are a critical security vulnerability.

### AUTH-009: Ensure SSH PasswordAuthentication is configured
**CIS Reference**: 5.2.12
**Severity**: Medium
**NIST Controls**: IA-2, IA-5

Password authentication should be explicitly configured (preferably disabled in favor of key-based auth).

### AUTH-010: Ensure SSH MaxAuthTries is 4 or less
**CIS Reference**: 5.2.7
**Severity**: Medium
**NIST Controls**: AC-7

Limits brute force authentication attempts.

---

## Network Controls

### NET-001: Ensure IP forwarding is disabled
**CIS Reference**: 3.1.1
**Severity**: High
**NIST Controls**: CM-7, SC-7

Unless the system is a router, IP forwarding should be disabled.

**Check Method**: Examines sysctl net.ipv4.ip_forward and net.ipv6.conf.all.forwarding

### NET-002: Ensure packet redirect sending is disabled
**CIS Reference**: 3.1.2
**Severity**: Medium
**NIST Controls**: CM-7, SC-7

ICMP redirects can be used in man-in-the-middle attacks.

### NET-003: Ensure source routed packets are not accepted
**CIS Reference**: 3.2.1
**Severity**: Medium
**NIST Controls**: SC-7, SC-5

Source routing can bypass network security measures.

### NET-004: Ensure ICMP redirects are not accepted
**CIS Reference**: 3.2.2
**Severity**: Medium
**NIST Controls**: SC-7, SC-5

Accepting ICMP redirects can allow routing table manipulation.

### NET-005: Ensure broadcast ICMP requests are ignored
**CIS Reference**: 3.2.5
**Severity**: Medium
**NIST Controls**: SC-7, SC-5

Prevents the system from being used in smurf amplification attacks.

### NET-006: Ensure TCP SYN Cookies are enabled
**CIS Reference**: 3.2.8
**Severity**: High
**NIST Controls**: SC-5, SC-7

SYN cookies help protect against SYN flood denial-of-service attacks.

### NET-007: Ensure firewall is active
**CIS Reference**: 3.4.1.1
**Severity**: Critical
**NIST Controls**: SC-7, AC-4

A firewall is essential for protecting the system from unauthorized network access.

**Check Method**: Checks for active ufw, firewalld, or iptables rules

---

## Logging Controls

### LOG-001: Ensure rsyslog is installed
**CIS Reference**: 4.2.1.1
**Severity**: High
**NIST Controls**: AU-2, AU-3

rsyslog provides system logging capabilities essential for security monitoring.

### LOG-002: Ensure rsyslog service is enabled
**CIS Reference**: 4.2.1.2
**Severity**: High
**NIST Controls**: AU-2, AU-3, AU-12

The logging service must be running to capture events.

### LOG-003: Ensure journald is configured to compress logs
**CIS Reference**: 4.2.2.1
**Severity**: Low
**NIST Controls**: AU-4, AU-9

Compression allows more logs to be stored.

### LOG-004: Ensure journald is configured to write to persistent storage
**CIS Reference**: 4.2.2.2
**Severity**: Medium
**NIST Controls**: AU-4, AU-9, AU-11

Persistent storage ensures logs survive reboots.

### LOG-005: Ensure permissions on /var/log are configured
**CIS Reference**: 4.2.3
**Severity**: Medium
**NIST Controls**: AU-9, AC-6

Proper permissions protect log integrity.

---

## Access Control Checks

### AC-001 through AC-003: File Permission Checks
Verifies permissions on critical system files (/etc/passwd, /etc/shadow, /etc/group).

### AC-004: Ensure no world-writable files exist
Files writable by all users are security risks.

### AC-005: Ensure no unowned files exist
Unowned files may indicate deleted users or system compromise.

### AC-006: Ensure SUID/SGID files are reviewed
Elevated privilege files should be minimized and reviewed.

---

## Services Controls

### SVC-001: Ensure xinetd is not installed
Legacy internet services daemon with security concerns.

### SVC-002: Ensure telnet server is not installed
**Severity**: Critical

Telnet transmits data including passwords in cleartext.

### SVC-003: Ensure FTP server is not installed
FTP transmits data in cleartext; use SFTP or SCP instead.

### SVC-004: Ensure HTTP server is not installed
Unless needed, web servers increase attack surface.

### SVC-005: Ensure LDAP server is not installed
Unless needed, LDAP servers increase attack surface.

### SVC-006: Ensure NFS is not installed
Unless needed, NFS increases attack surface.

---

*Author: Rayshaun Smith*
