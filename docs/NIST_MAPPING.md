# NIST 800-53 Control Mapping Reference

This document explains how CIS Benchmark checks map to NIST 800-53 Rev 5 controls.

## Why Map to NIST 800-53?

NIST 800-53 is the gold standard for federal information security. By mapping CIS checks to NIST controls, this scanner:

1. **Supports RMF Compliance**: Directly assists with Risk Management Framework activities
2. **Enables FedRAMP Alignment**: Control mappings support FedRAMP authorization
3. **Provides Audit Evidence**: Generates documentation for A&A packages
4. **Demonstrates Control Implementation**: Shows how technical checks satisfy security requirements

## Control Mapping Methodology

### Mapping Process

1. Each CIS check is analyzed for its security objective
2. The corresponding NIST 800-53 control(s) are identified
3. Multiple controls may map to a single check (defense in depth)
4. Mappings are validated against NIST control descriptions

### Example Mapping

**Check**: AUTH-007 - Ensure SSH root login is disabled

**NIST Controls**:
- **AC-6 (Least Privilege)**: Disabling root SSH login enforces least privilege by requiring users to authenticate with individual accounts
- **AC-17 (Remote Access)**: This is a remote access control that restricts who can access the system remotely
- **IA-2 (Identification and Authentication)**: Ensures organizational users authenticate with unique identifiers, not shared root account

## Control Family Overview

### AC - Access Control

| Control | Name | Related Checks |
|---------|------|----------------|
| AC-2 | Account Management | AUTH-004, AUTH-005 |
| AC-3 | Access Enforcement | AC-001, AC-002, AC-003 |
| AC-4 | Information Flow Enforcement | NET-007, SVC-006 |
| AC-6 | Least Privilege | FS-005, FS-006, FS-007, AUTH-005, AUTH-006, AUTH-007, AC-006 |
| AC-7 | Unsuccessful Logon Attempts | AUTH-010 |
| AC-17 | Remote Access | AUTH-006, AUTH-007 |

### AU - Audit and Accountability

| Control | Name | Related Checks |
|---------|------|----------------|
| AU-2 | Audit Events | LOG-001, LOG-002 |
| AU-3 | Content of Audit Records | LOG-001, LOG-002 |
| AU-4 | Audit Storage Capacity | LOG-003, LOG-004 |
| AU-9 | Protection of Audit Information | LOG-003, LOG-004, LOG-005 |
| AU-11 | Audit Record Retention | LOG-004 |
| AU-12 | Audit Generation | LOG-002 |

### CM - Configuration Management

| Control | Name | Related Checks |
|---------|------|----------------|
| CM-7 | Least Functionality | FS-001, FS-002, FS-003, NET-001, NET-002, SVC-001 through SVC-006 |
| CM-8 | System Component Inventory | AC-005 |

### IA - Identification and Authentication

| Control | Name | Related Checks |
|---------|------|----------------|
| IA-2 | Identification and Authentication | AUTH-005, AUTH-007, AUTH-008, AUTH-009 |
| IA-5 | Authenticator Management | AUTH-001, AUTH-002, AUTH-003, AUTH-004, AUTH-008, AUTH-009 |

### SC - System and Communications Protection

| Control | Name | Related Checks |
|---------|------|----------------|
| SC-4 | Information in Shared Resources | FS-004 |
| SC-5 | Denial-of-Service Protection | NET-003, NET-004, NET-005, NET-006 |
| SC-7 | Boundary Protection | NET-001 through NET-007 |
| SC-8 | Transmission Confidentiality | SVC-002, SVC-003 |
| SC-28 | Protection of Information at Rest | FS-001, FS-002, FS-003 |

## Complete Mapping Table

| Check ID | CIS Control | NIST Controls | Rationale |
|----------|-------------|---------------|-----------|
| FS-001 | Disable cramfs | CM-7, SC-28 | Least functionality, data protection |
| FS-002 | Disable squashfs | CM-7, SC-28 | Least functionality, data protection |
| FS-003 | Disable udf | CM-7, SC-28 | Least functionality, data protection |
| FS-004 | /tmp partition | SC-4, SC-28 | Information separation |
| FS-005 | /tmp noexec | AC-6, CM-7 | Least privilege, least functionality |
| FS-006 | /tmp nodev | AC-6, CM-7 | Least privilege, least functionality |
| FS-007 | /tmp nosuid | AC-6, CM-7 | Least privilege, least functionality |
| AUTH-001 | Password max age | IA-5 | Authenticator management |
| AUTH-002 | Password min age | IA-5 | Authenticator management |
| AUTH-003 | Password warn age | IA-5 | Authenticator management |
| AUTH-004 | Inactive lock | IA-5, AC-2 | Authenticator, account management |
| AUTH-005 | Root UID 0 only | AC-6, IA-2 | Least privilege, identification |
| AUTH-006 | Root console only | AC-6, AC-17 | Least privilege, remote access |
| AUTH-007 | SSH root login | AC-6, AC-17, IA-2 | Least privilege, remote access, ID |
| AUTH-008 | SSH empty passwords | IA-5, IA-2 | Authenticator management |
| AUTH-009 | SSH password auth | IA-2, IA-5 | Identification, authentication |
| AUTH-010 | SSH max auth tries | AC-7 | Unsuccessful logon attempts |
| NET-001 | IP forwarding | CM-7, SC-7 | Least functionality, boundary |
| NET-002 | Send redirects | CM-7, SC-7 | Least functionality, boundary |
| NET-003 | Source route | SC-7, SC-5 | Boundary, DoS protection |
| NET-004 | ICMP redirects | SC-7, SC-5 | Boundary, DoS protection |
| NET-005 | ICMP broadcast | SC-7, SC-5 | Boundary, DoS protection |
| NET-006 | SYN cookies | SC-5, SC-7 | DoS protection, boundary |
| NET-007 | Firewall active | SC-7, AC-4 | Boundary, information flow |
| LOG-001 | rsyslog installed | AU-2, AU-3 | Audit events, content |
| LOG-002 | rsyslog enabled | AU-2, AU-3, AU-12 | Audit events, generation |
| LOG-003 | journald compress | AU-4, AU-9 | Storage, protection |
| LOG-004 | journald persistent | AU-4, AU-9, AU-11 | Storage, protection, retention |
| LOG-005 | /var/log permissions | AU-9, AC-6 | Audit protection, least privilege |
| AC-001 | /etc/passwd perms | AC-3, AC-6 | Access enforcement, least privilege |
| AC-002 | /etc/shadow perms | AC-3, AC-6, IA-5 | Access, privilege, authenticator |
| AC-003 | /etc/group perms | AC-3, AC-6 | Access enforcement, least privilege |
| AC-004 | World-writable files | AC-3, AC-6 | Access enforcement, least privilege |
| AC-005 | Unowned files | AC-3, CM-8 | Access enforcement, inventory |
| AC-006 | SUID/SGID review | AC-6, CM-7 | Least privilege, least functionality |
| SVC-001 | xinetd removed | CM-7, SA-4 | Least functionality, acquisition |
| SVC-002 | Telnet removed | CM-7, SC-8 | Least functionality, confidentiality |
| SVC-003 | FTP removed | CM-7, SC-8 | Least functionality, confidentiality |
| SVC-004 | HTTP removed | CM-7 | Least functionality |
| SVC-005 | LDAP removed | CM-7 | Least functionality |
| SVC-006 | NFS removed | CM-7, AC-4 | Least functionality, information flow |

## Using Mappings for Compliance

### System Security Plan (SSP)

Use scanner output to populate SSP control implementation statements:

> **AC-6: Least Privilege**
>
> Implementation: SSH root login is disabled as verified by automated compliance scanning (AUTH-007). Users must authenticate with individual accounts and use sudo for privileged operations. File system mounts are configured with noexec, nodev, and nosuid options where appropriate (FS-005, FS-006, FS-007).

### Plan of Action & Milestones (POA&M)

Failed checks automatically generate POA&M items with:
- Control ID and description
- Current finding status
- Recommended remediation
- Severity for prioritization

Example POA&M entry from scanner output:

| Field | Value |
|-------|-------|
| Weakness ID | NET-007-001 |
| Control | SC-7 Boundary Protection |
| Weakness Description | Firewall is not active on all interfaces |
| Scheduled Completion | [Date] |
| Milestone | Enable ufw/firewalld on all systems |
| Resource | System Administrator |
| Status | Open |

### Continuous Monitoring

Schedule regular scans and trend compliance over time:

```bash
# Weekly compliance scan
0 0 * * 0 /usr/local/bin/compliance-scanner --output json -f /var/log/compliance/scan_$(date +\%Y\%m\%d).json
```

## Baselines and Impact Levels

NIST 800-53 controls are assigned to baselines based on system impact level:

| Baseline | Confidentiality | Integrity | Availability |
|----------|-----------------|-----------|--------------|
| LOW | Low | Low | Low |
| MODERATE | Moderate | Moderate | Moderate |
| HIGH | High | High | High |

All checks in this scanner map to controls in the LOW baseline or higher, making the scanner suitable for systems at any impact level.

## References

- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53A Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final) - Assessment Procedures
- [NIST SP 800-53B](https://csrc.nist.gov/publications/detail/sp/800-53b/final) - Control Baselines
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

---

*Author: Rayshaun Smith*
