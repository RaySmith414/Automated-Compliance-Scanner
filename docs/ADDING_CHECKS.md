# Guide to Adding New Compliance Checks

This guide explains how to add new compliance checks to the Automated Compliance Scanner.

## Overview

Adding a new check involves:
1. Implementing the check function
2. Adding the check to the checks dictionary
3. Mapping to NIST controls
4. Writing tests
5. Updating documentation

## Step 1: Implement the Check Function

Each check function should:
- Return a dictionary with `passed`, `actual`, `expected`, and `remediation` keys
- Handle errors gracefully
- Be deterministic and idempotent

### Check Function Template

```python
def check_example_control(self) -> Dict:
    """
    CIS X.X.X - Brief description of the check

    Detailed explanation of what this check verifies and why it matters.
    """
    # Perform the check
    try:
        # Your check logic here
        code, output, _ = self._run_command("your command here")

        # Determine if check passed
        passed = (code == 0 and "expected_value" in output)

        return {
            'passed': passed,
            'actual': output if output else 'Unable to determine',
            'expected': 'Description of expected state',
            'remediation': 'Command or steps to fix the issue'
        }
    except Exception as e:
        return {
            'passed': False,
            'actual': f'Error: {str(e)}',
            'expected': 'Description of expected state',
            'remediation': 'Command or steps to fix the issue'
        }
```

### Example: Adding a New Linux Check

```python
def check_cron_restricted(self) -> Dict:
    """
    CIS 5.1.8 - Ensure cron is restricted to authorized users

    Verifies that /etc/cron.allow exists and /etc/cron.deny does not,
    ensuring only explicitly authorized users can schedule cron jobs.
    """
    cron_allow_exists = os.path.exists('/etc/cron.allow')
    cron_deny_exists = os.path.exists('/etc/cron.deny')

    passed = cron_allow_exists and not cron_deny_exists

    return {
        'passed': passed,
        'actual': f'cron.allow exists: {cron_allow_exists}, cron.deny exists: {cron_deny_exists}',
        'expected': '/etc/cron.allow should exist, /etc/cron.deny should not exist',
        'remediation': 'rm /etc/cron.deny && touch /etc/cron.allow && chmod 600 /etc/cron.allow'
    }
```

## Step 2: Register the Check

Add your check to the `self.checks` dictionary in the `__init__` method:

```python
self.checks = {
    # ... existing categories ...
    'scheduling': [
        ('CRON-001', 'Ensure cron is restricted to authorized users', 'medium', self.check_cron_restricted),
        # Add more scheduling checks here
    ],
}
```

The tuple format is:
```python
(check_id, check_name, severity, check_function)
```

Where:
- `check_id`: Unique identifier (format: CATEGORY-NNN)
- `check_name`: Human-readable description
- `severity`: One of 'critical', 'high', 'medium', 'low'
- `check_function`: Reference to the check method

## Step 3: Add NIST Mapping

In `scanner/nist_mapper.py`, add the mapping for your new check:

```python
self.mappings = {
    # ... existing mappings ...
    'CRON-001': ['CM-7', 'AC-3'],  # Least Functionality, Access Enforcement
}
```

Choose appropriate NIST controls based on what the check verifies:

| If the check relates to... | Consider these controls |
|---------------------------|------------------------|
| User authentication | IA-2, IA-5 |
| Access permissions | AC-3, AC-6 |
| Logging/auditing | AU-2, AU-3, AU-9 |
| Network configuration | SC-7, SC-5 |
| Service configuration | CM-7 |
| Data protection | SC-28, SC-8 |

## Step 4: Write Tests

Add tests in `tests/test_linux_checks.py` (or appropriate test file):

```python
class TestCronChecks:
    """Tests for cron-related compliance checks"""

    def test_check_cron_restricted_pass(self, mocker):
        """Test cron restriction check when properly configured"""
        mocker.patch('os.path.exists', side_effect=lambda p: p == '/etc/cron.allow')

        checker = LinuxComplianceChecker()
        result = checker.check_cron_restricted()

        assert result['passed'] == True
        assert 'cron.allow exists: True' in result['actual']

    def test_check_cron_restricted_fail(self, mocker):
        """Test cron restriction check when misconfigured"""
        mocker.patch('os.path.exists', return_value=False)

        checker = LinuxComplianceChecker()
        result = checker.check_cron_restricted()

        assert result['passed'] == False
        assert 'remediation' in result
```

## Step 5: Update Documentation

### Update CONTROLS_REFERENCE.md

Add an entry for your new check:

```markdown
### CRON-001: Ensure cron is restricted to authorized users
**CIS Reference**: 5.1.8
**Severity**: Medium
**NIST Controls**: CM-7, AC-3

Description of what this check does and why it's important.

**Check Method**: Describe how the check works.

**Remediation**:
```bash
rm /etc/cron.deny
touch /etc/cron.allow
chmod 600 /etc/cron.allow
```
```

### Update NIST_MAPPING.md

Add your check to the mapping table.

## Best Practices

### Check Implementation

1. **Be specific**: Checks should verify one specific security setting
2. **Handle errors**: Never let exceptions crash the scanner
3. **Provide context**: The `actual` field should show what was found
4. **Clear remediation**: The `remediation` field should be actionable

### Severity Guidelines

| Severity | Criteria |
|----------|----------|
| Critical | Direct path to system compromise, credential exposure |
| High | Significant security weakness, important control missing |
| Medium | Moderate risk, defense-in-depth measure |
| Low | Minor hardening, best practice |

### NIST Mapping Guidelines

1. Map to the most specific applicable control
2. Multiple mappings are acceptable when appropriate
3. Verify mappings against NIST 800-53 descriptions
4. Consider all applicable control families

## Testing Your Changes

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=scanner --cov-report=html

# Run specific test file
pytest tests/test_linux_checks.py -v

# Test your new check directly
python -c "from scanner.linux_checks import LinuxComplianceChecker; c = LinuxComplianceChecker(); print(c.check_cron_restricted())"
```

## Submitting Changes

1. Create a feature branch
2. Implement your changes following this guide
3. Ensure all tests pass
4. Update documentation
5. Submit a pull request with:
   - Description of the new check(s)
   - CIS Benchmark reference
   - NIST control mapping rationale

---

*Author: Rayshaun Smith*
