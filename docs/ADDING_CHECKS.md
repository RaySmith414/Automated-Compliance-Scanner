# Adding a check

A check has two parts that live in different places:

| Part | Where | What it holds |
| --- | --- | --- |
| Catalog entry | `scanner/data/checks_linux.yaml` or `checks_windows.yaml` | ID, title, category, severity, expected state, remediation text and framework mappings |
| Test logic | `scanner/linux_checks.py` or `scanner/windows_checks.py` | One method that reads the host and returns a verdict |

The catalog is the single source for everything a report prints about a check. The method only decides the outcome. `tests/test_catalog.py` fails when a catalog entry has no method or a method has no catalog entry.

The steps below add a real example: a Linux check for the permissions on `/etc/crontab`.

## 1. Add the catalog entry

Append an entry to `scanner/data/checks_linux.yaml`. Use the next free number in the category.

```yaml
  - id: LNX-ACC-007
    function: crontab_permissions
    title: Ensure permissions on /etc/crontab are configured
    category: access_control
    severity: medium
    requires_root: false
    expected: /etc/crontab is owned by root:root with mode 0600 or stricter
    remediation: Run "chown root:root /etc/crontab" and "chmod 600 /etc/crontab".
    cis_id: null
    nist_800_53: [AC-3, AC-6]
    soc2: [CC6.1, CC6.3]
    iso_27001: [A.8.3]
```

Field rules, all enforced when the catalog loads:

- `id` starts with `LNX-` or `WIN-` and is unique.
- `function` is the name of the method you add in step 2.
- `category` is one of `filesystem`, `authentication`, `network`, `logging`, `access_control`, `services`.
- `severity` is one of `critical`, `high`, `medium`, `low`. The POA&M export gives critical and high findings 30 days, medium 90 and low 180.
- `requires_root: true` makes the runner report ERROR instead of calling the method when the scan is not privileged. Set it when the answer cannot be read without root or administrator rights.
- `cis_id` stays `null` unless you have the number from the benchmark version you follow. Write it as a quoted string such as `"5.1.2"`. The same number cannot be used twice.
- Add `cis: false` when the check is not a CIS recommendation.
- Every control ID must exist in `scanner/data/frameworks.yaml`. A check needs at least one NIST SP 800-53 control. To map to a control that is not listed yet, add it to `frameworks.yaml` with its official title first.

## 2. Write the method

Add a method with the same name to `LinuxChecks` in `scanner/linux_checks.py`.

```python
    def crontab_permissions(self) -> Outcome:
        if self.probe.stat("/etc/crontab") is None:
            raise NotApplicable("/etc/crontab does not exist, so cron is not installed")
        return self._file_permissions("/etc/crontab", 0o600, [])
```

A method ends in one of five ways:

| Outcome | How | Use it when |
| --- | --- | --- |
| PASS | `return passed("what was found")` | The host meets the expected state |
| FAIL | `return failed("what was found")` | The host does not meet it |
| MANUAL | `return manual("evidence to review")` | The scanner can collect evidence but a person has to decide |
| NOT_APPLICABLE | `raise NotApplicable("why")` | The control does not apply to this host |
| ERROR | `raise Unassessable("why")` | The state could not be read |

Rules that keep results honest:

1. **No answer is never a pass.** A missing tool, a timeout, a denied read or output you cannot parse is `Unassessable`. Do not fall back to a default value.
2. **Go through the probe.** Read files with `self.probe.read_text`, file modes with `self.probe.stat` and commands with `self.probe.run([...])`. Commands are argument lists. Nothing runs through a shell.
3. **Never change the host.** Checks only read.
4. **Compare permission bits with `mode_within`.** Comparing modes as numbers gets it wrong: 0604 is smaller than 0640 and still world readable.
5. **Say what you found.** The text you pass to `passed`, `failed` or `manual` is the "Found" line in every report, so include the value you read.

Windows checks follow the same rules. Each query is a PowerShell script that prints JSON, read with `self._ps_json(...)`, so the decision in Python can be tested on any platform.

## 3. Add tests

Tests run against a fake host, so they need no root and behave the same everywhere.

1. Give the clean host a passing answer. In `tests/linux_host.py`, add the file to `stats` inside `hardened_probe`:

   ```python
        "/etc/crontab": stat(0o600),
   ```

2. Add cases to `CASES` in `tests/test_linux_checks.py`. Each case changes one fact on the clean host and names the status and a fragment of the "Found" text it expects. `tests/test_linux_checks.py` fails if a check has no case that ends in something other than PASS.

   ```python
    ("crontab_permissions", lambda: hardened_probe(stats={"/etc/crontab": stat(0o644)}), "FAIL", "0644"),
    ("crontab_permissions", lambda: hardened_probe(stats={"/etc/crontab": stat(0o600, "bob", "root")}), "FAIL", "bob"),
    ("crontab_permissions", lambda: hardened_probe(stats={"/etc/crontab": None}), "NOT_APPLICABLE", "cron is not installed"),
   ```

3. Update the count in `test_expected_check_counts` in `tests/test_catalog.py`.

4. If the answer is stable on a stock Ubuntu image, add the expected verdict for both states to `tests/containers/expected.json`. CI then proves the check against real Ubuntu 22.04 and 24.04 containers. When the hardened state needs a new setting, apply it in `tests/containers/run_state.sh`.

## 4. Regenerate the reference docs

`docs/CHECKS.md` and `docs/MAPPINGS.md` are generated from the catalogs. Do not edit them by hand.

```bash
python -m scanner.docs
```

## 5. Run everything

```bash
python -m pip install -e ".[dev]"
ruff check .
python -m scanner.docs --check
python -m pytest
```

To try the new check on the machine you are on:

```bash
python -m scanner --categories access_control
```

## Choosing mappings

Map a check to the control it gives direct evidence for, not to every control it touches. A file permission check is evidence for AC-3 (Access Enforcement) and AC-6 (Least Privilege). It is not evidence for AC-2 (Account Management).

The mappings in this project are an informative crosswalk. They are not published by NIST, the AICPA, ISO or CIS. Keep new mappings to the same standard: a reviewer should be able to read the control text and see why the check belongs there.
