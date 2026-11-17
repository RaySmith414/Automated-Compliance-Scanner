#!/usr/bin/env python3
"""Compare a scan result with the verdicts expected for a container state."""

import json
import sys
from pathlib import Path

VALID = {"PASS", "FAIL", "ERROR", "NOT_APPLICABLE", "MANUAL"}


def main(state: str, result_path: str) -> int:
    expected = json.loads((Path(__file__).parent / "expected.json").read_text(encoding="utf-8"))[state]
    result = json.loads(Path(result_path).read_text(encoding="utf-8"))
    found = {check["id"]: check for check in result["checks"]}
    print(f"{result['system_info']['distribution']}, state: {state}, privileged: {result['privileged']}")
    problems = []
    for check_id, check in found.items():
        if check["status"] not in VALID:
            problems.append(f"{check_id}: unknown status {check['status']}")
    for check_id, wanted in expected.items():
        got = found[check_id]["status"] if check_id in found else "MISSING"
        marker = "ok " if got == wanted else "BAD"
        print(f"  {marker} {check_id:13} expected {wanted:15} got {got:15} {found.get(check_id, {}).get('actual', '')[:90]}")
        if got != wanted:
            problems.append(f"{check_id}: expected {wanted}, got {got}")
    for check_id, check in found.items():
        if check_id not in expected:
            print(f"  --  {check_id:13} (not asserted)          got {check['status']:15} {check['actual'][:90]}")
    if not result["privileged"]:
        problems.append("the scan did not run as root")
    if problems:
        print("\nMISMATCH:\n  " + "\n  ".join(problems))
        return 1
    print(f"\nall {len(expected)} asserted verdicts match")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
