"""Load and validate the check catalogs and the framework reference data.

The YAML files in scanner/data are the single source of truth. Nothing about a
check (title, severity, mapping, remediation text) is defined in Python.
"""

from functools import cache
from importlib import resources
from typing import Any, Dict, List

import yaml

from scanner.model import CATEGORIES, FRAMEWORK_KEYS, SEVERITIES, CheckDef

PLATFORMS = ("linux", "windows")


class CatalogError(ValueError):
    """The catalog data is malformed. Raised at load time, never mid-scan."""


def _read_yaml(name: str) -> Dict[str, Any]:
    text = resources.files("scanner").joinpath("data", name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise CatalogError(f"{name}: expected a mapping at the top level")
    return data


@cache
def load_frameworks() -> Dict[str, Any]:
    data = _read_yaml("frameworks.yaml")
    for key in FRAMEWORK_KEYS:
        if key not in data or "controls" not in data[key]:
            raise CatalogError(f"frameworks.yaml: missing section {key}")
    return data


@cache
def load_benchmark(platform: str) -> Dict[str, Any]:
    return dict(_read_yaml(f"checks_{platform}.yaml").get("benchmark", {}))


@cache
def load_checks(platform: str) -> List[CheckDef]:
    if platform not in PLATFORMS:
        raise CatalogError(f"unknown platform: {platform}")
    name = f"checks_{platform}.yaml"
    data = _read_yaml(name)
    frameworks = load_frameworks()
    prefix = "LNX-" if platform == "linux" else "WIN-"
    seen_ids = set()
    seen_functions = set()
    seen_cis_ids: Dict[str, str] = {}
    checks: List[CheckDef] = []
    for position, raw in enumerate(data.get("checks", []), start=1):
        where = f"{name} entry {position}"
        if not isinstance(raw, dict):
            raise CatalogError(f"{where}: expected a mapping")
        for key in ("id", "function", "title", "category", "severity", "expected", "remediation"):
            if not raw.get(key):
                raise CatalogError(f"{where}: missing {key}")
        check_id = raw["id"]
        where = f"{name} {check_id}"
        if not check_id.startswith(prefix):
            raise CatalogError(f"{where}: id must start with {prefix}")
        if check_id in seen_ids:
            raise CatalogError(f"{where}: duplicate id")
        if raw["function"] in seen_functions:
            raise CatalogError(f"{where}: function {raw['function']} is already used")
        if raw["category"] not in CATEGORIES:
            raise CatalogError(f"{where}: unknown category {raw['category']}")
        if raw["severity"] not in SEVERITIES:
            raise CatalogError(f"{where}: unknown severity {raw['severity']}")
        mappings = {}
        for key in FRAMEWORK_KEYS:
            ids = raw.get(key) or []
            unknown = [i for i in ids if i not in frameworks[key]["controls"]]
            if unknown:
                raise CatalogError(f"{where}: {key} ids not in frameworks.yaml: {unknown}")
            mappings[key] = list(ids)
        if not mappings["nist_800_53"]:
            raise CatalogError(f"{where}: at least one NIST 800-53 control is required")
        is_cis = bool(raw.get("cis", True))
        cis_id = raw.get("cis_id")
        if cis_id is not None:
            # Unquoted, YAML reads 5.10 as the number 5.1, so the id must be a string.
            if not isinstance(cis_id, str) or not cis_id.strip():
                raise CatalogError(f"{where}: cis_id must be a quoted string such as \"5.4.1.1\"")
            cis_id = cis_id.strip()
            if not is_cis:
                raise CatalogError(f"{where}: cis_id is set on a check marked cis: false")
            if cis_id in seen_cis_ids:
                raise CatalogError(f"{where}: cis_id {cis_id} is already used by {seen_cis_ids[cis_id]}")
            seen_cis_ids[cis_id] = check_id
        seen_ids.add(check_id)
        seen_functions.add(raw["function"])
        checks.append(CheckDef(
            id=check_id,
            function=raw["function"],
            title=raw["title"],
            category=raw["category"],
            severity=raw["severity"],
            requires_root=bool(raw.get("requires_root", False)),
            expected=raw["expected"],
            remediation=raw["remediation"],
            is_cis=is_cis,
            cis_id=cis_id,
            **mappings,
        ))
    if not checks:
        raise CatalogError(f"{name}: no checks defined")
    return checks


def describe_controls(key: str, ids: List[str]) -> List[Dict[str, Any]]:
    """Expand control ids into the detail the reports print."""
    reference = load_frameworks()[key]
    out = []
    for control_id in ids:
        entry = reference["controls"][control_id]
        item = {"control_id": control_id, "control_name": entry["title"]}
        if key == "nist_800_53":
            item["control_family"] = reference["families"][control_id.split("-")[0]]
            item["baselines"] = list(entry["baselines"])
        out.append(item)
    return out
