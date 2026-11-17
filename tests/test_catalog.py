"""The YAML catalogs are the single source of truth. These tests keep the code,
the data and the framework reference in step."""

import inspect

import pytest
import yaml

from scanner import catalog
from scanner.catalog import CatalogError, describe_controls, load_checks, load_frameworks
from scanner.linux_checks import LinuxChecks
from scanner.model import CATEGORIES, FRAMEWORK_KEYS, SEVERITIES
from scanner.windows_checks import WindowsChecks

CHECKERS = {"linux": LinuxChecks, "windows": WindowsChecks}


def public_check_methods(cls):
    skip = {"is_privileged"}
    return {name for name, member in inspect.getmembers(cls, inspect.isfunction)
            if not name.startswith("_") and name not in skip}


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_catalog_and_code_match_one_to_one(platform):
    in_catalog = {check.function for check in load_checks(platform)}
    in_code = public_check_methods(CHECKERS[platform])
    assert in_catalog - in_code == set(), "catalog entries without a test in code"
    assert in_code - in_catalog == set(), "tests in code that the catalog does not list"


def test_expected_check_counts():
    assert len(load_checks("linux")) == 41
    assert len(load_checks("windows")) == 32


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_catalog_entries_are_well_formed(platform):
    checks = load_checks(platform)
    assert len({c.id for c in checks}) == len(checks)
    for check in checks:
        assert check.category in CATEGORIES
        assert check.severity in SEVERITIES
        assert check.nist_800_53, check.id
        assert check.soc2, check.id
        assert check.iso_27001, check.id
        assert check.expected and check.remediation and check.title
        assert check.cis_id is None or check.is_cis


def test_every_mapped_control_exists_in_the_reference_data():
    frameworks = load_frameworks()
    for platform in ("linux", "windows"):
        for check in load_checks(platform):
            for key in FRAMEWORK_KEYS:
                for control_id in getattr(check, key):
                    assert control_id in frameworks[key]["controls"], (check.id, key, control_id)


def test_reference_data_has_no_unused_controls():
    used = {key: set() for key in FRAMEWORK_KEYS}
    for platform in ("linux", "windows"):
        for check in load_checks(platform):
            for key in FRAMEWORK_KEYS:
                used[key].update(getattr(check, key))
    for key in FRAMEWORK_KEYS:
        assert set(load_frameworks()[key]["controls"]) == used[key], key


def test_nist_titles_are_revision_5_titles():
    controls = load_frameworks()["nist_800_53"]["controls"]
    assert controls["AU-2"]["title"] == "Event Logging"
    assert controls["AU-4"]["title"] == "Audit Log Storage Capacity"
    assert controls["AU-12"]["title"] == "Audit Record Generation"
    assert controls["CM-6"]["title"] == "Configuration Settings"


def test_nist_baselines_follow_800_53b():
    controls = load_frameworks()["nist_800_53"]["controls"]
    for control_id in ("AC-4", "AC-6", "SC-8"):
        assert controls[control_id]["baselines"] == ["MODERATE", "HIGH"], control_id
    for control_id in ("AC-2", "AC-3", "AC-7", "AC-17", "AU-2", "CM-6", "CM-7", "IA-2", "IA-5", "SC-5", "SC-7"):
        assert controls[control_id]["baselines"] == ["LOW", "MODERATE", "HIGH"], control_id


def test_windows_checks_have_their_own_mappings():
    """The mappings used to be shared with the Linux check that had the same number."""
    windows = {check.id: check for check in load_checks("windows")}
    assert windows["WIN-AUTH-010"].nist_800_53 == ["AC-17", "IA-2"]      # Remote Desktop NLA
    assert "AC-7" in windows["WIN-AUTH-006"].nist_800_53                 # lockout threshold
    assert "AC-7" in windows["WIN-AUTH-007"].nist_800_53                 # lockout duration
    assert windows["WIN-NET-002"].nist_800_53 == ["CM-7", "CM-6"]        # SMB v1
    assert "AC-6" in windows["WIN-ACC-001"].nist_800_53                  # UAC
    assert "AU-4" in windows["WIN-LOG-004"].nist_800_53                  # Security log size


def test_describe_controls_expands_nist_detail():
    detail = describe_controls("nist_800_53", ["AC-6", "CM-7"])
    assert detail[0] == {"control_id": "AC-6", "control_name": "Least Privilege",
                         "control_family": "Access Control", "baselines": ["MODERATE", "HIGH"]}
    assert describe_controls("iso_27001", ["A.8.9"]) == [{"control_id": "A.8.9", "control_name": "Configuration management"}]


@pytest.mark.parametrize("mutation, message", [
    (lambda c: c.update(severity="urgent"), "unknown severity"),
    (lambda c: c.update(category="misc"), "unknown category"),
    (lambda c: c.update(nist_800_53=["ZZ-9"]), "not in frameworks.yaml"),
    (lambda c: c.update(nist_800_53=[]), "at least one NIST"),
    (lambda c: c.update(id="FS-001"), "must start with LNX-"),
    (lambda c: c.pop("remediation"), "missing remediation"),
    (lambda c: c.update(cis_id=5.1), "must be a quoted string"),       # what YAML makes of an unquoted 5.10
    (lambda c: c.update(cis_id="1.1.1.1", cis=False), "marked cis: false"),
])
def test_malformed_catalog_is_rejected_at_load_time(monkeypatch, mutation, message):
    real = catalog._read_yaml

    def broken(name):
        data = yaml.safe_load(yaml.safe_dump(real(name)))
        if name == "checks_linux.yaml":
            mutation(data["checks"][0])
        return data

    monkeypatch.setattr(catalog, "_read_yaml", broken)
    catalog.load_checks.cache_clear()
    try:
        with pytest.raises(CatalogError, match=message):
            catalog.load_checks("linux")
    finally:
        catalog.load_checks.cache_clear()


def test_duplicate_ids_are_rejected(monkeypatch):
    real = catalog._read_yaml

    def duplicated(name):
        data = yaml.safe_load(yaml.safe_dump(real(name)))
        if name == "checks_linux.yaml":
            data["checks"][1]["id"] = data["checks"][0]["id"]
        return data

    monkeypatch.setattr(catalog, "_read_yaml", duplicated)
    catalog.load_checks.cache_clear()
    try:
        with pytest.raises(CatalogError, match="duplicate id"):
            catalog.load_checks("linux")
    finally:
        catalog.load_checks.cache_clear()


def test_cis_ids_can_be_filled_in_but_not_reused(monkeypatch):
    """Version 1 shipped two pairs of checks that shared a CIS number."""
    real = catalog._read_yaml

    def numbered(reuse):
        def read(name):
            data = yaml.safe_load(yaml.safe_dump(real(name)))
            if name == "checks_linux.yaml":
                data["checks"][0]["cis_id"] = "1.1.1.1"
                data["checks"][1]["cis_id"] = "1.1.1.1" if reuse else "1.1.1.2"
            return data
        return read

    try:
        monkeypatch.setattr(catalog, "_read_yaml", numbered(reuse=False))
        catalog.load_checks.cache_clear()
        assert [c.cis_id for c in catalog.load_checks("linux")[:3]] == ["1.1.1.1", "1.1.1.2", None]
        monkeypatch.setattr(catalog, "_read_yaml", numbered(reuse=True))
        catalog.load_checks.cache_clear()
        with pytest.raises(CatalogError, match="already used by LNX-FS-001"):
            catalog.load_checks("linux")
    finally:
        catalog.load_checks.cache_clear()
