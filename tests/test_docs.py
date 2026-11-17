"""The generated reference documents must match the catalogs."""

from pathlib import Path

from scanner import docs
from scanner.catalog import load_checks

DOCS = Path(__file__).resolve().parent.parent / "docs"


def test_reference_documents_are_current():
    for name, content in docs.documents().items():
        on_disk = (DOCS / name).read_text(encoding="utf-8")
        assert on_disk == content, f"docs/{name} is stale. Run: python -m scanner.docs"


def test_every_check_appears_in_both_documents():
    checks_doc = docs.checks_markdown()
    mappings_doc = docs.mappings_markdown()
    for platform in ("linux", "windows"):
        for check in load_checks(platform):
            assert f"| {check.id} |" in checks_doc
            assert f"| {check.id} |" in mappings_doc


def test_check_mode_detects_stale_files(tmp_path):
    assert docs.main(["--out", str(tmp_path)]) == 0
    assert docs.main(["--out", str(tmp_path), "--check"]) == 0
    (tmp_path / "CHECKS.md").write_text("old", encoding="utf-8")
    assert docs.main(["--out", str(tmp_path), "--check"]) == 1
