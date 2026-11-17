"""LocalProbe: the only code that touches the real machine."""

import sys

import pytest

from scanner import probe as probe_module
from scanner.model import Unassessable
from scanner.probe import LocalProbe, child_environment


def test_command_output_and_exit_code_are_reported():
    result = LocalProbe().run([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"])
    assert result.ran and not result.ok
    assert result.returncode == 3
    assert result.stdout.strip() == "out" and result.stderr.strip() == "err"


def test_a_missing_executable_is_reported_as_missing_not_as_a_failure():
    result = LocalProbe().run(["this-tool-does-not-exist-anywhere", "--version"])
    assert result.missing and not result.ran and result.returncode is None
    with pytest.raises(Unassessable, match="is not installed"):
        result.require_ran()


def test_a_timeout_is_reported_and_never_looks_like_an_answer():
    result = LocalProbe().run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert result.timed_out and not result.ran and not result.ok
    with pytest.raises(Unassessable, match="timed out"):
        result.require_ran()


def test_commands_get_no_input_to_wait_for():
    result = LocalProbe().run([sys.executable, "-c", "import sys; print(len(sys.stdin.read()))"], timeout=20)
    assert result.ok and result.stdout.strip() == "0"


def test_text_from_the_shell_is_not_interpreted():
    # One argument, passed as is. A shell would expand or run the second half.
    result = LocalProbe().run([sys.executable, "-c", "import sys; print(sys.argv[1])", "$HOME; echo injected"])
    assert result.stdout.strip() == "$HOME; echo injected"


def test_missing_file_is_none_and_a_folder_is_not_a_file(tmp_path):
    probe = LocalProbe()
    assert probe.read_text(str(tmp_path / "absent.conf")) is None
    assert probe.stat(str(tmp_path / "absent.conf")) is None
    assert probe.list_dir(str(tmp_path / "absent.d")) == []
    target = tmp_path / "present.conf"
    target.write_text("KEY=value\n", encoding="utf-8")
    assert probe.read_text(str(target)) == "KEY=value\n"
    assert probe.exists(str(target))
    assert probe.list_dir(str(tmp_path)) == ["present.conf"]


def test_windows_powershell_does_not_inherit_the_powershell_7_module_path(monkeypatch):
    monkeypatch.setattr(probe_module.os, "name", "nt")
    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")
    monkeypatch.setenv("SCANNER_TEST_KEEP", "1")
    environment = child_environment()
    assert environment is not None
    assert "PSMODULEPATH" not in {key.upper() for key in environment}
    assert environment["SCANNER_TEST_KEEP"] == "1"


def test_other_platforms_inherit_the_environment_unchanged(monkeypatch):
    monkeypatch.setattr(probe_module.os, "name", "posix")
    assert child_environment() is None
