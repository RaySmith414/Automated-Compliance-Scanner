"""Shared test doubles.

FakeProbe stands in for the host. A test states exactly which files, stats and
command results exist. Anything else behaves like a machine where that file or
tool is absent, so a check can never pass by accident.
"""

import ntpath
import os
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Union

import pytest

from scanner.model import Unassessable
from scanner.probe import CommandResult, FileStat

Result = Union[CommandResult, Callable[[Sequence[str]], CommandResult]]


def ok(stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult((), 0, stdout, stderr)


def fail(returncode: int = 1, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult((), returncode, stdout, stderr)


def missing() -> CommandResult:
    return CommandResult((), None, missing=True)


def timed_out(stdout: str = "") -> CommandResult:
    return CommandResult((), None, stdout=stdout, timed_out=True)


def stat(mode: int, owner: str = "root", group: str = "root", uid: int = 0, gid: Optional[int] = None) -> FileStat:
    if gid is None:
        gid = 0 if group == "root" else 1000
    if owner != "root" and uid == 0:
        uid = 1000
    return FileStat(mode=mode, uid=uid, gid=gid, owner=owner, group=group)


class FakeProbe:
    def __init__(self, files: Optional[Dict[str, object]] = None, stats: Optional[Dict[str, FileStat]] = None,
                 commands: Optional[Dict[tuple, Result]] = None, tools: Optional[Iterable[str]] = None,
                 dirs: Optional[Dict[str, List[str]]] = None, existing: Optional[Iterable[str]] = None,
                 scripts: Optional[Dict[str, Result]] = None, root: bool = True):
        self.files = dict(files or {})
        self.stats = dict(stats or {})
        self.commands = dict(commands or {})
        self.tools = set(tools or ())
        self.dirs = dict(dirs or {})
        self.existing = set(existing or ())
        self.scripts = dict(scripts or {})   # PowerShell: substring of the script -> result
        self.root = root
        self.calls: List[List[str]] = []

    # --- probe interface -------------------------------------------------
    def which(self, name: str) -> Optional[str]:
        return f"/usr/bin/{name}" if name in self.tools else None

    def run(self, argv: Sequence[str], timeout: int = 30) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        program = os.path.basename(argv[0])
        if ntpath.basename(argv[0]).lower() in ("powershell", "powershell.exe"):
            if "powershell" not in self.tools:
                return CommandResult(argv, None, missing=True)
            return self._finish(argv, self._script_result(argv[-1]))
        if program not in self.tools:
            return CommandResult(argv, None, missing=True)
        key = (program, *argv[1:])
        best = None
        for candidate in self.commands:
            if key[:len(candidate)] == candidate and (best is None or len(candidate) > len(best)):
                best = candidate
        if best is None:
            raise AssertionError(f"FakeProbe has no result for command: {key}")
        return self._finish(argv, self.commands[best])

    def _script_result(self, script: str) -> Result:
        matches = [needle for needle in self.scripts if needle in script]
        if not matches:
            raise AssertionError(f"FakeProbe has no result for PowerShell script: {script[:120]!r}")
        return self.scripts[max(matches, key=len)]

    @staticmethod
    def _finish(argv: List[str], result: Result) -> CommandResult:
        if callable(result):
            result = result(argv)
        return CommandResult(argv, result.returncode, result.stdout, result.stderr, result.missing, result.timed_out)

    def read_text(self, path: str) -> Optional[str]:
        value = self.files.get(path)
        if isinstance(value, Exception):
            raise value
        return value

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.existing or path in self.stats or path in self.dirs

    def list_dir(self, path: str) -> List[str]:
        return sorted(self.dirs.get(path, []))

    def stat(self, path: str) -> Optional[FileStat]:
        value = self.stats.get(path)
        if isinstance(value, Exception):
            raise value
        return value

    def is_root(self) -> bool:
        return self.root


def denied(path: str) -> Unassessable:
    return Unassessable(f"no permission to read {path}")


@pytest.fixture
def fake_probe():
    return FakeProbe
