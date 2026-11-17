"""Read-only access to the host being scanned.

Every check goes through a Probe. The scanner never changes the host. Commands
run as argument lists and never through a shell. Every failure mode (missing
tool, timeout, denied read) is reported to the caller instead of being mistaken
for a compliant answer. Tests replace LocalProbe with a fake.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from scanner.model import Unassessable

DEFAULT_TIMEOUT = 30


@dataclass(frozen=True)
class CommandResult:
    argv: Sequence[str]
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    missing: bool = False     # the executable is not installed
    timed_out: bool = False

    @property
    def ran(self) -> bool:
        """True when the command started and finished, whatever its exit code."""
        return not self.missing and not self.timed_out

    @property
    def ok(self) -> bool:
        return self.ran and self.returncode == 0

    def require_ran(self) -> "CommandResult":
        """Return self. Raise Unassessable when there is no answer to read."""
        name = self.argv[0] if self.argv else "command"
        if self.missing:
            raise Unassessable(f"{name} is not installed")
        if self.timed_out:
            raise Unassessable(f"{name} timed out")
        return self


@dataclass(frozen=True)
class FileStat:
    mode: int   # permission bits only, for example 0o644
    uid: int
    gid: int
    owner: str
    group: str


def child_environment() -> Optional[Dict[str, str]]:
    """Environment for the commands the scanner starts. None means inherit.

    PowerShell 7 adds its own module folders to PSModulePath. When the scanner
    is started from a PowerShell 7 session, Windows PowerShell inherits that
    value and then fails to load built-in modules such as
    Microsoft.PowerShell.Security. Without the variable it builds its default
    module path.
    """
    if os.name != "nt":
        return None
    return {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}


class LocalProbe:
    """Probe for the machine the scanner is running on."""

    def run(self, argv: Sequence[str], timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        try:
            done = subprocess.run(  # noqa: S603 - argument list, no shell
                list(argv), capture_output=True, text=True, timeout=timeout,
                errors="replace", stdin=subprocess.DEVNULL, env=child_environment(),
            )
        except FileNotFoundError:
            return CommandResult(argv, None, missing=True)
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
            return CommandResult(argv, None, stdout=partial, timed_out=True)
        except OSError as exc:
            return CommandResult(argv, None, stderr=str(exc), missing=True)
        return CommandResult(argv, done.returncode, done.stdout, done.stderr)

    def which(self, name: str) -> Optional[str]:
        found = shutil.which(name)
        if found:
            return found
        # Root-only tools live in sbin, which may be missing from PATH.
        for directory in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None

    def read_text(self, path: str) -> Optional[str]:
        """File content. None when the file does not exist."""
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError as exc:
            raise Unassessable(f"no permission to read {path}") from exc
        except OSError as exc:
            raise Unassessable(f"cannot read {path}: {exc.strerror or exc}") from exc

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def list_dir(self, path: str) -> List[str]:
        try:
            return sorted(os.listdir(path))
        except (FileNotFoundError, NotADirectoryError):
            return []
        except PermissionError as exc:
            raise Unassessable(f"no permission to list {path}") from exc

    def stat(self, path: str) -> Optional[FileStat]:
        """Permission bits and ownership. None when the path does not exist."""
        import stat as stat_module

        try:
            info = os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError as exc:
            raise Unassessable(f"no permission to stat {path}") from exc
        return FileStat(
            mode=stat_module.S_IMODE(info.st_mode),
            uid=info.st_uid,
            gid=info.st_gid,
            owner=_user_name(info.st_uid),
            group=_group_name(info.st_gid),
        )

    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0


def _user_name(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        import grp

        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)
