"""
Automated Compliance Scanner
A security compliance scanner for CIS Benchmarks with NIST 800-53 mapping
"""

__version__ = "1.0.0"
__author__ = "Rayshaun Smith"
__email__ = "RaySmith414@users.noreply.github.com"

from scanner.linux_checks import LinuxComplianceChecker
from scanner.windows_checks import WindowsComplianceChecker
from scanner.nist_mapper import NISTMapper

__all__ = [
    "LinuxComplianceChecker",
    "WindowsComplianceChecker",
    "NISTMapper",
]
