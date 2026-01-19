"""
Utility functions for Automated Compliance Scanner

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import os
import subprocess
import platform
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


def run_command(command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """
    Execute a shell command and return the result.

    Args:
        command: The command to execute
        timeout: Command timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, '', 'Command timed out'
    except Exception as e:
        return -1, '', str(e)


def check_file_exists(filepath: str) -> bool:
    """Check if a file exists"""
    return os.path.isfile(filepath)


def check_directory_exists(dirpath: str) -> bool:
    """Check if a directory exists"""
    return os.path.isdir(dirpath)


def get_file_permissions(filepath: str) -> Optional[int]:
    """
    Get file permissions in octal format.

    Args:
        filepath: Path to the file

    Returns:
        Permissions in octal (e.g., 644) or None if file doesn't exist
    """
    try:
        import stat
        file_stat = os.stat(filepath)
        return stat.S_IMODE(file_stat.st_mode)
    except (FileNotFoundError, PermissionError):
        return None


def get_file_owner(filepath: str) -> Optional[Tuple[str, str]]:
    """
    Get file owner and group.

    Args:
        filepath: Path to the file

    Returns:
        Tuple of (owner, group) or None if file doesn't exist
    """
    try:
        import pwd
        import grp
        file_stat = os.stat(filepath)
        owner = pwd.getpwuid(file_stat.st_uid).pw_name
        group = grp.getgrgid(file_stat.st_gid).gr_name
        return owner, group
    except (FileNotFoundError, PermissionError, KeyError):
        return None


def read_file_content(filepath: str) -> Optional[str]:
    """
    Read and return file content.

    Args:
        filepath: Path to the file

    Returns:
        File content as string or None if unable to read
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def parse_config_file(filepath: str, delimiter: str = '=') -> Dict[str, str]:
    """
    Parse a simple configuration file.

    Args:
        filepath: Path to the config file
        delimiter: Character separating key and value

    Returns:
        Dictionary of config key-value pairs
    """
    config = {}
    content = read_file_content(filepath)
    if content:
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and delimiter in line:
                parts = line.split(delimiter, 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip().strip('"\'')
                    config[key] = value
    return config


def get_system_info() -> Dict[str, Any]:
    """
    Gather comprehensive system information.

    Returns:
        Dictionary containing system details
    """
    info = {
        'hostname': platform.node(),
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'scan_timestamp': datetime.now().isoformat()
    }

    # Add Linux-specific info
    if platform.system() == 'Linux':
        try:
            import distro
            info['distribution'] = f"{distro.name()} {distro.version()}"
            info['distribution_id'] = distro.id()
        except ImportError:
            info['distribution'] = 'Unknown'
            info['distribution_id'] = 'unknown'

    # Add memory info
    try:
        import psutil
        mem = psutil.virtual_memory()
        info['total_memory_gb'] = round(mem.total / (1024**3), 2)
        info['cpu_count'] = psutil.cpu_count()
    except ImportError:
        pass

    return info


def calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate hash of a file.

    Args:
        filepath: Path to the file
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hex digest of the file hash or None if unable to read
    """
    hash_func = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (FileNotFoundError, PermissionError, IOError):
        return None


def format_severity_level(severity: str) -> int:
    """
    Convert severity string to numeric level for comparison.

    Args:
        severity: Severity string (critical, high, medium, low)

    Returns:
        Numeric severity level (0 = critical, 3 = low)
    """
    severity_map = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3
    }
    return severity_map.get(severity.lower(), 999)


def filter_checks_by_severity(checks: List[Dict], min_severity: str) -> List[Dict]:
    """
    Filter checks by minimum severity level.

    Args:
        checks: List of check dictionaries
        min_severity: Minimum severity to include

    Returns:
        Filtered list of checks
    """
    if min_severity == 'all':
        return checks

    min_level = format_severity_level(min_severity)
    return [c for c in checks if format_severity_level(c.get('severity', 'low')) <= min_level]


def group_checks_by_category(checks: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Group checks by their category.

    Args:
        checks: List of check dictionaries

    Returns:
        Dictionary with categories as keys and lists of checks as values
    """
    grouped = {}
    for check in checks:
        category = check.get('category', 'other')
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(check)
    return grouped


def validate_output_path(filepath: str) -> bool:
    """
    Validate that the output path is writable.

    Args:
        filepath: Path to validate

    Returns:
        True if path is writable, False otherwise
    """
    try:
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            return False
        if directory:
            return os.access(directory, os.W_OK)
        return os.access('.', os.W_OK)
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing invalid characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename safe for filesystem
    """
    import re
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    return sanitized or 'unnamed'


def export_to_json(data: Dict, filepath: str, indent: int = 2) -> bool:
    """
    Export data to JSON file.

    Args:
        data: Dictionary to export
        filepath: Output file path
        indent: JSON indentation level

    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=str)
        return True
    except (IOError, TypeError) as e:
        return False


def load_yaml_config(filepath: str) -> Optional[Dict]:
    """
    Load and parse a YAML configuration file.

    Args:
        filepath: Path to YAML file

    Returns:
        Parsed YAML as dictionary or None if unable to load
    """
    try:
        import yaml
        with open(filepath, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except (FileNotFoundError, ImportError) as e:
        return None


def get_service_status(service_name: str) -> Dict[str, Any]:
    """
    Get the status of a systemd service (Linux).

    Args:
        service_name: Name of the service

    Returns:
        Dictionary with service status information
    """
    status = {
        'name': service_name,
        'active': False,
        'enabled': False,
        'status': 'unknown'
    }

    # Check if service is active
    code, output, _ = run_command(f"systemctl is-active {service_name} 2>/dev/null")
    status['active'] = output == 'active'
    status['status'] = output if output else 'unknown'

    # Check if service is enabled
    code, output, _ = run_command(f"systemctl is-enabled {service_name} 2>/dev/null")
    status['enabled'] = output == 'enabled'

    return status


def is_root() -> bool:
    """Check if script is running with root privileges"""
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def format_timestamp(dt: datetime = None, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format a datetime object as a string.

    Args:
        dt: Datetime object (default: now)
        format_str: Format string

    Returns:
        Formatted timestamp string
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime(format_str)
