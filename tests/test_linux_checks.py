"""
Tests for Linux compliance checks

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import pytest
from unittest.mock import patch, MagicMock
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.linux_checks import LinuxComplianceChecker


class TestLinuxComplianceChecker:
    """Test suite for LinuxComplianceChecker class"""

    @pytest.fixture
    def checker(self):
        """Create a LinuxComplianceChecker instance for testing"""
        return LinuxComplianceChecker()

    # ==================== FILESYSTEM TESTS ====================

    def test_check_cramfs_disabled_pass(self, checker):
        """Test cramfs check when module is disabled"""
        with patch.object(checker, '_check_module_disabled', return_value=True):
            result = checker.check_cramfs_disabled()
            assert result['passed'] == True
            assert 'Module disabled' in result['actual']

    def test_check_cramfs_disabled_fail(self, checker):
        """Test cramfs check when module is enabled"""
        with patch.object(checker, '_check_module_disabled', return_value=False):
            result = checker.check_cramfs_disabled()
            assert result['passed'] == False
            assert 'remediation' in result

    def test_check_tmp_partition_pass(self, checker):
        """Test /tmp partition check when configured"""
        with patch.object(checker, '_run_command', return_value=(0, '/tmp tmpfs tmpfs', '')):
            result = checker.check_tmp_partition()
            assert result['passed'] == True

    def test_check_tmp_partition_fail(self, checker):
        """Test /tmp partition check when not configured"""
        with patch.object(checker, '_run_command', return_value=(1, '', '')):
            result = checker.check_tmp_partition()
            assert result['passed'] == False

    # ==================== AUTHENTICATION TESTS ====================

    def test_check_password_max_days_pass(self, checker):
        """Test password max days check when compliant"""
        with patch.object(checker, '_run_command', return_value=(0, 'PASS_MAX_DAYS 90', '')):
            result = checker.check_password_max_days()
            assert result['passed'] == True
            assert '90' in result['actual']

    def test_check_password_max_days_fail(self, checker):
        """Test password max days check when non-compliant"""
        with patch.object(checker, '_run_command', return_value=(0, 'PASS_MAX_DAYS 99999', '')):
            result = checker.check_password_max_days()
            assert result['passed'] == False

    def test_check_root_only_uid0_pass(self, checker):
        """Test root UID 0 check when only root has UID 0"""
        with patch.object(checker, '_run_command', return_value=(0, 'root', '')):
            result = checker.check_root_only_uid0()
            assert result['passed'] == True

    def test_check_root_only_uid0_fail(self, checker):
        """Test root UID 0 check when multiple accounts have UID 0"""
        with patch.object(checker, '_run_command', return_value=(0, 'root\nadmin', '')):
            result = checker.check_root_only_uid0()
            assert result['passed'] == False

    def test_check_ssh_root_login_pass(self, checker):
        """Test SSH root login check when disabled"""
        with patch.object(checker, '_check_ssh_config', return_value=True):
            with patch.object(checker, '_run_command', return_value=(0, 'permitrootlogin no', '')):
                result = checker.check_ssh_root_login()
                assert result['passed'] == True

    def test_check_ssh_root_login_fail(self, checker):
        """Test SSH root login check when enabled"""
        with patch.object(checker, '_check_ssh_config', return_value=False):
            with patch.object(checker, '_run_command', return_value=(0, 'permitrootlogin yes', '')):
                result = checker.check_ssh_root_login()
                assert result['passed'] == False

    # ==================== NETWORK TESTS ====================

    def test_check_ip_forwarding_pass(self, checker):
        """Test IP forwarding check when disabled"""
        with patch.object(checker, '_check_sysctl', return_value=True):
            result = checker.check_ip_forwarding()
            assert result['passed'] == True

    def test_check_ip_forwarding_fail(self, checker):
        """Test IP forwarding check when enabled"""
        with patch.object(checker, '_check_sysctl', side_effect=[False, True]):
            result = checker.check_ip_forwarding()
            assert result['passed'] == False

    def test_check_firewall_active_pass(self, checker):
        """Test firewall check when active"""
        with patch.object(checker, '_run_command', side_effect=[
            (0, '', ''),  # ufw active
            (1, '', ''),  # firewalld
            (0, '10', '')  # iptables
        ]):
            result = checker.check_firewall_active()
            assert result['passed'] == True

    def test_check_firewall_active_fail(self, checker):
        """Test firewall check when inactive"""
        with patch.object(checker, '_run_command', side_effect=[
            (1, '', ''),  # ufw not active
            (1, '', ''),  # firewalld not active
            (0, '5', '')   # iptables no rules
        ]):
            result = checker.check_firewall_active()
            assert result['passed'] == False

    # ==================== LOGGING TESTS ====================

    def test_check_rsyslog_installed_pass(self, checker):
        """Test rsyslog check when installed"""
        with patch.object(checker, '_check_package_installed', return_value=True):
            result = checker.check_rsyslog_installed()
            assert result['passed'] == True

    def test_check_rsyslog_installed_fail(self, checker):
        """Test rsyslog check when not installed"""
        with patch.object(checker, '_check_package_installed', return_value=False):
            result = checker.check_rsyslog_installed()
            assert result['passed'] == False

    # ==================== ACCESS CONTROL TESTS ====================

    def test_check_passwd_permissions_pass(self, checker):
        """Test /etc/passwd permissions when correct"""
        with patch.object(checker, '_check_file_permissions', return_value=True):
            with patch.object(checker, '_run_command', return_value=(0, '644 root root', '')):
                result = checker.check_passwd_permissions()
                assert result['passed'] == True

    def test_check_passwd_permissions_fail(self, checker):
        """Test /etc/passwd permissions when incorrect"""
        with patch.object(checker, '_check_file_permissions', return_value=False):
            with patch.object(checker, '_run_command', return_value=(0, '777 root root', '')):
                result = checker.check_passwd_permissions()
                assert result['passed'] == False

    # ==================== SERVICES TESTS ====================

    def test_check_telnet_not_installed_pass(self, checker):
        """Test telnet check when not installed"""
        with patch.object(checker, '_check_package_installed', return_value=False):
            result = checker.check_telnet_not_installed()
            assert result['passed'] == True

    def test_check_telnet_not_installed_fail(self, checker):
        """Test telnet check when installed"""
        with patch.object(checker, '_check_package_installed', return_value=True):
            result = checker.check_telnet_not_installed()
            assert result['passed'] == False

    # ==================== RUNNER TESTS ====================

    def test_run_all_checks(self, checker):
        """Test running all checks returns expected structure"""
        with patch.object(checker, '_run_command', return_value=(0, '', '')):
            with patch.object(checker, '_check_sysctl', return_value=True):
                with patch.object(checker, '_check_module_disabled', return_value=True):
                    with patch.object(checker, '_check_package_installed', return_value=False):
                        with patch.object(checker, '_check_ssh_config', return_value=True):
                            with patch.object(checker, '_check_file_permissions', return_value=True):
                                results = checker.run_all_checks()

                                assert 'system_info' in results
                                assert 'scan_time' in results
                                assert 'checks' in results
                                assert len(results['checks']) > 0

    def test_run_checks_with_category_filter(self, checker):
        """Test running checks with category filter"""
        with patch.object(checker, '_run_command', return_value=(0, '', '')):
            with patch.object(checker, '_check_sysctl', return_value=True):
                results = checker.run_all_checks(categories=['network'])

                for check in results['checks']:
                    assert check['category'] == 'network'

    def test_run_checks_with_severity_filter(self, checker):
        """Test running checks with severity filter"""
        with patch.object(checker, '_run_command', return_value=(0, '', '')):
            with patch.object(checker, '_check_sysctl', return_value=True):
                with patch.object(checker, '_check_module_disabled', return_value=True):
                    with patch.object(checker, '_check_package_installed', return_value=False):
                        with patch.object(checker, '_check_ssh_config', return_value=True):
                            results = checker.run_all_checks(min_severity='critical')

                            for check in results['checks']:
                                assert check['severity'] == 'critical'


class TestHelperMethods:
    """Test suite for helper methods"""

    @pytest.fixture
    def checker(self):
        return LinuxComplianceChecker()

    def test_run_command_success(self, checker):
        """Test _run_command with successful command"""
        code, stdout, stderr = checker._run_command('echo test')
        assert code == 0
        assert 'test' in stdout

    def test_run_command_failure(self, checker):
        """Test _run_command with failing command"""
        code, stdout, stderr = checker._run_command('false')
        assert code != 0

    def test_run_command_timeout(self, checker):
        """Test _run_command handles timeout"""
        with patch('subprocess.run', side_effect=Exception('timeout')):
            code, stdout, stderr = checker._run_command('sleep 100')
            assert code == -1

    def test_get_system_info(self, checker):
        """Test _get_system_info returns expected keys"""
        info = checker._get_system_info()
        assert 'hostname' in info
        assert 'kernel' in info
        assert 'architecture' in info


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
