"""
Tests for Windows compliance checks

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import pytest
from unittest.mock import patch, MagicMock
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.windows_checks import WindowsComplianceChecker


class TestWindowsComplianceChecker:
    """Test suite for WindowsComplianceChecker class"""

    @pytest.fixture
    def checker(self):
        """Create a WindowsComplianceChecker instance for testing"""
        return WindowsComplianceChecker()

    # ==================== AUTHENTICATION TESTS ====================

    def test_check_password_history_pass(self, checker):
        """Test password history check when compliant"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'Length of password history maintained: 24', '')):
            result = checker.check_password_history()
            assert result['passed'] == True

    def test_check_password_history_fail(self, checker):
        """Test password history check when non-compliant"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'Length of password history maintained: 5', '')):
            result = checker.check_password_history()
            assert result['passed'] == False

    def test_check_password_max_age_pass(self, checker):
        """Test password max age check when compliant"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'Maximum password age (days): 90', '')):
            result = checker.check_password_max_age()
            assert result['passed'] == True

    def test_check_password_max_age_fail(self, checker):
        """Test password max age check when non-compliant"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'Maximum password age (days): Never', '')):
            result = checker.check_password_max_age()
            assert result['passed'] == False

    def test_check_guest_disabled_pass(self, checker):
        """Test guest account check when disabled"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'False', '')):
            result = checker.check_guest_disabled()
            assert result['passed'] == True

    def test_check_guest_disabled_fail(self, checker):
        """Test guest account check when enabled"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'True', '')):
            result = checker.check_guest_disabled()
            assert result['passed'] == False

    # ==================== NETWORK TESTS ====================

    def test_check_firewall_enabled_pass(self, checker):
        """Test firewall check when all profiles enabled"""
        mock_output = '[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":true}]'
        with patch.object(checker, '_run_powershell', return_value=(0, mock_output, '')):
            result = checker.check_firewall_enabled()
            assert result['passed'] == True

    def test_check_firewall_enabled_fail(self, checker):
        """Test firewall check when some profiles disabled"""
        mock_output = '[{"Name":"Domain","Enabled":false},{"Name":"Private","Enabled":true}]'
        with patch.object(checker, '_run_powershell', return_value=(0, mock_output, '')):
            result = checker.check_firewall_enabled()
            assert result['passed'] == False

    def test_check_smbv1_disabled_pass(self, checker):
        """Test SMBv1 check when disabled"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'Disabled', '')):
            result = checker.check_smbv1_disabled()
            assert result['passed'] == True

    def test_check_smbv1_disabled_fail(self, checker):
        """Test SMBv1 check when enabled"""
        with patch.object(checker, '_run_powershell', return_value=(0, 'Enabled', '')):
            result = checker.check_smbv1_disabled()
            assert result['passed'] == False

    # ==================== ACCESS CONTROL TESTS ====================

    def test_check_uac_enabled_pass(self, checker):
        """Test UAC check when enabled"""
        with patch.object(checker, '_run_powershell', return_value=(0, '1', '')):
            result = checker.check_uac_enabled()
            assert result['passed'] == True

    def test_check_uac_enabled_fail(self, checker):
        """Test UAC check when disabled"""
        with patch.object(checker, '_run_powershell', return_value=(0, '0', '')):
            result = checker.check_uac_enabled()
            assert result['passed'] == False

    # ==================== SERVICES TESTS ====================

    def test_check_telnet_disabled_pass(self, checker):
        """Test telnet service check when disabled"""
        with patch.object(checker, '_check_service_status', return_value={
            'exists': True, 'status': 'Stopped', 'start_type': 'Disabled'
        }):
            result = checker.check_telnet_disabled()
            assert result['passed'] == True

    def test_check_telnet_disabled_fail(self, checker):
        """Test telnet service check when running"""
        with patch.object(checker, '_check_service_status', return_value={
            'exists': True, 'status': 'Running', 'start_type': 'Automatic'
        }):
            result = checker.check_telnet_disabled()
            assert result['passed'] == False

    # ==================== RUNNER TESTS ====================

    def test_run_all_checks(self, checker):
        """Test running all checks returns expected structure"""
        with patch.object(checker, '_run_powershell', return_value=(0, '', '')):
            with patch.object(checker, '_run_command', return_value=(0, '', '')):
                with patch.object(checker, '_check_service_status', return_value={
                    'exists': False, 'status': 'Unknown', 'start_type': 'Unknown'
                }):
                    results = checker.run_all_checks()

                    assert 'system_info' in results
                    assert 'scan_time' in results
                    assert 'checks' in results

    def test_run_checks_with_category_filter(self, checker):
        """Test running checks with category filter"""
        with patch.object(checker, '_run_powershell', return_value=(0, '', '')):
            results = checker.run_all_checks(categories=['authentication'])

            for check in results['checks']:
                assert check['category'] == 'authentication'


class TestWindowsHelperMethods:
    """Test suite for Windows helper methods"""

    @pytest.fixture
    def checker(self):
        return WindowsComplianceChecker()

    def test_get_system_info(self, checker):
        """Test _get_system_info returns expected keys"""
        info = checker._get_system_info()
        assert 'hostname' in info
        assert 'kernel' in info
        assert 'distribution' in info
        assert 'architecture' in info

    def test_check_service_status(self, checker):
        """Test _check_service_status returns expected structure"""
        with patch.object(checker, '_run_powershell', return_value=(0, '{"Status":4,"StartType":2}', '')):
            status = checker._check_service_status('TestService')
            assert 'exists' in status
            assert 'status' in status
            assert 'start_type' in status


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
