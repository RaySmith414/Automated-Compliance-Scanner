"""
Tests for NIST 800-53 control mapper

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

import pytest
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.nist_mapper import NISTMapper


class TestNISTMapper:
    """Test suite for NISTMapper class"""

    @pytest.fixture
    def mapper(self):
        """Create a NISTMapper instance for testing"""
        return NISTMapper()

    @pytest.fixture
    def sample_results(self):
        """Create sample scan results for testing"""
        return {
            'system_info': {'hostname': 'test-server'},
            'scan_time': '2024-01-15T10:00:00',
            'checks': [
                {
                    'id': 'AUTH-007',
                    'category': 'authentication',
                    'name': 'Ensure SSH root login is disabled',
                    'severity': 'critical',
                    'status': 'PASS',
                    'actual': 'PermitRootLogin no',
                    'expected': 'PermitRootLogin no',
                    'remediation': ''
                },
                {
                    'id': 'NET-007',
                    'category': 'network',
                    'name': 'Ensure firewall is active',
                    'severity': 'critical',
                    'status': 'FAIL',
                    'actual': 'Firewall inactive',
                    'expected': 'Firewall should be active',
                    'remediation': 'Enable ufw'
                },
                {
                    'id': 'LOG-001',
                    'category': 'logging',
                    'name': 'Ensure rsyslog is installed',
                    'severity': 'high',
                    'status': 'PASS',
                    'actual': 'rsyslog installed',
                    'expected': 'rsyslog installed',
                    'remediation': ''
                }
            ]
        }

    def test_add_nist_mappings(self, mapper, sample_results):
        """Test adding NIST mappings to results"""
        results = mapper.add_nist_mappings(sample_results)

        # Check that NIST controls were added to checks
        for check in results['checks']:
            assert 'nist_controls' in check
            if check['id'] == 'AUTH-007':
                control_ids = [c['control_id'] for c in check['nist_controls']]
                assert 'AC-6' in control_ids or 'AC-17' in control_ids or 'IA-2' in control_ids

    def test_nist_summary_generated(self, mapper, sample_results):
        """Test that NIST summary is generated"""
        results = mapper.add_nist_mappings(sample_results)

        assert 'nist_summary' in results
        assert 'controls_assessed' in results['nist_summary']
        assert 'controls' in results['nist_summary']

    def test_control_compliance_calculation(self, mapper, sample_results):
        """Test compliance percentage calculation"""
        results = mapper.add_nist_mappings(sample_results)

        for control in results['nist_summary']['controls']:
            assert 'compliance_percentage' in control
            assert 0 <= control['compliance_percentage'] <= 100

    def test_get_control_details(self, mapper):
        """Test getting details for a specific control"""
        details = mapper.get_control_details('AC-6')

        assert details['control_id'] == 'AC-6'
        assert details['control_name'] == 'Least Privilege'
        assert 'related_checks' in details

    def test_get_controls_by_family(self, mapper):
        """Test getting all controls for a family"""
        ac_controls = mapper.get_controls_by_family('AC')

        assert len(ac_controls) > 0
        for control in ac_controls:
            assert control['control_id'].startswith('AC')

    def test_get_checks_for_control(self, mapper):
        """Test getting checks that map to a control"""
        checks = mapper.get_checks_for_control('IA-5')

        assert len(checks) > 0
        assert 'AUTH-001' in checks

    def test_control_descriptions_exist(self, mapper):
        """Test that all mapped controls have descriptions"""
        all_controls = set()
        for controls in mapper.mappings.values():
            all_controls.update(controls)

        for control in all_controls:
            assert control in mapper.control_descriptions, f"Missing description for {control}"

    def test_control_families_exist(self, mapper):
        """Test that all control families are defined"""
        all_families = set()
        for controls in mapper.mappings.values():
            for control in controls:
                all_families.add(control[:2])

        for family in all_families:
            assert family in mapper.control_families, f"Missing family for {family}"

    def test_family_summary_generation(self, mapper, sample_results):
        """Test family summary generation"""
        results = mapper.add_nist_mappings(sample_results)

        if 'family_summary' in results['nist_summary']:
            for family in results['nist_summary']['family_summary']:
                assert 'family' in family
                assert 'controls' in family
                assert 'compliance_percentage' in family


class TestMappingCompleteness:
    """Test suite for mapping completeness"""

    @pytest.fixture
    def mapper(self):
        return NISTMapper()

    def test_all_check_ids_have_mappings(self, mapper):
        """Test that common check IDs have NIST mappings"""
        expected_checks = [
            'FS-001', 'FS-002', 'AUTH-001', 'AUTH-007',
            'NET-001', 'NET-007', 'LOG-001', 'AC-001', 'SVC-001'
        ]

        for check_id in expected_checks:
            assert check_id in mapper.mappings, f"Missing mapping for {check_id}"

    def test_critical_controls_mapped(self, mapper):
        """Test that critical NIST controls have check mappings"""
        critical_controls = ['AC-2', 'AC-6', 'AU-2', 'CM-7', 'IA-2', 'IA-5', 'SC-7']

        for control in critical_controls:
            checks = mapper.get_checks_for_control(control)
            assert len(checks) > 0, f"No checks mapped to {control}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
