"""
NIST 800-53 Control Mapper
Maps CIS Benchmark checks to NIST 800-53 security controls

Author: Rayshaun Smith
GitHub: https://github.com/RaySmith414
"""

from typing import Dict, List


class NISTMapper:
    """Maps compliance checks to NIST 800-53 Rev 5 controls"""

    def __init__(self):
        # Mapping of check IDs to NIST 800-53 controls
        self.mappings = {
            # Filesystem checks
            'FS-001': ['CM-7', 'SC-28'],      # Configuration Management, Protection of Information at Rest
            'FS-002': ['CM-7', 'SC-28'],
            'FS-003': ['CM-7', 'SC-28'],
            'FS-004': ['SC-4', 'SC-28'],       # Information in Shared Resources
            'FS-005': ['AC-6', 'CM-7'],        # Least Privilege
            'FS-006': ['AC-6', 'CM-7'],
            'FS-007': ['AC-6', 'CM-7'],

            # Authentication checks
            'AUTH-001': ['IA-5'],              # Authenticator Management
            'AUTH-002': ['IA-5'],
            'AUTH-003': ['IA-5'],
            'AUTH-004': ['IA-5', 'AC-2'],      # Account Management
            'AUTH-005': ['AC-6', 'IA-2'],      # Identification and Authentication
            'AUTH-006': ['AC-6', 'AC-17'],     # Remote Access
            'AUTH-007': ['AC-6', 'AC-17', 'IA-2'],
            'AUTH-008': ['IA-5', 'IA-2'],
            'AUTH-009': ['IA-2', 'IA-5'],
            'AUTH-010': ['AC-7'],              # Unsuccessful Logon Attempts

            # Network checks
            'NET-001': ['CM-7', 'SC-7'],       # Boundary Protection
            'NET-002': ['CM-7', 'SC-7'],
            'NET-003': ['SC-7', 'SC-5'],       # Denial of Service Protection
            'NET-004': ['SC-7', 'SC-5'],
            'NET-005': ['SC-7', 'SC-5'],
            'NET-006': ['SC-5', 'SC-7'],
            'NET-007': ['SC-7', 'AC-4'],       # Information Flow Enforcement

            # Logging checks
            'LOG-001': ['AU-2', 'AU-3'],       # Audit Events, Audit Content
            'LOG-002': ['AU-2', 'AU-3', 'AU-12'],  # Audit Generation
            'LOG-003': ['AU-4', 'AU-9'],       # Audit Storage Capacity, Audit Protection
            'LOG-004': ['AU-4', 'AU-9', 'AU-11'],  # Audit Record Retention
            'LOG-005': ['AU-9', 'AC-6'],

            # Access control checks
            'AC-001': ['AC-3', 'AC-6'],        # Access Enforcement
            'AC-002': ['AC-3', 'AC-6', 'IA-5'],
            'AC-003': ['AC-3', 'AC-6'],
            'AC-004': ['AC-3', 'AC-6'],
            'AC-005': ['AC-3', 'CM-8'],        # System Component Inventory
            'AC-006': ['AC-6', 'CM-7'],

            # Services checks
            'SVC-001': ['CM-7', 'SA-4'],       # Acquisition Process
            'SVC-002': ['CM-7', 'SC-8'],       # Transmission Confidentiality
            'SVC-003': ['CM-7', 'SC-8'],
            'SVC-004': ['CM-7'],
            'SVC-005': ['CM-7'],
            'SVC-006': ['CM-7', 'AC-4'],
        }

        # NIST 800-53 control descriptions
        self.control_descriptions = {
            'AC-2': 'Account Management',
            'AC-3': 'Access Enforcement',
            'AC-4': 'Information Flow Enforcement',
            'AC-6': 'Least Privilege',
            'AC-7': 'Unsuccessful Logon Attempts',
            'AC-17': 'Remote Access',
            'AU-2': 'Audit Events',
            'AU-3': 'Content of Audit Records',
            'AU-4': 'Audit Storage Capacity',
            'AU-9': 'Protection of Audit Information',
            'AU-11': 'Audit Record Retention',
            'AU-12': 'Audit Generation',
            'CM-7': 'Least Functionality',
            'CM-8': 'System Component Inventory',
            'IA-2': 'Identification and Authentication (Organizational Users)',
            'IA-5': 'Authenticator Management',
            'SA-4': 'Acquisition Process',
            'SC-4': 'Information in Shared System Resources',
            'SC-5': 'Denial-of-Service Protection',
            'SC-7': 'Boundary Protection',
            'SC-8': 'Transmission Confidentiality and Integrity',
            'SC-28': 'Protection of Information at Rest',
        }

        # Control families
        self.control_families = {
            'AC': 'Access Control',
            'AU': 'Audit and Accountability',
            'CM': 'Configuration Management',
            'IA': 'Identification and Authentication',
            'SA': 'System and Services Acquisition',
            'SC': 'System and Communications Protection',
        }

        # Control baselines
        self.control_baselines = {
            'AC-2': ['LOW', 'MODERATE', 'HIGH'],
            'AC-3': ['LOW', 'MODERATE', 'HIGH'],
            'AC-4': ['MODERATE', 'HIGH'],
            'AC-6': ['MODERATE', 'HIGH'],
            'AC-7': ['LOW', 'MODERATE', 'HIGH'],
            'AC-17': ['LOW', 'MODERATE', 'HIGH'],
            'AU-2': ['LOW', 'MODERATE', 'HIGH'],
            'AU-3': ['LOW', 'MODERATE', 'HIGH'],
            'AU-4': ['LOW', 'MODERATE', 'HIGH'],
            'AU-9': ['LOW', 'MODERATE', 'HIGH'],
            'AU-11': ['LOW', 'MODERATE', 'HIGH'],
            'AU-12': ['LOW', 'MODERATE', 'HIGH'],
            'CM-7': ['LOW', 'MODERATE', 'HIGH'],
            'CM-8': ['LOW', 'MODERATE', 'HIGH'],
            'IA-2': ['LOW', 'MODERATE', 'HIGH'],
            'IA-5': ['LOW', 'MODERATE', 'HIGH'],
            'SA-4': ['LOW', 'MODERATE', 'HIGH'],
            'SC-4': ['MODERATE', 'HIGH'],
            'SC-5': ['LOW', 'MODERATE', 'HIGH'],
            'SC-7': ['LOW', 'MODERATE', 'HIGH'],
            'SC-8': ['MODERATE', 'HIGH'],
            'SC-28': ['MODERATE', 'HIGH'],
        }

    def add_nist_mappings(self, results: Dict) -> Dict:
        """Add NIST control mappings to check results"""
        for check in results.get('checks', []):
            check_id = check.get('id', '')
            nist_controls = self.mappings.get(check_id, [])

            check['nist_controls'] = []
            for control in nist_controls:
                check['nist_controls'].append({
                    'control_id': control,
                    'control_name': self.control_descriptions.get(control, 'Unknown'),
                    'control_family': self.control_families.get(control[:2], 'Unknown'),
                    'baselines': self.control_baselines.get(control, [])
                })

        # Add summary of control coverage
        results['nist_summary'] = self._generate_nist_summary(results)

        return results

    def _generate_nist_summary(self, results: Dict) -> Dict:
        """Generate summary of NIST control coverage"""
        control_status = {}

        for check in results.get('checks', []):
            status = check.get('status', 'ERROR')
            for nist_control in check.get('nist_controls', []):
                control_id = nist_control['control_id']

                if control_id not in control_status:
                    control_status[control_id] = {
                        'control_id': control_id,
                        'control_name': nist_control['control_name'],
                        'control_family': nist_control['control_family'],
                        'baselines': nist_control.get('baselines', []),
                        'checks_total': 0,
                        'checks_passed': 0,
                        'checks_failed': 0
                    }

                control_status[control_id]['checks_total'] += 1
                if status == 'PASS':
                    control_status[control_id]['checks_passed'] += 1
                elif status == 'FAIL':
                    control_status[control_id]['checks_failed'] += 1

        # Calculate compliance percentage per control
        for control_id, data in control_status.items():
            if data['checks_total'] > 0:
                data['compliance_percentage'] = round(
                    (data['checks_passed'] / data['checks_total']) * 100, 1
                )
            else:
                data['compliance_percentage'] = 0

        # Sort controls by family and ID
        sorted_controls = sorted(
            control_status.values(),
            key=lambda x: (x['control_family'], x['control_id'])
        )

        return {
            'controls_assessed': len(control_status),
            'controls': sorted_controls,
            'family_summary': self._generate_family_summary(control_status)
        }

    def _generate_family_summary(self, control_status: Dict) -> List[Dict]:
        """Generate summary by control family"""
        family_data = {}

        for control_id, data in control_status.items():
            family = data['control_family']
            if family not in family_data:
                family_data[family] = {
                    'family': family,
                    'controls': 0,
                    'checks_passed': 0,
                    'checks_total': 0
                }

            family_data[family]['controls'] += 1
            family_data[family]['checks_passed'] += data['checks_passed']
            family_data[family]['checks_total'] += data['checks_total']

        # Calculate percentages
        for family, data in family_data.items():
            if data['checks_total'] > 0:
                data['compliance_percentage'] = round(
                    (data['checks_passed'] / data['checks_total']) * 100, 1
                )
            else:
                data['compliance_percentage'] = 0

        return sorted(family_data.values(), key=lambda x: x['family'])

    def get_control_details(self, control_id: str) -> Dict:
        """Get detailed information about a specific NIST control"""
        return {
            'control_id': control_id,
            'control_name': self.control_descriptions.get(control_id, 'Unknown'),
            'control_family': self.control_families.get(control_id[:2], 'Unknown'),
            'baselines': self.control_baselines.get(control_id, []),
            'related_checks': [
                check_id for check_id, controls in self.mappings.items()
                if control_id in controls
            ]
        }

    def get_controls_by_family(self, family: str) -> List[Dict]:
        """Get all controls for a specific family"""
        controls = []
        for control_id, description in self.control_descriptions.items():
            if control_id.startswith(family):
                controls.append({
                    'control_id': control_id,
                    'control_name': description,
                    'baselines': self.control_baselines.get(control_id, [])
                })
        return sorted(controls, key=lambda x: x['control_id'])

    def get_checks_for_control(self, control_id: str) -> List[str]:
        """Get all check IDs that map to a specific NIST control"""
        return [
            check_id for check_id, controls in self.mappings.items()
            if control_id in controls
        ]
