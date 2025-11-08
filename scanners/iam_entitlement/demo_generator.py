#!/usr/bin/env python3
"""
Demo Data Generator for IAM Entitlement Analysis
Creates sample IAM findings for demonstration and learning
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Any

class IAMDemoGenerator:
    """Generates demo IAM findings for testing and case studies"""
    
    def __init__(self):
        # Sample data for realistic demonstrations
        self.sample_users = [
            'admin-user', 'dev-user1', 'service-account1',
            'backup-user', 'readonly-user', 'temp-admin'
        ]
        
        self.sample_roles = [
            'Administrator', 'Developer', 'ReadOnly',
            'BackupOperator', 'SecurityAuditor', 'DatabaseAdmin'
        ]
        
        self.sample_policies = [
            'AdminPolicy', 'DevAccess', 'ReadOnlyAccess',
            'BackupPolicy', 'SecurityAuditPolicy', 'CustomPolicy1'
        ]
    
    def create_demo_findings_report(self) -> Dict[str, Any]:
        """Create comprehensive demo findings report"""
        print("🔑 Generating Demo IAM Security Findings...")
        
        demo_report = {
            'scan_metadata': {
                'scan_time': datetime.utcnow().isoformat(),
                'account_id': '123456789012',
                'entities_scanned': 25,
                'total_findings': 12
            },
            'findings': {
                'excessive_privileges': self._generate_excessive_privilege_findings(),
                'unused_credentials': self._generate_unused_credential_findings(),
                'security_risks': self._generate_security_risk_findings()
            },
            'risk_scores': self._generate_risk_scores(),
            'remediation_suggestions': self._generate_remediation_suggestions(),
            'summary': {
                'critical_findings': 2,
                'high_findings': 4,
                'medium_findings': 4,
                'low_findings': 2
            }
        }
        
        return demo_report
    
    def _generate_excessive_privilege_findings(self) -> List[Dict]:
        """Generate findings for excessive privileges"""
        return [
            {
                'entity_name': 'admin-user',
                'entity_type': 'user',
                'risk_level': 'CRITICAL',
                'finding_details': 'User has unrestricted administrative access',
                'affected_services': ['iam', 's3', 'ec2', 'rds', 'lambda'],
                'recommended_actions': [
                    'Implement least privilege access',
                    'Create specific role for required tasks',
                    'Remove unnecessary permissions'
                ]
            },
            {
                'entity_name': 'dev-user1',
                'entity_type': 'user',
                'risk_level': 'HIGH',
                'finding_details': 'Developer has broad access beyond development requirements',
                'affected_services': ['s3', 'dynamodb', 'lambda'],
                'recommended_actions': [
                    'Restrict access to development resources only',
                    'Remove production access',
                    'Implement environment-specific roles'
                ]
            }
        ]
    
    def _generate_unused_credential_findings(self) -> List[Dict]:
        """Generate findings for unused credentials"""
        return [
            {
                'entity_name': 'service-account1',
                'entity_type': 'user',
                'risk_level': 'MEDIUM',
                'finding_details': 'Access key unused for 90+ days',
                'last_used': (datetime.utcnow() - timedelta(days=95)).isoformat(),
                'recommended_actions': [
                    'Rotate access keys',
                    'Review service account necessity',
                    'Implement automated key rotation'
                ]
            },
            {
                'entity_name': 'temp-admin',
                'entity_type': 'user',
                'risk_level': 'HIGH',
                'finding_details': 'Temporary admin account still active',
                'creation_date': (datetime.utcnow() - timedelta(days=45)).isoformat(),
                'recommended_actions': [
                    'Delete temporary account',
                    'Review account creation process',
                    'Implement automatic cleanup'
                ]
            }
        ]
    
    def _generate_security_risk_findings(self) -> List[Dict]:
        """Generate findings for security risks"""
        return [
            {
                'entity_name': 'CustomPolicy1',
                'entity_type': 'policy',
                'risk_level': 'CRITICAL',
                'finding_details': 'Policy allows full access to all resources',
                'affected_resources': '*',
                'recommended_actions': [
                    'Review policy requirements',
                    'Implement resource restrictions',
                    'Use AWS managed policies where possible'
                ]
            },
            {
                'entity_name': 'BackupOperator',
                'entity_type': 'role',
                'risk_level': 'MEDIUM',
                'finding_details': 'Role has unnecessary permissions',
                'affected_services': ['ec2', 'rds'],
                'recommended_actions': [
                    'Restrict to backup-related actions only',
                    'Remove EC2 and RDS full access',
                    'Implement backup-specific policy'
                ]
            }
        ]
    
    def _generate_risk_scores(self) -> Dict[str, float]:
        """Generate risk scores for entities"""
        return {
            'admin-user': 95.0,
            'dev-user1': 85.0,
            'service-account1': 65.0,
            'temp-admin': 80.0,
            'CustomPolicy1': 90.0,
            'BackupOperator': 70.0
        }
    
    def _generate_remediation_suggestions(self) -> List[Dict]:
        """Generate remediation suggestions"""
        return [
            {
                'entity': 'admin-user',
                'priority': 'CRITICAL',
                'suggestion': 'Implement least privilege access model',
                'steps': [
                    'Review current access patterns',
                    'Create specific roles for daily tasks',
                    'Remove administrator access',
                    'Assign specific role-based permissions'
                ]
            },
            {
                'entity': 'CustomPolicy1',
                'priority': 'CRITICAL',
                'suggestion': 'Replace custom policy with restricted permissions',
                'steps': [
                    'Audit current policy usage',
                    'Identify required permissions',
                    'Create new restricted policy',
                    'Migrate users to new policy'
                ]
            },
            {
                'entity': 'dev-user1',
                'priority': 'HIGH',
                'suggestion': 'Restrict development environment access',
                'steps': [
                    'Create development-specific role',
                    'Remove production access',
                    'Implement environment separation'
                ]
            }
        ]

def generate_demo_report(output_file: str = 'entitlement_report.json'):
    """Generate and save demo findings report"""
    generator = IAMDemoGenerator()
    demo_report = generator.create_demo_findings_report()
    
    with open(output_file, 'w') as f:
        json.dump(demo_report, f, indent=2, default=str)
    
    print(f"✅ Demo IAM findings generated: {output_file}")
    print("📊 Demo Summary:")
    print(f"   - Critical Findings: {demo_report['summary']['critical_findings']}")
    print(f"   - High Findings: {demo_report['summary']['high_findings']}")
    print(f"   - Medium Findings: {demo_report['summary']['medium_findings']}")
    print(f"   - Low Findings: {demo_report['summary']['low_findings']}")
    
    return demo_report

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate Demo IAM Findings')
    parser.add_argument('--output', default='entitlement_report.json', help='Output file')
    
    args = parser.parse_args()
    generate_demo_report(args.output)