#!/usr/bin/env python3
"""
CloudGuardStack IAM Entitlement Scanner
Detects over-privileged principals, unused roles, and excessive trust relationships
"""

import json
import boto3
from botocore.exceptions import ClientError
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Union
import argparse
import sys
import os


class IAMEntitlementScanner:
    def __init__(self, profile: str = None, region: str = 'us-east-1'):
        """Initialize the IAM scanner with AWS session"""
        try:
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self.iam = self.session.client('iam')
            self.cloudtrail = self.session.client('cloudtrail')
            self.access_analyzer = self.session.client('accessanalyzer')
            self.s3 = self.session.client('s3')
        except Exception as e:
            print(f"⚠️ AWS session initialization failed (mocking clients): {e}")
            self.session = None
            self.iam = self.cloudtrail = self.access_analyzer = self.s3 = None

        self.findings = {
            'over_privileged_roles': [],
            'unused_roles': [],
            'excessive_trust': [],
            'risky_permissions': [],
            'cross_account_risks': [],
            'sensitive_data_findings': []
        }

        self.risk_scores = {}
        self.logger = None  # placeholder, fallback to print
        self.analyzed_roles = set()  # Track which roles have been analyzed

    # ------------------------------------------------------------
    # Core IAM Scanning Methods
    # ------------------------------------------------------------

    def _get_all_roles(self) -> List[Dict[str, Any]]:
        """Retrieve all IAM roles with pagination support."""
        roles = []
        marker = None
        if not self.iam:
            print("⚠️ No IAM client available (mock mode). Returning empty list.")
            return roles
        try:
            while True:
                if marker:
                    response = self.iam.list_roles(Marker=marker)
                else:
                    response = self.iam.list_roles()
                roles.extend(response.get('Roles', []))
                if response.get('IsTruncated'):
                    marker = response['Marker']
                else:
                    break
        except Exception as e:
            print(f"⚠️ Error retrieving IAM roles: {str(e)}")
        return roles

    def _get_attached_policies(self, resource_name: str, resource_type: str = 'Role') -> List[Dict[str, Any]]:
        """Get all attached policies for an IAM Role/User/Group."""
        if not self.iam:
            print(f"⚠️ IAM client unavailable while getting attached policies for {resource_type} {resource_name}")
            return []

        try:
            if resource_type == 'Role':
                response = self.iam.list_attached_role_policies(RoleName=resource_name)
            elif resource_type == 'User':
                response = self.iam.list_attached_user_policies(UserName=resource_name)
            else:
                response = self.iam.list_attached_group_policies(GroupName=resource_name)

            attached = []
            for p in response.get('AttachedPolicies', []):
                try:
                    version = self.iam.get_policy_version(
                        PolicyArn=p['PolicyArn'],
                        VersionId=self.iam.get_policy(PolicyArn=p['PolicyArn'])['Policy']['DefaultVersionId']
                    )
                    attached.append({
                        'PolicyName': p['PolicyName'],
                        'PolicyArn': p['PolicyArn'],
                        'PolicyDocument': version['PolicyVersion']['Document']
                    })
                except Exception as e:
                    print(f"⚠️ Could not retrieve full policy {p['PolicyName']}: {e}")
                    attached.append({'PolicyName': p['PolicyName'], 'PolicyArn': p['PolicyArn'], 'PolicyDocument': {}})
            return attached
        except Exception as e:
            print(f"⚠️ Error getting attached policies for {resource_type} {resource_name}: {str(e)}")
            return []

    def _get_inline_policies(self, resource_name: str, resource_type: str = 'Role') -> Dict[str, Dict]:
        """Get inline policies for a Role/User/Group."""
        if not self.iam:
            print(f"⚠️ IAM client unavailable while getting inline policies for {resource_type} {resource_name}")
            return {}

        policies = {}
        try:
            if resource_type == 'Role':
                names = self.iam.list_role_policies(RoleName=resource_name).get('PolicyNames', [])
                for n in names:
                    doc = self.iam.get_role_policy(RoleName=resource_name, PolicyName=n).get('PolicyDocument', {})
                    policies[n] = doc
            elif resource_type == 'User':
                names = self.iam.list_user_policies(UserName=resource_name).get('PolicyNames', [])
                for n in names:
                    doc = self.iam.get_user_policy(UserName=resource_name, PolicyName=n).get('PolicyDocument', {})
                    policies[n] = doc
            else:
                names = self.iam.list_group_policies(GroupName=resource_name).get('PolicyNames', [])
                for n in names:
                    doc = self.iam.get_group_policy(GroupName=resource_name, PolicyName=n).get('PolicyDocument', {})
                    policies[n] = doc
        except Exception as e:
            print(f"⚠️ Error retrieving inline policies for {resource_type} {resource_name}: {e}")
        return policies

    def scan_role(self, role_name: str, start_time: datetime) -> dict:
        """
        Scan a single IAM role and return findings.
        
        Args:
            role_name: Name of the IAM role to scan
            start_time: Start time for activity analysis
            
        Returns:
            dict: Scan results including findings, policies, and trust relationships
        """
        if not self.iam:
            return {'error': 'IAM client not initialized'}
            
        try:
            # Get role details
            role = self.iam.get_role(RoleName=role_name)
            self.analyzed_roles.add(role_name)  # Only add to analyzed_roles if role exists
            role_arn = role['Role']['Arn']
            
            # Get trust relationship policy
            trust_policy = role['Role'].get('AssumeRolePolicyDocument', {})
            
            # Get attached policies
            attached_policies = self._get_attached_policies(role_name, 'Role')
            
            # Get inline policies
            inline_policies = self._get_inline_policies(role_name, 'Role')
            
            # Analyze policies and trust relationships
            findings = []
            
            # Analyze trust policy if it exists
            if trust_policy:
                trust_findings = self._analyze_trust_policy(trust_policy, role_name)
                findings.extend(trust_findings)
            
            # Analyze attached and inline policies
            for policy in attached_policies + [{'PolicyName': k, 'PolicyDocument': v} for k, v in inline_policies.items()]:
                if 'PolicyDocument' in policy:
                    findings.extend(self._analyze_policy_document(policy['PolicyDocument'], role_name))
            
            # Get CloudTrail events if available
            events = []
            if self.cloudtrail:
                events = self._get_cloudtrail_events(role_name, start_time, datetime.now(timezone.utc))
            
            # Build result dictionary
            result = {
                'role_name': role_name,
                'arn': role_arn,
                'findings': findings,
                'policies': {
                    'attached': [p['PolicyName'] for p in attached_policies],
                    'inline': list(inline_policies.keys())
                },
                'activity': {
                    'event_count': len(events),
                    'last_activity': max([e['EventTime'] for e in events], default=None) if events else None
                }
            }
            
            # Add trust relationship if it exists
            if trust_policy:
                result['trust_relationship'] = trust_policy
                
            return result
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return {'error': f'Role {role_name} does not exist', 'details': str(e)}
            return {'error': f'Error scanning role {role_name}: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error scanning role {role_name}: {str(e)}'}
    
    def _analyze_trust_policy(self, trust_policy: dict, role_name: str) -> list:
        """
        Analyze a trust relationship policy for potential security issues.
        
        Args:
            trust_policy: The trust policy document to analyze
            role_name: Name of the role the policy is attached to
            
        Returns:
            list: List of findings related to the trust policy
        """
        findings = []
        
        if not isinstance(trust_policy, dict) or 'Statement' not in trust_policy:
            return findings
            
        statements = trust_policy['Statement']
        if not isinstance(statements, list):
            statements = [statements]
            
        for i, statement in enumerate(statements):
            effect = statement.get('Effect', 'Allow')
            principal = statement.get('Principal', {})
            
            # Check for wildcard principals
            if principal == '*' or (isinstance(principal, dict) and any(v == '*' for v in principal.values())):
                findings.append({
                    'severity': 'HIGH',
                    'issue': 'Wildcard principal in trust policy',
                    'statement': f'Trust Statement {i+1}',
                    'description': 'Trust policy allows any principal to assume the role',
                    'effect': effect
                })
                
            # Check for federated users (SAML, OIDC, etc.)
            if isinstance(principal, dict) and 'Federated' in principal:
                findings.append({
                    'severity': 'MEDIUM',
                    'issue': 'Federated trust relationship',
                    'statement': f'Trust Statement {i+1}',
                    'description': f'Role can be assumed by federated users: {principal["Federated"]}',
                    'effect': effect
                })
                
            # Check for service principals
            if isinstance(principal, dict) and 'Service' in principal:
                service = principal['Service']
                if not isinstance(service, list):
                    service = [service]
                    
                for svc in service:
                    findings.append({
                        'severity': 'LOW',
                        'issue': 'Service principal in trust policy',
                        'statement': f'Trust Statement {i+1}',
                        'description': f'Role can be assumed by AWS service: {svc}',
                        'effect': effect,
                        'service': svc
                    })
        
        return findings

    def _analyze_policy_document(self, policy_doc: dict, role_name: str) -> list:
        """
        Analyze an IAM policy document for potential issues.
        
        Args:
            policy_doc: The IAM policy document to analyze
            role_name: Name of the role this policy is attached to
            
        Returns:
            list: List of findings with details about potential issues
        """
        findings = []
        
        if not isinstance(policy_doc, dict) or 'Statement' not in policy_doc:
            return findings
            
        statements = policy_doc['Statement']
        if not isinstance(statements, list):
            statements = [statements]
            
        for i, statement in enumerate(statements, 1):
            if not isinstance(statement, dict):
                continue
                
            effect = statement.get('Effect', 'Allow')
            actions = self._get_actions_from_statement(statement)
            resources = statement.get('Resource', [])
            conditions = statement.get('Condition', {})
            
            if not isinstance(resources, list):
                resources = [resources]
                
            # Check for wildcard actions
            if '*' in actions:
                findings.append({
                    'severity': 'HIGH',
                    'issue': 'Wildcard action',
                    'statement': f'Statement {i}',
                    'description': f'Policy allows all actions with {effect} effect',
                    'effect': effect,
                    'action': '*',
                    'resource': resources[0] if len(resources) == 1 else resources,
                    'role': role_name
                })
            
            # Check for wildcard resources
            wildcard_resources = [r for r in resources if r == '*' or r == 'arn:aws:*' or (isinstance(r, str) and (r.endswith('*') or ':*/' in r))]
            if wildcard_resources:
                findings.append({
                    'severity': 'HIGH',
                    'issue': 'Wildcard resource',
                    'statement': f'Statement {i}',
                    'description': f'Policy allows access to {len(wildcard_resources)} wildcard resources with {effect} effect',
                    'effect': effect,
                    'action': actions[0] if len(actions) == 1 else actions,
                    'resource': wildcard_resources[0] if len(wildcard_resources) == 1 else wildcard_resources,
                    'role': role_name
                })
            
            # Check for specific resource constraints (non-wildcard resources)
            specific_resources = [r for r in resources if r not in wildcard_resources and r]
            if specific_resources:
                findings.append({
                    'severity': 'LOW',
                    'issue': 'Specific resource constraint',
                    'statement': f'Statement {i}',
                    'description': f'Policy has specific resource constraints with {effect} effect',
                    'effect': effect,
                    'action': actions[0] if len(actions) == 1 else actions,
                    'resource': specific_resources[0] if len(specific_resources) == 1 else specific_resources,
                    'role': role_name
                })
                
            # Check for conditions
            if conditions:
                findings.append({
                    'severity': 'MEDIUM',
                    'issue': 'Conditional statement',
                    'statement': f'Statement {i}',
                    'description': f'Policy has conditional {effect} statement',
                    'effect': effect,
                    'condition': conditions,
                    'action': actions[0] if len(actions) == 1 else actions,
                    'resource': resources[0] if len(resources) == 1 else resources,
                    'role': role_name
                })
                
            # Check for deny statements
            if effect == 'Deny':
                findings.append({
                    'severity': 'INFO',
                    'issue': 'Deny statement',
                    'statement': f'Statement {i}',
                    'description': 'Policy contains an explicit deny statement',
                    'effect': effect,
                    'action': actions[0] if len(actions) == 1 else actions,
                    'resource': resources[0] if len(resources) == 1 else resources,
                    'role': role_name
                })
                
        return findings

    def _get_cloudtrail_events(self, role_name: str, start_time: datetime, end_time: datetime) -> list:
        """
        Get CloudTrail events for a role within a time range.
        
        Args:
            role_name: Name of the IAM role
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            list: List of CloudTrail events
        """
        if not self.cloudtrail:
            return []
            
        try:
            response = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'ResourceName', 'AttributeValue': role_name}
                ],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            )
            return response.get('Events', [])
        except Exception as e:
            print(f"⚠️ Error getting CloudTrail events for {role_name}: {e}")
            return []
            
    def scan_all_roles(self, start_time: datetime):
        """
        Scan all IAM roles and yield results for each one.
        
        Args:
            start_time: Start time for activity analysis
            
        Yields:
            dict: Scan result for each role
        """
        try:
            # Get all IAM roles
            roles = self._get_all_roles()
            
            # Scan each role that hasn't been analyzed yet
            for role in roles:
                role_name = role['RoleName']
                if role_name not in self.analyzed_roles:
                    yield self.scan_role(role_name, start_time)
                    
        except Exception as e:
            print(f"⚠️ Error scanning all roles: {e}")
            yield {'error': f'Error scanning all roles: {str(e)}'}

    def find_unused_roles(self, days_threshold: int = 90) -> None:
        """Find IAM roles not used recently."""
        print(f"🔍 Checking for roles unused for {days_threshold} days...")
        roles = self._get_all_roles()
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_threshold)

        for role in roles:
            last_used = self._get_role_last_used(role, cutoff_date)
            if last_used is None or last_used < cutoff_date:
                self.findings['unused_roles'].append({
                    'RoleName': role['RoleName'],
                    'Arn': role['Arn'],
                    'LastUsed': last_used.isoformat() if last_used else 'Never',
                    'DaysUnused': (datetime.now(timezone.utc) - last_used).days if last_used else 'Unknown'
                })
        print(f"✅ Found {len(self.findings['unused_roles'])} unused roles")

    def _get_role_last_used(self, role: dict, cutoff_date: datetime) -> Optional[datetime]:
        """Get the last used timestamp for a role."""
        role_name = role['RoleName']
        if 'RoleLastUsed' in role and 'LastUsedDate' in role['RoleLastUsed']:
            return role['RoleLastUsed']['LastUsedDate']

        if not self.cloudtrail:
            print(f"⚠️ No CloudTrail client available (mock mode) for {role_name}")
            return None

        try:
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[{'AttributeKey': 'ResourceName', 'AttributeValue': role_name}],
                StartTime=cutoff_date,
                EndTime=datetime.now(timezone.utc),
                MaxResults=1
            )
            if events.get('Events'):
                return events['Events'][0]['EventTime']
        except Exception as e:
            print(f"⚠️ Error checking CloudTrail for {role_name}: {str(e)}")
        return None

    def detect_over_privileged_roles(self) -> None:
        """Detect IAM roles with excessive permissions."""
        print("🔍 Scanning for over-privileged roles...")
        for role in self._get_all_roles():
            role_name = role['RoleName']
            risky_permissions = self._find_risky_permissions(role_name)
            if risky_permissions:
                self.findings['over_privileged_roles'].append({
                    'RoleName': role_name,
                    'Arn': role['Arn'],
                    'RiskyPermissions': risky_permissions
                })
        print(f"✅ Found {len(self.findings['over_privileged_roles'])} over-privileged roles")

    def _find_risky_permissions(self, role_name: str) -> list:
        """Find risky permissions in a role's policies."""
        risky_permissions = []
        for policy in self._get_attached_policies(role_name, 'Role'):
            risky_permissions.extend(
                self._check_policy_for_risky_actions(
                    policy.get('PolicyDocument', {}),
                    policy.get('PolicyName', 'Unknown'),
                    'Attached'
                )
            )
        for policy_name, policy_doc in self._get_inline_policies(role_name, 'Role').items():
            risky_permissions.extend(
                self._check_policy_for_risky_actions(policy_doc, policy_name, 'Inline')
            )
        return risky_permissions

    def _check_policy_for_risky_actions(self, policy_doc: dict, policy_name: str, policy_type: str) -> list:
        """Check policy for risky actions."""
        risky_permissions = []
        HIGH_RISK_ACTIONS = [
            '*', 'iam:*', 's3:*', 'ec2:*', 'rds:*', 'lambda:*',
            'cloudformation:*', 'sts:AssumeRole*', 'secretsmanager:*', 'kms:*'
        ]
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = self._get_actions_from_statement(statement)
                for action in actions:
                    if any(self._matches_wildcard(action, pattern) for pattern in HIGH_RISK_ACTIONS):
                        risky_permissions.append({
                            'Action': action,
                            'Resource': statement.get('Resource', '*'),
                            'PolicyType': policy_type,
                            'PolicyName': policy_name
                        })
        return risky_permissions

    def _get_actions_from_statement(self, statement: dict) -> list:
        actions = statement.get('Action', [])
        return [actions] if isinstance(actions, str) else actions

    def _matches_wildcard(self, action: str, pattern: str) -> bool:
        if pattern == '*':
            return True
        pattern_parts = pattern.lower().split(':')
        action_parts = action.lower().split(':')
        if len(pattern_parts) != len(action_parts):
            return False
        for p, a in zip(pattern_parts, action_parts):
            if p == '*' or p == a:
                continue
            return False
        return True

    # ------------------------------------------------------------
    # Sensitive Data Scanning
    # ------------------------------------------------------------

    def _scan_s3_bucket_for_sensitive_data(self, bucket_name: str) -> List[Dict[str, Any]]:
        print(f"🔍 Scanning bucket {bucket_name} for sensitive data...")
        return []  # placeholder

    def scan_for_sensitive_data(self, buckets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_findings = []
        for bucket in buckets:
            bucket_name = bucket.get('name')
            if not bucket_name:
                continue
            try:
                findings = self._scan_s3_bucket_for_sensitive_data(bucket_name)
                all_findings.extend(findings)
                self.findings['sensitive_data_findings'].extend(findings)
            except Exception as e:
                print(f"⚠️ Error scanning {bucket_name} for sensitive data: {str(e)}")
        return all_findings

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    def scan(self) -> Dict[str, Any]:
        print("🚀 Starting IAM entitlement scan...")
        self.find_unused_roles(days_threshold=90)
        self.detect_over_privileged_roles()
        print("✅ Scan completed.")
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'findings': self.findings,
            'summary': {
                'total_risks': sum(len(v) for v in self.findings.values()),
                'unused_roles': len(self.findings['unused_roles']),
                'over_privileged_roles': len(self.findings['over_privileged_roles']),
                'excessive_trust': len(self.findings['excessive_trust']),
                'risky_permissions': len(self.findings['risky_permissions']),
                'cross_account_risks': len(self.findings['cross_account_risks']),
                'sensitive_data_findings': len(self.findings['sensitive_data_findings'])
            }
        }
        return report


# ------------------------------------------------------------
# CLI Entry Point
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='IAM Entitlement Scanner')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', default='entitlement_report.json', help='Output file')
    parser.add_argument('--generate-visualization', action='store_true', help='Generate privilege visualization')
    args = parser.parse_args()

    scanner = IAMEntitlementScanner(profile=args.profile, region=args.region)
    report = scanner.scan()

    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"✅ IAM Entitlement Scan Complete!")
    print(f"📄 Report saved to: {args.output}")
    print(f"📊 Summary: {report['summary']}")

    if args.generate_visualization:
        from visualizer import PrivilegeVisualizer
        visualizer = PrivilegeVisualizer(entitlement_report=report)
        visualizer.generate_visualizations()


if __name__ == '__main__':
    main()
