#!/usr/bin/env python3
"""
IAM Entitlement Scanner Utilities
Common helper functions and utilities for IAM analysis
"""

import json
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def normalize_action(action: str) -> str:
    """
    Normalize an IAM action name to lowercase for consistent comparison.
    
    Args:
        action: The IAM action name to normalize (e.g., 's3:GetObject')
        
    Returns:
        str: The normalized action name in lowercase (e.g., 's3:getobject')
    """
    if action is None:
        return None
    return str(action).lower()

# High-risk IAM actions that should be carefully controlled
RISKY_ACTIONS = {
    'iam': [
        'iam:PassRole',
        'iam:PutRolePolicy', 
        'iam:PutUserPolicy',
        'iam:CreateAccessKey',
        'iam:UpdateAccessKey',
        'iam:DeleteUserPolicy',
        'iam:AttachUserPolicy',
        'iam:DetachUserPolicy',
        'iam:CreateUser'
    ],
    's3': [
        's3:PutBucketPolicy',
        's3:PutBucketAcl',
        's3:PutBucketPublicAccessBlock',
        's3:DeleteBucketPolicy'
    ],
    'ec2': [
        'ec2:AuthorizeSecurityGroupIngress',
        'ec2:RevokeSecurityGroupIngress',
        'ec2:ModifyInstanceAttribute',
        'ec2:TerminateInstances'
    ],
    'kms': [
        'kms:Decrypt',
        'kms:Encrypt',
        'kms:GenerateDataKey',
        'kms:PutKeyPolicy'
    ],
    'lambda': [
        'lambda:UpdateFunctionCode',
        'lambda:InvokeFunction'
    ],
    'rds': [
        'rds:ModifyDBInstance',
        'rds:DeleteDBInstance'
    ]
}

# Administrative actions that typically indicate over-privilege
ADMIN_ACTIONS = [
    'iam:*',
    's3:*', 
    'ec2:*',
    'rds:*',
    'lambda:*',
    'kms:*',
    'cloudformation:*',
    'sts:AssumeRole',
    'organizations:*',
    'cloudtrail:*'
]

def is_high_risk_action(action: str) -> bool:
    """
    Check if an IAM action is considered high-risk.
    
    Args:
        action: The IAM action to check (e.g., 'iam:CreateUser')
        
    Returns:
        bool: True if the action is high-risk, False otherwise
    """
    # Guard invalid types or empty strings
    if not isinstance(action, str) or not action:
        return False

    action = normalize_action(action)

    # Explicit risky actions match only
    for service, actions in RISKY_ACTIONS.items():
        if any(normalize_action(a) == action for a in actions):
            return True

    return False

def get_actions_from_statement(statement: Dict) -> List[str]:
    """
    Extract all actions from a policy statement.
    
    Args:
        statement: The policy statement dictionary
        
    Returns:
        List[str]: List of action strings
    """
    if not isinstance(statement, dict):
        return []
        
    if statement.get('Effect') != 'Allow':
        return []
        
    actions = []
    if 'Action' in statement:
        action = statement['Action']
        if isinstance(action, str):
            actions.append(action)
        elif isinstance(action, list):
            actions.extend(action)
            
    if 'NotAction' in statement:
        not_action = statement['NotAction']
        if isinstance(not_action, str):
            actions.append(not_action)
        elif isinstance(not_action, list):
            actions.extend(not_action)
            
    return actions

def expand_action_wildcards(actions: List[str], service_prefix: str) -> List[str]:
    """
    Expand wildcard actions for a specific service.
    
    Args:
        actions: List of action patterns (may contain wildcards)
        service_prefix: The service prefix to filter by (e.g., 's3')
        
    Returns:
        List[str]: Expanded list of actions for the specified service
    """
    if not actions:
        return []
    
    # If service prefix is empty, pass through global wildcard if present
    if not service_prefix:
        return ['*'] if any(isinstance(a, str) and a == '*' for a in actions) else []
        
    service_actions = []
    for action in actions:
        if not isinstance(action, str):
            continue
            
        if action == '*':
            service_actions.append(f"{service_prefix}:*")
        elif action.startswith(f"{service_prefix}:") or action.startswith('*'):
            service_actions.append(action)
            
    return service_actions

def get_principal_type(principal: Any) -> str:
    """
    Determine the type of principal in a policy.
    
    Args:
        principal: The principal value from a policy
        
    Returns:
        str: The principal type ('AWS', 'Service', 'Federated', 'Wildcard', or 'Unknown')
    """
    if not principal:
        return 'Unknown'
        
    if isinstance(principal, str):
        if principal == '*':
            return 'Wildcard'
        return 'AWS'
        
    if isinstance(principal, dict):
        if 'AWS' in principal:
            return 'AWS'
        if 'Service' in principal:
            return 'Service'
        if 'Federated' in principal:
            return 'Federated'
            
    return 'Unknown'

def is_risky_principal(principal: Any) -> bool:
    """
    Check if a principal represents a potential security risk.
    
    Args:
        principal: The principal to check
        
    Returns:
        bool: True if the principal is considered risky, False otherwise
    """
    if not principal:
        return False
        
    if isinstance(principal, str):
        return principal in ('*', 'arn:aws:iam::*:root')
        
    if isinstance(principal, dict):
        aws_principal = principal.get('AWS')
        if isinstance(aws_principal, str):
            return aws_principal in ('*', 'arn:aws:iam::*:root')
        if isinstance(aws_principal, list):
            return any(p in ('*', 'arn:aws:iam::*:root') for p in aws_principal)
            
    return False

def get_used_actions(events: List[Dict]) -> set:
    """
    Extract unique IAM actions from CloudTrail events.
    
    Args:
        events: List of CloudTrail events
        
    Returns:
        set: Set of unique IAM actions found in the events
    """
    if not events:
        return set()
        
    used_actions = set()
    
    for event in events:
        if not isinstance(event, dict):
            continue
            
        event_source = event.get('eventSource', '')
        event_name = event.get('eventName', '')
        
        if not event_source or not event_name:
            continue
            
        # Convert service name to IAM action prefix (e.g., 's3.amazonaws.com' -> 's3')
        service = event_source.split('.')[0]
        action = f"{service}:{event_name}"
        used_actions.add(action)
    
    return used_actions

class IAMUtils:
    """Utility class for IAM operations and analysis"""
    
    # Expose constants as class attributes
    RISKY_ACTIONS = RISKY_ACTIONS
    ADMIN_ACTIONS = ADMIN_ACTIONS
    
    # Expose functions as class methods for backward compatibility
    normalize_action = staticmethod(normalize_action)
    is_high_risk_action = staticmethod(is_high_risk_action)
    get_actions_from_statement = staticmethod(get_actions_from_statement)
    expand_action_wildcards = staticmethod(expand_action_wildcards)
    get_principal_type = staticmethod(get_principal_type)
    is_risky_principal = staticmethod(is_risky_principal)
    get_used_actions = staticmethod(get_used_actions)
    
    @staticmethod
    def get_aws_session(profile: str = None, region: str = 'us-east-1'):
        """Create AWS session with optional profile and region"""
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            # Test the session
            sts = session.client('sts')
            sts.get_caller_identity()
            return session
        except Exception as e:
            logger.error(f"Failed to create AWS session: {e}")
            raise
    
    @staticmethod
    def get_account_id(session: boto3.Session) -> str:
        """Get AWS account ID from session"""
        sts = session.client('sts')
        return sts.get_caller_identity()['Account']
    
    @staticmethod
    def parse_arn(arn: str) -> Dict[str, str]:
        """Parse AWS ARN into components"""
        parts = arn.split(':')
        if len(parts) < 6:
            return {}
        
        return {
            'partition': parts[1],
            'service': parts[2],
            'region': parts[3],
            'account_id': parts[4],
            'resource': parts[5],
            'resource_type': parts[5].split('/')[0] if '/' in parts[5] else ''
        }
    
    @staticmethod
    def is_cross_account_arn(arn: str, current_account: str) -> bool:
        """Check if ARN represents cross-account access"""
        parsed = IAMUtils.parse_arn(arn)
        return parsed.get('account_id') and parsed['account_id'] != current_account
    
    @staticmethod
    def is_wildcard_resource(resources: List[str]) -> bool:
        """Check if resources list contains wildcards"""
        return any(resource == '*' for resource in resources)
    
    @staticmethod
    def calculate_risk_score(permissions: List[Dict], trust_issues: List[Dict] = None) -> int:
        """Calculate risk score based on permissions and trust relationships"""
        risk_score = 0
        
        # Base risk from permissions
        for perm in permissions:
            action = perm.get('action', '')
            
            # Check for admin actions
            if any(admin in action for admin in IAMUtils.ADMIN_ACTIONS):
                risk_score += 30
            
            # Check for risky actions
            for service, actions in IAMUtils.RISKY_ACTIONS.items():
                if any(risky in action for risky in actions):
                    risk_score += 20
                    break
            
            # Check for wildcard resources
            if IAMUtils.is_wildcard_resource(perm.get('resources', [])):
                risk_score += 15
        
        # Additional risk from trust issues
        if trust_issues:
            for issue in trust_issues:
                if issue.get('risk_level') == 'CRITICAL':
                    risk_score += 50
                elif issue.get('risk_level') == 'HIGH':
                    risk_score += 30
        
        return min(risk_score, 100)  # Cap at 100
    
    @staticmethod
    def normalize_policy_document(policy_doc: Dict) -> Dict:
        """Normalize policy document structure"""
        if not policy_doc:
            return {}
        
        normalized = {
            'Version': policy_doc.get('Version', '2012-10-17'),
            'Statement': []
        }
        
        statements = policy_doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for stmt in statements:
            normalized_stmt = {
                'Effect': stmt.get('Effect', 'Allow'),
                'Action': IAMUtils._normalize_actions(stmt.get('Action', [])),
                'Resource': IAMUtils._normalize_resources(stmt.get('Resource', ['*'])),
                'Condition': stmt.get('Condition', {})
            }
            
            # Handle NotAction, NotResource if present
            if 'NotAction' in stmt:
                normalized_stmt['NotAction'] = IAMUtils._normalize_actions(stmt['NotAction'])
            if 'NotResource' in stmt:
                normalized_stmt['NotResource'] = IAMUtils._normalize_resources(stmt['NotResource'])
            
            # Handle Principal for trust policies
            if 'Principal' in stmt:
                normalized_stmt['Principal'] = stmt['Principal']
            
            normalized['Statement'].append(normalized_stmt)
        
        return normalized
    
    @staticmethod
    def _normalize_actions(actions) -> List[str]:
        """Normalize actions to list format"""
        if isinstance(actions, str):
            return [actions]
        elif isinstance(actions, list):
            return actions
        return []
    
    @staticmethod
    def _normalize_resources(resources) -> List[str]:
        """Normalize resources to list format"""
        if isinstance(resources, str):
            return [resources]
        elif isinstance(resources, list):
            return resources
        return ['*']
    
    @staticmethod
    def extract_all_permissions(policies: List[Dict]) -> List[Dict]:
        """Extract all permissions from policy documents"""
        all_permissions = []
        
        for policy in policies:
            normalized = IAMUtils.normalize_policy_document(policy)
            
            for statement in normalized.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', ['*'])
                    conditions = statement.get('Condition', {})
                    
                    for action in actions:
                        all_permissions.append({
                            'action': action,
                            'resources': resources,
                            'conditions': conditions,
                            'statement': statement
                        })
        
        return all_permissions
    
    @staticmethod
    def analyze_trust_policy(trust_policy: Dict, current_account: str) -> List[Dict]:
        """Analyze IAM trust policy for security issues"""
        issues = []
        
        if not trust_policy:
            return issues
        
        normalized = IAMUtils.normalize_policy_document(trust_policy)
        
        for statement in normalized.get('Statement', []):
            principal = statement.get('Principal', {})
            
            # Check AWS account principals
            if 'AWS' in principal:
                aws_principals = IAMUtils._normalize_principals(principal['AWS'])
                
                for principal_arn in aws_principals:
                    if principal_arn == '*':
                        issues.append({
                            'principal': principal_arn,
                            'issue': 'Trusts all AWS principals (wildcard)',
                            'risk_level': 'CRITICAL'
                        })
                    elif ':root' in principal_arn:
                        if IAMUtils.is_cross_account_arn(principal_arn, current_account):
                            issues.append({
                                'principal': principal_arn,
                                'issue': 'Trusts external AWS account root',
                                'risk_level': 'CRITICAL'
                            })
                        else:
                            issues.append({
                                'principal': principal_arn,
                                'issue': 'Trusts own AWS account root',
                                'risk_level': 'HIGH'
                            })
                    elif IAMUtils.is_cross_account_arn(principal_arn, current_account):
                        issues.append({
                            'principal': principal_arn,
                            'issue': 'Cross-account trust to specific principal',
                            'risk_level': 'HIGH'
                        })
            
            # Check service principals
            if 'Service' in principal:
                service_principals = IAMUtils._normalize_principals(principal['Service'])
                
                for service in service_principals:
                    if service == '*':
                        issues.append({
                            'principal': service,
                            'issue': 'Trusts all AWS services (wildcard)',
                            'risk_level': 'CRITICAL'
                        })
                    elif '.amazonaws.com' in service and service != 'ec2.amazonaws.com':
                        # More permissive than EC2
                        issues.append({
                            'principal': service,
                            'issue': f'Trusts AWS service: {service}',
                            'risk_level': 'MEDIUM'
                        })
            
            # Check federated principals
            if 'Federated' in principal:
                federated_principals = IAMUtils._normalize_principals(principal['Federated'])
                
                for fed in federated_principals:
                    if fed == '*':
                        issues.append({
                            'principal': fed,
                            'issue': 'Trusts all identity providers (wildcard)',
                            'risk_level': 'CRITICAL'
                        })
        
        return issues
    
    @staticmethod
    def _normalize_principals(principals) -> List[str]:
        """Normalize principals to list format"""
        if isinstance(principals, str):
            return [principals]
        elif isinstance(principals, list):
            return principals
        return []
    
    @staticmethod
    def format_timestamp(timestamp: datetime) -> str:
        """Format datetime for JSON serialization"""
        return timestamp.isoformat() if timestamp else None
    
    @staticmethod
    def days_since_creation(create_date: datetime) -> int:
        """Calculate days since entity creation"""
        return (datetime.utcnow() - create_date.replace(tzinfo=None)).days
    
    @staticmethod
    def save_json(data: Dict, filename: str) -> None:
        """Save data as JSON file with proper serialization"""
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=json_serializer)
    
    @staticmethod
    def load_json(filename: str) -> Dict:
        """Load data from JSON file"""
        with open(filename, 'r') as f:
            return json.load(f)

class RiskCalculator:
    """Advanced risk calculation utilities"""
    
    @staticmethod
    def calculate_entity_risk(entity_data: Dict) -> Dict:
        """Calculate comprehensive risk assessment for an entity"""
        permissions = entity_data.get('permissions', [])
        trust_issues = entity_data.get('trust_issues', [])
        usage_info = entity_data.get('usage', {})
        
        base_score = IAMUtils.calculate_risk_score(permissions, trust_issues)
        
        # Adjust based on usage patterns
        if not usage_info.get('recent_activity', True):
            base_score += 10  # Unused entities are higher risk
        
        if usage_info.get('admin_activity', False):
            base_score += 20  # Entities with admin activity
        
        # Categorize risk level
        if base_score >= 80:
            risk_level = 'CRITICAL'
        elif base_score >= 60:
            risk_level = 'HIGH'
        elif base_score >= 40:
            risk_level = 'MEDIUM'
        elif base_score >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'score': base_score,
            'level': risk_level,
            'factors': RiskCalculator._get_risk_factors(permissions, trust_issues, usage_info)
        }
    
    @staticmethod
    def _get_risk_factors(permissions: List, trust_issues: List, usage_info: Dict) -> List[str]:
        """Identify specific risk factors"""
        factors = []
        
        # Permission-based factors
        admin_actions = [p for p in permissions if any(admin in p.get('action', '') 
                       for admin in IAMUtils.ADMIN_ACTIONS)]
        if admin_actions:
            factors.append(f"Has {len(admin_actions)} administrative permissions")
        
        risky_actions = [p for p in permissions if any(any(risky in p.get('action', '') 
                        for risky in risky_list) for risky_list in IAMUtils.RISKY_ACTIONS.values())]
        if risky_actions:
            factors.append(f"Has {len(risky_actions)} risky permissions")
        
        wildcard_resources = [p for p in permissions if IAMUtils.is_wildcard_resource(p.get('resources', []))]
        if wildcard_resources:
            factors.append(f"Uses wildcard resources in {len(wildcard_resources)} permissions")
        
        # Trust-based factors
        if trust_issues:
            critical_trust = [t for t in trust_issues if t.get('risk_level') == 'CRITICAL']
            if critical_trust:
                factors.append(f"Has {len(critical_trust)} critical trust issues")
        
        # Usage-based factors
        if not usage_info.get('recent_activity', True):
            factors.append("No recent activity detected")
        
        return factors