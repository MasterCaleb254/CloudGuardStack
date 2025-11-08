# tests/integration/test_iam_remediation_generator.py
import pytest
import json
import unittest
from unittest.mock import patch, MagicMock, mock_open
from botocore.exceptions import ClientError
from scanners.iam_entitlement.remediation_generator import RemediationGenerator

@pytest.fixture
def iam_remediator():
    """Create a RemediationGenerator instance for testing."""
    # Create a generator with a mock entitlement report
    generator = RemediationGenerator(entitlement_report={
        'findings': {},
        'risk_scores': {}
    })
    
    # Mock boto3 clients
    generator.iam = MagicMock()
    generator.organizations = MagicMock()
    
    return generator

class IAMPolicy:
    """Simple IAM Policy class for testing purposes."""
    def __init__(self, Version: str, Statement: list):
        self.Version = Version
        self.Statement = Statement
    
    def to_json(self) -> str:
        """Convert policy to JSON string."""
        return json.dumps({
            'Version': self.Version,
            'Statement': self.Statement
        }, indent=2)


def test_iam_policy_to_json():
    """Test IAMPolicy to JSON conversion."""
    policy = IAMPolicy(
        Version="2012-10-17",
        Statement=[{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
    )
    
    result = policy.to_json()
    assert '"Version": "2012-10-17"' in result
    assert '"Effect": "Allow"' in result
    assert '"Action": "s3:GetObject"' in result

def test_generate_least_privilege_policy(iam_remediator):
    """Test generating a least privilege policy."""
    current_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': ['s3:*', 'ec2:*'],
                'Resource': '*'
            }
        ]
    }
    
    used_actions = ['s3:GetObject', 's3:ListBucket']
    
    result = iam_remediator.generate_least_privilege_policy(
        current_policy=current_policy,
        used_actions=used_actions
    )
    
    assert 'Version' in result
    assert 'Statement' in result
    assert isinstance(result['Statement'], list)

def test_create_remediation_plan(iam_remediator):
    """Test creating a remediation plan from findings."""
    findings = [
        {
            'id': 'finding-1',
            'type': 'excessive_permissions',
            'resource_arn': 'arn:aws:iam::123456789012:role/TestRole',
            'details': {
                'permissions': ['s3:*', 'ec2:*'],
                'used_permissions': ['s3:GetObject', 's3:ListBucket']
            }
        }
    ]
    
    plan = iam_remediator.create_remediation_plan(findings)
    
    assert 'remediations' in plan
    assert 'timestamp' in plan  # Changed from 'version' to 'timestamp'
    assert isinstance(plan['remediations'], list)

def test_apply_remediation_plan(iam_remediator):
    """Test applying a remediation plan."""
    plan = {
        'version': '2023-01-01',
        'remediations': [
            {
                'type': 'update_iam_policy',
                'resource_arn': 'arn:aws:iam::123456789012:policy/TestPolicy',
                'current_policy': {'Version': '2012-10-17', 'Statement': []},
                'recommended_policy': {'Version': '2012-10-17', 'Statement': []},
                'changes_made': {'permissions_removed': True}
            }
        ]
    }
    
    # Mock the IAM client
    iam_remediator.iam.update_policy = MagicMock(return_value={'Policy': {'Arn': 'test-arn'}})
    
    results = iam_remediator.apply_remediation_plan(plan, dry_run=True)
    
    assert isinstance(results, list)
    assert len(results) == 1
    assert 'status' in results[0]
    assert 'entity_arn' in results[0]  # Changed from 'resource_arn' to 'entity_arn'

def test_generate_terraform_templates(iam_remediator, tmp_path):
    """Test generating Terraform templates."""
    # Setup test data with role_name to avoid None.replace() error
    iam_remediator.entitlement_report = {
        'findings': {
            'over_privileged_roles': [
                {
                    'role_name': 'TestRole',
                    'role_arn': 'arn:aws:iam::123456789012:role/TestRole',
                    'excessive_permissions': ['s3:DeleteBucket', 'ec2:TerminateInstances'],
                    'used_permissions': ['s3:GetObject', 's3:ListBucket']
                }
            ],
            'excessive_trust': [
                {
                    'role_name': 'TestRole',
                    'role_arn': 'arn:aws:iam::123456789012:role/TestRole',
                    'trusted_entities': ['*']
                }
            ],
            'unused_roles': [
                {
                    'role_name': 'UnusedRole',
                    'role_arn': 'arn:aws:iam::123456789012:role/UnusedRole',
                    'last_used': '2022-01-01T00:00:00Z'
                }
            ]
        }
    }
    
    # Test generating templates
    output_dir = tmp_path / "templates"
    output_dir.mkdir(exist_ok=True)
    
    # Mock the file writing to avoid actual file I/O
    with patch('builtins.open', mock_open()) as mock_file:
        iam_remediator.generate_terraform_templates(output_dir=str(output_dir))
        
        # Check if the files would have been created
        assert mock_file.call_count >= 3  # At least 3 files should be created

def test_generate_remediation_report(iam_remediator, tmp_path):
    """Test generating a remediation report."""
    # Setup test data
    iam_remediator.entitlement_report = {
        'findings': {
            'over_privileged_roles': [
                {
                    'role_arn': 'arn:aws:iam::123456789012:role/TestRole',
                    'excessive_permissions': ['s3:DeleteBucket'],
                    'used_permissions': ['s3:GetObject']
                }
            ]
        },
        'risk_scores': {
            'high': 1,
            'medium': 0,
            'low': 0
        }
    }
    
    # Test generating report
    report_path = tmp_path / "remediation_plan.md"
    
    # Mock the file writing to avoid actual file I/O
    with patch('builtins.open', mock_open()) as mock_file:
        iam_remediator.generate_remediation_report(output_file=str(report_path))
        
        # Check if the file would have been created with the correct content
        assert any("IAM Entitlement Remediation Plan" in str(call) for call in mock_file.mock_calls)

def test_error_handling(iam_remediator, tmp_path):
    """Test error handling during remediation."""
    # Test with invalid policy format
    with pytest.raises(ValueError, match="Invalid policy format"):
        iam_remediator.generate_least_privilege_policy(
            current_policy={"invalid": "policy"},
            used_actions=['s3:GetObject']
        )
    
    # Test with valid policy but IAM error
    mock_iam = iam_remediator.iam
    
    # Setup the mock to raise ClientError on get_role_policy
    mock_iam.get_role_policy = MagicMock()
    mock_iam.get_role_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchEntity'}},
        'GetRolePolicy'
    )
    
    # Create a plan that will trigger the get_role_policy call
    plan = {
        'remediations': [{
            'entity_name': 'TestRole',
            'entity_arn': 'arn:aws:iam::123456789012:role/TestRole',
            'actions': [{
                'type': 'update_policy',
                'policy_name': 'TestPolicy',
                'used_actions': ['s3:GetObject']
            }]
        }]
    }
    
    # Apply the remediation plan
    results = iam_remediator.apply_remediation_plan(
        plan=plan,
        dry_run=False
    )
    
    # Verify the result contains the expected error
    assert len(results) == 1
    assert results[0]['status'] == 'error'
    assert 'NoSuchEntity' in results[0]['error']
    assert len(results[0]['actions']) == 1
    assert results[0]['actions'][0]['status'] == 'error'
    assert 'NoSuchEntity' in results[0]['actions'][0]['error']
    
    # Verify the mock was called
    mock_iam.get_role_policy.assert_called_once_with(
        RoleName='TestRole',
        PolicyName='TestPolicy'
    )

def test_notaction_preserved(iam_remediator):
    """Test that NotAction is preserved in policy generation."""
    # Test with a policy containing NotAction
    policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'NotAction': 'ec2:*',
                'Resource': '*'
            }
        ]
    }
    
    # This should preserve the NotAction in the generated policy
    result = iam_remediator.generate_least_privilege_policy(
        current_policy=policy,
        used_actions=['s3:GetObject']  # This won't affect NotAction statements
    )
    
    # The NotAction should be preserved as-is
    assert 'Statement' in result
    assert len(result['Statement']) == 1
    assert 'NotAction' in result['Statement'][0]
    assert result['Statement'][0]['NotAction'] == 'ec2:*'

def test_normalize_actions(iam_remediator):
    """Test action normalization."""
    # Test with None
    assert iam_remediator._normalize_actions(None) == []
    
    # Test with string
    assert iam_remediator._normalize_actions('s3:GetObject') == ['s3:GetObject']
    
    # Test with list
    assert iam_remediator._normalize_actions(['s3:GetObject', 's3:PutObject']) == ['s3:GetObject', 's3:PutObject']
