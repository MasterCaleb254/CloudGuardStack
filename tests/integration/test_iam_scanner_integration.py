# tests/integration/test_iam_scanner.py
import pytest
import boto3
from botocore.stub import Stubber
from datetime import datetime, timedelta
import json
from unittest.mock import patch, MagicMock
from scanners.iam_entitlement.scanner import IAMScanner

@pytest.fixture
def iam_scanner():
    """Create an IAMScanner instance with a stubbed boto3 session."""
    with patch('boto3.Session') as mock_session:
        # Create mock AWS clients
        mock_iam = MagicMock()
        mock_orgs = MagicMock()
        mock_sts = MagicMock()
        
        # Configure session to return mock clients
        mock_session.return_value.client.side_effect = [
            mock_iam,   # iam client
            mock_orgs,  # organizations client
            mock_sts    # sts client
        ]
        
        # Create scanner with mock session
        scanner = IAMScanner(session=mock_session.return_value)
        
        # Store mock clients for testing
        scanner.iam = mock_iam
        scanner.organizations = mock_orgs
        scanner.sts = mock_sts
        
        yield scanner

def test_initialization(iam_scanner):
    """Test IAMScanner initialization and AWS client setup."""
    assert iam_scanner.iam is not None
    assert iam_scanner.organizations is not None
    assert iam_scanner.sts is not None
    assert iam_scanner.account_id is not None
    assert iam_scanner.region is not None

def test_scan_iam_roles(iam_scanner):
    """Test scanning IAM roles with various permission sets."""
    # Mock IAM API responses
    iam_scanner.iam.list_roles.return_value = {
        'Roles': [{
            'RoleName': 'TestRole',
            'Arn': 'arn:aws:iam::123456789012:role/TestRole',
            'CreateDate': datetime.utcnow(),
            'AssumeRolePolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'ec2.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            }
        }]
    }
    
    iam_scanner.iam.list_attached_role_policies.return_value = {
        'AttachedPolicies': [{
            'PolicyName': 'TestPolicy',
            'PolicyArn': 'arn:aws:iam::aws:policy/TestPolicy'
        }]
    }
    
    iam_scanner.iam.list_role_policies.return_value = {
        'PolicyNames': ['TestInlinePolicy']
    }
    
    iam_scanner.iam.get_role_policy.return_value = {
        'PolicyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': '*'
            }]
        }
    }
    
    # Test scanning
    results = iam_scanner.scan_iam_roles()
    
    # Verify results
    assert len(results) > 0
    assert any(r['resource_arn'] == 'arn:aws:iam::123456789012:role/TestRole' for r in results)

def test_scan_iam_users(iam_scanner):
    """Test scanning IAM users and their access keys."""
    # Mock IAM API responses
    iam_scanner.iam.list_users.return_value = {
        'Users': [{
            'UserName': 'testuser',
            'Arn': 'arn:aws:iam::123456789012:user/testuser',
            'CreateDate': datetime.utcnow() - timedelta(days=100),
            'PasswordLastUsed': datetime.utcnow() - timedelta(days=30)
        }]
    }
    
    iam_scanner.iam.list_access_keys.return_value = {
        'AccessKeyMetadata': [{
            'AccessKeyId': 'AKIAEXAMPLE',
            'Status': 'Active',
            'CreateDate': datetime.utcnow() - timedelta(days=90)
        }]
    }
    
    # Test scanning
    results = iam_scanner.scan_iam_users()
    
    # Verify results
    assert len(results) > 0
    assert any(r['resource_arn'] == 'arn:aws:iam::123456789012:user/testuser' for r in results)

def test_scan_iam_policies(iam_scanner):
    """Test scanning IAM policies for excessive permissions."""
    # Mock IAM API responses
    iam_scanner.iam.list_policies.return_value = {
        'Policies': [{
            'PolicyName': 'TestPolicy',
            'PolicyId': 'TESTPOLICYID',
            'Arn': 'arn:aws:iam::123456789012:policy/TestPolicy',
            'DefaultVersionId': 'v1'
        }]
    }
    
    iam_scanner.iam.get_policy_version.return_value = {
        'PolicyVersion': {
            'Document': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }]
            }
        }
    }
    
    # Test scanning
    results = iam_scanner.scan_iam_policies()
    
    # Verify results
    assert len(results) > 0
    assert any(r['resource_arn'] == 'arn:aws:iam::123456789012:policy/TestPolicy' for r in results)

def test_scan_trust_relationships(iam_scanner):
    """Test scanning IAM trust relationships."""
    # Mock IAM API responses
    iam_scanner.iam.list_roles.return_value = {
        'Roles': [{
            'RoleName': 'TestRole',
            'Arn': 'arn:aws:iam::123456789012:role/TestRole',
            'AssumeRolePolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'AWS': '*'},
                    'Action': 'sts:AssumeRole'
                }]
            }
        }]
    }
    
    # Test scanning
    results = iam_scanner.scan_trust_relationships()
    
    # Verify results
    assert len(results) > 0
    assert any(r['resource_arn'] == 'arn:aws:iam::123456789012:role/TestRole' for r in results)

def test_scan_all(iam_scanner):
    """Test the main scan_all method."""
    # Mock individual scan methods
    with patch.object(iam_scanner, 'scan_iam_roles') as mock_roles, \
         patch.object(iam_scanner, 'scan_iam_users') as mock_users, \
         patch.object(iam_scanner, 'scan_iam_policies') as mock_policies, \
         patch.object(iam_scanner, 'scan_trust_relationships') as mock_trust:
        
        # Configure mocks
        mock_roles.return_value = [{'id': 'role1', 'severity': 'high'}]
        mock_users.return_value = [{'id': 'user1', 'severity': 'medium'}]
        mock_policies.return_value = [{'id': 'policy1', 'severity': 'high'}]
        mock_trust.return_value = [{'id': 'trust1', 'severity': 'low'}]
        
        # Run scan
        results = iam_scanner.scan_all()
        
        # Verify all scanners were called
        mock_roles.assert_called_once()
        mock_users.assert_called_once()
        mock_policies.assert_called_once()
        mock_trust.assert_called_once()
        
        # Verify results aggregation
        assert len(results) == 4
        assert any(r['id'] == 'role1' for r in results)
        assert any(r['id'] == 'user1' for r in results)
        assert any(r['id'] == 'policy1' for r in results)
        assert any(r['id'] == 'trust1' for r in results)

def test_error_handling(iam_scanner, caplog):
    """Test error handling in the scanner."""
    # Test IAM API error
    iam_scanner.iam.list_roles.side_effect = Exception("Test error")
    
    # Should not raise exception
    results = iam_scanner.scan_iam_roles()
    
    # Should log the error
    assert "Error scanning IAM roles" in caplog.text
    assert results == []

def test_pagination_handling(iam_scanner):
    """Test handling of paginated API responses."""
    # Mock paginated response for list_roles
    iam_scanner.iam.get_paginator.return_value.paginate.return_value = [
        {
            'Roles': [{'RoleName': f'Role-{i}', 'Arn': f'arn:aws:iam::123456789012:role/Role-{i}'}]
        }
        for i in range(3)
    ]
    
    # Test scanning with pagination
    results = iam_scanner.scan_iam_roles()
    
    # Verify all results were processed
    assert len(results) == 3
    assert all(r['resource_arn'].startswith('arn:aws:iam::123456789012:role/Role-') for r in results)

def test_permission_boundary_handling(iam_scanner):
    """Test handling of IAM permission boundaries."""
    # Mock IAM role with permission boundary
    iam_scanner.iam.list_roles.return_value = {
        'Roles': [{
            'RoleName': 'BoundaryRole',
            'Arn': 'arn:aws:iam::123456789012:role/BoundaryRole',
            'PermissionsBoundary': {
                'PermissionsBoundaryType': 'Policy',
                'PermissionsBoundaryArn': 'arn:aws:iam::aws:policy/TestBoundary'
            }
        }]
    }
    
    # Test scanning
    results = iam_scanner.scan_iam_roles()
    
    # Verify permission boundary is included in results
    assert len(results) > 0
    role_result = next(r for r in results if r['resource_arn'] == 'arn:aws:iam::123456789012:role/BoundaryRole')
    assert 'permissions_boundary' in role_result
    assert role_result['permissions_boundary'] == 'arn:aws:iam::aws:policy/TestBoundary'

def test_service_linked_roles(iam_scanner):
    """Test handling of AWS service-linked roles."""
    # Mock service-linked role
    iam_scanner.iam.list_roles.return_value = {
        'Roles': [{
            'RoleName': 'AWSServiceRoleForAutoScaling',
            'Arn': 'arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling',
            'CreateServiceLinkedRole': 'autoscaling.amazonaws.com'
        }]
    }
    
    # Test scanning
    results = iam_scanner.scan_iam_roles()
    
    # Verify service-linked role is processed
    assert len(results) > 0
    assert any(r['resource_arn'] == 'arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling' 
               for r in results)