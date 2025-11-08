# tests/integration/test_iam_utils_integration.py
import pytest
import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError
from unittest.mock import patch, MagicMock
from scanners.iam_entitlement.utils import (
    is_valid_iam_policy,
    parse_arn,
    get_account_id_from_arn,
    normalize_policy_document,
    is_policy_principal_wildcard,
    get_effective_permissions
)

# Test data
SAMPLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
        }
    ]
}

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def iam_client(aws_credentials):
    """Create a mock IAM client."""
    with patch('boto3.client') as mock_client:
        yield mock_client.return_value

def test_is_valid_iam_policy_integration(iam_client):
    """Test IAM policy validation with AWS API integration."""
    # Mock the AWS IAM client
    iam_client.simulate_principal_policy.return_value = {
        'EvaluationResults': [{
            'EvalActionName': 's3:GetObject',
            'EvalResourceName': 'arn:aws:s3:::example-bucket/test.txt',
            'EvalDecision': 'allowed',
            'MatchedStatements': [{
                'SourcePolicyId': 'PolicyInputList.1',
                'StartPosition': {'Line': 1, 'Column': 1},
                'EndPosition': {'Line': 1, 'Column': 1}
            }]
        }]
    }
    
    # Test with valid policy
    assert is_valid_iam_policy(SAMPLE_POLICY_DOCUMENT) is True
    
    # Test with invalid policy
    assert is_valid_iam_policy({"Invalid": "Policy"}) is False

def test_parse_arn_integration():
    """Test ARN parsing with various formats."""
    # Standard IAM role ARN
    arn = "arn:aws:iam::123456789012:role/TestRole"
    parsed = parse_arn(arn)
    assert parsed['partition'] == 'aws'
    assert parsed['service'] == 'iam'
    assert parsed['account'] == '123456789012'
    
    # S3 bucket ARN
    s3_arn = "arn:aws:s3:::example-bucket"
    parsed = parse_arn(s3_arn)
    assert parsed['service'] == 's3'
    assert parsed['resource'] == 'example-bucket'
    
    # Invalid ARN
    assert parse_arn("invalid-arn") == {}

def test_get_account_id_from_arn_integration():
    """Test account ID extraction from ARNs."""
    assert get_account_id_from_arn("arn:aws:iam::123456789012:role/TestRole") == "123456789012"
    assert get_account_id_from_arn("arn:aws:s3:::example-bucket") == ""
    assert get_account_id_from_arn("invalid-arn") is None

def test_normalize_policy_document_integration(iam_client):
    """Test policy document normalization."""
    # Test with string input
    policy_str = json.dumps(SAMPLE_POLICY_DOCUMENT)
    assert normalize_policy_document(policy_str) == SAMPLE_POLICY_DOCUMENT
    
    # Test with dict input
    assert normalize_policy_document(SAMPLE_POLICY_DOCUMENT) == SAMPLE_POLICY_DOCUMENT
    
    # Test with invalid input
    assert normalize_policy_document("invalid-json") is None

def test_is_policy_principal_wildcard_integration():
    """Test principal wildcard detection."""
    # Test with string wildcard
    assert is_policy_principal_wildcard('*') is True
    
    # Test with AWS wildcard
    assert is_policy_principal_wildcard({'AWS': '*'}) is True
    
    # Test with specific principal
    assert is_policy_principal_wildcard({'AWS': '123456789012'}) is False
    
    # Test with service principal
    assert is_policy_principal_wildcard({'Service': 'ec2.amazonaws.com'}) is False

def test_get_effective_permissions_integration(iam_client):
    """Test getting effective permissions with AWS API integration."""
    # Mock the AWS IAM client
    iam_client.simulate_principal_policy.return_value = {
        'EvaluationResults': [
            {
                'EvalActionName': 's3:GetObject',
                'EvalResourceName': 'arn:aws:s3:::example-bucket/test.txt',
                'EvalDecision': 'allowed'
            },
            {
                'EvalActionName': 's3:DeleteBucket',
                'EvalResourceName': 'arn:aws:s3:::example-bucket',
                'EvalDecision': 'denied'
            }
        ]
    }
    
    # Test with valid parameters
    results = get_effective_permissions(
        'arn:aws:iam::123456789012:role/TestRole',
        ['s3:GetObject', 's3:DeleteBucket'],
        ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
    )
    
    assert len(results) == 2
    assert results[0]['EvalActionName'] == 's3:GetObject'
    assert results[0]['EvalDecision'] == 'allowed'
    assert results[1]['EvalActionName'] == 's3:DeleteBucket'
    assert results[1]['EvalDecision'] == 'denied'

def test_get_effective_permissions_error_handling(iam_client):
    """Test error handling in get_effective_permissions."""
    # Test with invalid principal
    iam_client.simulate_principal_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchEntity'}},
        'SimulatePrincipalPolicy'
    )
    
    results = get_effective_permissions(
        'arn:aws:iam::123456789012:role/NonExistentRole',
        ['s3:GetObject'],
        ['arn:aws:s3:::example-bucket']
    )
    assert results == []

def test_policy_evaluation_with_conditions(iam_client):
    """Test policy evaluation with conditions."""
    # Mock the AWS IAM client with condition context
    iam_client.simulate_principal_policy.return_value = {
        'EvaluationResults': [{
            'EvalActionName': 's3:GetObject',
            'EvalResourceName': 'arn:aws:s3:::example-bucket/test.txt',
            'EvalDecision': 'allowed',
            'MatchedStatements': [{
                'SourcePolicyId': 'PolicyInputList.1',
                'StartPosition': {'Line': 1, 'Column': 1},
                'EndPosition': {'Line': 1, 'Column': 1}
            }],
            'EvalDecisionDetails': {
                'allowedByPermissionsBoundary': True
            }
        }]
    }
    
    # Test with condition context
    results = get_effective_permissions(
        'arn:aws:iam::123456789012:role/TestRole',
        ['s3:GetObject'],
        ['arn:aws:s3:::example-bucket/test.txt'],
        context_entries=[{
            'ContextKeyName': 'aws:SourceIp',
            'ContextKeyValues': ['192.0.2.0/24'],
            'ContextKeyType': 'string'
        }]
    )
    
    assert len(results) == 1
    assert results[0]['EvalDecision'] == 'allowed'

def test_policy_evaluation_with_permissions_boundary(iam_client):
    """Test policy evaluation with permissions boundary."""
    # Mock the AWS IAM client with permissions boundary
    iam_client.simulate_principal_policy.return_value = {
        'EvaluationResults': [{
            'EvalActionName': 's3:GetObject',
            'EvalResourceName': 'arn:aws:s3:::example-bucket/test.txt',
            'EvalDecision': 'denied',
            'EvalDecisionDetails': {
                'allowedByPermissionsBoundary': False
            }
        }]
    }
    
    results = get_effective_permissions(
        'arn:aws:iam::123456789012:role/TestRole',
        ['s3:GetObject'],
        ['arn:aws:s3:::example-bucket/test.txt']
    )
    
    assert len(results) == 1
    assert results[0]['EvalDecision'] == 'denied'
    assert results[0]['EvalDecisionDetails']['allowedByPermissionsBoundary'] is False