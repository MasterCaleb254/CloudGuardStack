#!/usr/bin/env python3
"""
Test configuration and fixtures for CloudGuardStack unit tests
"""
import pytest
from unittest.mock import MagicMock, patch
import boto3
from botocore.stub import Stubber

@pytest.fixture
def mock_boto3_session():
    """Create a mock AWS session for testing"""
    with patch('boto3.Session') as mock_session:
        mock_iam = MagicMock()
        mock_cloudtrail = MagicMock()
        mock_analyzer = MagicMock()
        
        mock_session.return_value.client.side_effect = [
            mock_iam,  # iam client
            mock_cloudtrail,  # cloudtrail client
            mock_analyzer  # accessanalyzer client
        ]
        
        yield {
            'session': mock_session,
            'iam': mock_iam,
            'cloudtrail': mock_cloudtrail,
            'access_analyzer': mock_analyzer
        }

@pytest.fixture
def iam_test_data():
    """Sample IAM data for testing"""
    return {
        'roles': [
            {
                'RoleName': 'test-role',
                'Arn': 'arn:aws:iam::123456789012:role/test-role',
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Principal': {'Service': 'ec2.amazonaws.com'},
                            'Action': 'sts:AssumeRole'
                        }
                    ]
                }
            }
        ],
        'policies': [
            {
                'PolicyName': 'test-policy',
                'PolicyId': 'TESTPOLICYID123',
                'Arn': 'arn:aws:iam::123456789012:policy/test-policy',
                'DefaultVersionId': 'v1'
            }
        ]
    }