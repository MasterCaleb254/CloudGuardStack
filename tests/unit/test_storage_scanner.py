# tests/unit/test_storage_scanner.py
import pytest
from datetime import datetime, timezone
from dateutil import tz
from unittest.mock import patch, MagicMock, ANY

@pytest.fixture
def mock_boto3_client():
    """Create a mocked boto3 client."""
    with patch('boto3.client') as mock_client:
        s3_client = MagicMock()
        mock_client.return_value = s3_client
        yield s3_client

@pytest.fixture
def scanner(mock_boto3_client):
    """Create a StorageAuditor instance with a mocked S3 client."""
    with patch('boto3.Session') as mock_session:
        mock_session.return_value.client.return_value = mock_boto3_client
        from scanners.storage_auditor.scanner import StorageAuditor
        scanner = StorageAuditor(aws_region='us-east-1')
        yield scanner

def test_initialization(mock_boto3_client):
    """Test StorageAuditor initialization."""
    with patch('boto3.Session') as mock_session:
        mock_session.return_value.client.return_value = mock_boto3_client
        mock_session.return_value.region_name = 'us-west-2'
        
        from scanners.storage_auditor.scanner import StorageAuditor
        scanner = StorageAuditor(aws_region='us-west-2')
        assert scanner.aws_session.region_name == 'us-west-2'

def test_scan_bucket_public_access(scanner, mock_boto3_client):
    """Test scanning a bucket with public access."""
    bucket_name = 'test-public-bucket'
    
    # Setup mock responses
    mock_boto3_client.list_buckets.return_value = {
        'Buckets': [{'Name': bucket_name, 'CreationDate': datetime(2023, 1, 1, tzinfo=tz.UTC)}],
        'Owner': {'DisplayName': 'test', 'ID': 'test-id'}
    }
    
    mock_boto3_client.get_bucket_acl.return_value = {
        'Owner': {'DisplayName': 'test', 'ID': 'test-id'},
        'Grants': [{
            'Grantee': {
                'Type': 'Group',
                'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
            },
            'Permission': 'READ'
        }]
    }
    
    # Call the scan method
    findings = scanner.scan_s3_buckets()
    
    # Verify results - check for string content directly
    assert len(findings) > 0
    assert any('Public access allowed' in finding for finding in findings)

def test_error_handling(scanner, mock_boto3_client):
    """Test error handling during bucket scanning."""
    bucket_name = 'test-error-bucket'
    
    # Setup mock responses
    mock_boto3_client.list_buckets.return_value = {
        'Buckets': [{'Name': bucket_name, 'CreationDate': datetime(2023, 1, 1, tzinfo=tz.UTC)}],
        'Owner': {'DisplayName': 'test', 'ID': 'test-id'}
    }
    
    # Simulate error
    mock_boto3_client.get_bucket_acl.side_effect = Exception('Access Denied')
    
    # Call the scan method
    findings = scanner.scan_s3_buckets()
    
    # Verify error is handled gracefully - check for string content directly
    assert len(findings) > 0
    assert any('Access Denied' in finding for finding in findings)

# Keep skipped tests as they were
@pytest.mark.skip(reason="Test needs to be updated to match implementation")
def test_check_encryption_enabled():
    pass

@pytest.mark.skip(reason="Test needs to be updated to match implementation")
def test_check_versioning_enabled():
    pass