# tests/unit/test_storage_remediation.py
import pytest
import json
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from scanners.storage_auditor.remediation import StorageRemediation

@pytest.fixture
def remediation():
    """Create a StorageRemediation instance for testing."""
    return StorageRemediation(aws_region='us-east-1')

def test_initialization():
    """Test StorageRemediation initialization."""
    remediator = StorageRemediation(aws_region='us-west-2')
    assert remediator.region == 'us-west-2'
    assert remediator.s3_client.meta.region_name == 'us-west-2'
    assert remediator.iam_client.meta.region_name == 'us-west-2'

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_enable_bucket_encryption_success(mock_s3_client, remediation):
    """Test enabling bucket encryption successfully."""
    bucket_name = 'test-bucket'
    mock_s3_client.put_bucket_encryption.return_value = {}
    
    result = remediation.enable_bucket_encryption(bucket_name)
    
    assert result is True
    mock_s3_client.put_bucket_encryption.assert_called_once_with(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
        }
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_enable_bucket_encryption_error(mock_s3_client, remediation, capsys):
    """Test error handling when enabling bucket encryption fails."""
    bucket_name = 'test-bucket'
    mock_s3_client.put_bucket_encryption.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'PutBucketEncryption'
    )
    
    result = remediation.enable_bucket_encryption(bucket_name)
    
    assert result is False
    captured = capsys.readouterr()
    assert f"Error enabling encryption for {bucket_name}" in captured.out

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_enable_bucket_versioning_success(mock_s3_client, remediation):
    """Test enabling bucket versioning successfully."""
    bucket_name = 'test-bucket'
    mock_s3_client.put_bucket_versioning.return_value = {}
    
    result = remediation.enable_bucket_versioning(bucket_name)
    
    assert result is True
    mock_s3_client.put_bucket_versioning.assert_called_once_with(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_set_bucket_policy_success(mock_s3_client, remediation):
    """Test setting bucket policy successfully."""
    bucket_name = 'test-bucket'
    policy = {'Version': '2012-10-17', 'Statement': []}
    
    result = remediation.set_bucket_policy(bucket_name, policy)
    
    assert result is True
    mock_s3_client.put_bucket_policy.assert_called_once_with(
        Bucket=bucket_name,
        Policy=json.dumps(policy)
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_block_public_access_success(mock_s3_client, remediation):
    """Test blocking public access successfully."""
    bucket_name = 'test-bucket'
    mock_s3_client.put_public_access_block.return_value = {}
    
    result = remediation.block_public_access(bucket_name)
    
    assert result is True
    mock_s3_client.put_public_access_block.assert_called_once_with(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_enable_logging_success(mock_s3_client, remediation):
    """Test enabling logging successfully."""
    bucket_name = 'source-bucket'
    target_bucket = 'logs-bucket'
    prefix = 'logs/'
    
    result = remediation.enable_logging(bucket_name, target_bucket, prefix)
    
    assert result is True
    mock_s3_client.put_bucket_logging.assert_called_once_with(
        Bucket=bucket_name,
        BucketLoggingStatus={
            'LoggingEnabled': {
                'TargetBucket': target_bucket,
                'TargetPrefix': prefix
            }
        }
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_set_lifecycle_policy_success(mock_s3_client, remediation):
    """Test setting lifecycle policy successfully."""
    bucket_name = 'test-bucket'
    rules = [{'ID': 'TestRule', 'Status': 'Enabled', 'Prefix': '', 'Expiration': {'Days': 30}}]
    
    result = remediation.set_lifecycle_policy(bucket_name, rules)
    
    assert result is True
    mock_s3_client.put_bucket_lifecycle_configuration.assert_called_once_with(
        Bucket=bucket_name,
        LifecycleConfiguration={'Rules': rules}
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_tag_bucket_success(mock_s3_client, remediation):
    """Test tagging bucket successfully."""
    bucket_name = 'test-bucket'
    tags = {'Environment': 'test', 'Owner': 'team'}
    
    result = remediation.tag_bucket(bucket_name, tags)
    
    assert result is True
    mock_s3_client.put_bucket_tagging.assert_called_once_with(
        Bucket=bucket_name,
        Tagging={
            'TagSet': [
                {'Key': 'Environment', 'Value': 'test'},
                {'Key': 'Owner', 'Value': 'team'}
            ]
        }
    )

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_encryption_status_enabled(mock_s3_client, remediation):
    """Test getting encryption status when encryption is enabled."""
    bucket_name = 'test-bucket'
    mock_response = {
        'ServerSideEncryptionConfiguration': {
            'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
        }
    }
    mock_s3_client.get_bucket_encryption.return_value = mock_response
    
    result = remediation.get_bucket_encryption_status(bucket_name)
    
    assert result == mock_response['ServerSideEncryptionConfiguration']
    mock_s3_client.get_bucket_encryption.assert_called_once_with(Bucket=bucket_name)

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_encryption_status_not_found(mock_s3_client, remediation):
    """Test getting encryption status when no encryption is configured."""
    bucket_name = 'test-bucket'
    mock_s3_client.get_bucket_encryption.side_effect = ClientError(
        {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}},
        'GetBucketEncryption'
    )
    
    result = remediation.get_bucket_encryption_status(bucket_name)
    
    assert result is None

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_encryption_status_error(mock_s3_client, remediation, capsys):
    """Test error handling when getting encryption status fails."""
    bucket_name = 'test-bucket'
    mock_s3_client.get_bucket_encryption.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'GetBucketEncryption'
    )
    
    result = remediation.get_bucket_encryption_status(bucket_name)
    
    assert result is None
    captured = capsys.readouterr()
    assert f"Error getting encryption status for {bucket_name}" in captured.out

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_policy_exists(mock_s3_client, remediation):
    """Test getting an existing bucket policy."""
    bucket_name = 'test-bucket'
    policy = {'Version': '2012-10-17', 'Statement': []}
    mock_s3_client.get_bucket_policy.return_value = {'Policy': json.dumps(policy)}
    
    result = remediation.get_bucket_policy(bucket_name)
    
    assert result == policy
    mock_s3_client.get_bucket_policy.assert_called_once_with(Bucket=bucket_name)

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_policy_not_found(mock_s3_client, remediation):
    """Test getting a non-existent bucket policy."""
    bucket_name = 'test-bucket'
    mock_s3_client.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy'
    )
    
    result = remediation.get_bucket_policy(bucket_name)
    
    assert result is None

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_tagging_exists(mock_s3_client, remediation):
    """Test getting tags for a bucket with tags."""
    bucket_name = 'test-bucket'
    mock_s3_client.get_bucket_tagging.return_value = {
        'TagSet': [
            {'Key': 'Environment', 'Value': 'test'},
            {'Key': 'Owner', 'Value': 'team'}
        ]
    }
    
    result = remediation.get_bucket_tagging(bucket_name)
    
    assert result == {'Environment': 'test', 'Owner': 'team'}
    mock_s3_client.get_bucket_tagging.assert_called_once_with(Bucket=bucket_name)

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_tagging_no_tags(mock_s3_client, remediation):
    """Test getting tags for a bucket with no tags."""
    bucket_name = 'test-bucket'
    mock_s3_client.get_bucket_tagging.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchTagSet'}}, 'GetBucketTagging'
    )
    
    result = remediation.get_bucket_tagging(bucket_name)
    
    assert result == {}

@patch('scanners.storage_auditor.remediation.StorageRemediation.s3_client')
def test_get_bucket_tagging_error(mock_s3_client, remediation, capsys):
    """Test error handling when getting bucket tags fails."""
    bucket_name = 'test-bucket'
    mock_s3_client.get_bucket_tagging.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'GetBucketTagging'
    )
    
    result = remediation.get_bucket_tagging(bucket_name)
    
    assert result is None
    captured = capsys.readouterr()
    assert f"Error getting tags for {bucket_name}" in captured.out