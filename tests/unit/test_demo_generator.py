# tests/unit/test_demo_generator.py
import pytest
import json
import boto3
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from botocore.stub import Stubber
from scanners.storage_auditor.demo_generator import DemoGenerator

@pytest.fixture
def demo_generator():
    """Create a DemoGenerator instance for testing."""
    return DemoGenerator(aws_region='us-east-1')

def test_initialization():
    """Test DemoGenerator initialization."""
    generator = DemoGenerator(aws_region='us-west-2')
    assert generator.aws_region == 'us-west-2'
    assert generator.s3_client.meta.region_name == 'us-west-2'
    assert generator.iam_client.meta.region_name == 'us-west-2'

def test_generate_bucket_name(demo_generator):
    """Test bucket name generation."""
    name = demo_generator.generate_bucket_name('test-prefix')
    assert name.startswith('test-prefix-')
    assert len(name) > len('test-prefix-') + 10  # Should have a random suffix

def test_generate_bucket_policy(demo_generator):
    """Test bucket policy generation."""
    bucket_name = 'test-bucket'
    policy = demo_generator.generate_bucket_policy(bucket_name)
    
    assert policy['Version'] == '2012-10-17'
    assert len(policy['Statement']) == 1
    assert policy['Statement'][0]['Resource'] == f"arn:aws:s3:::{bucket_name}/*"

def test_generate_bucket_acl(demo_generator):
    """Test bucket ACL generation."""
    owner_id = 'test-owner-123'
    acl = demo_generator.generate_bucket_acl(owner_id)
    
    assert acl['Owner']['ID'] == owner_id
    assert len(acl['Grants']) == 1
    assert acl['Grants'][0]['Permission'] == 'READ'

def test_generate_bucket_encryption(demo_generator):
    """Test encryption configuration generation."""
    encryption = demo_generator.generate_bucket_encryption()
    assert encryption['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256'

def test_generate_bucket_versioning(demo_generator):
    """Test versioning configuration generation."""
    # Test enabled
    versioning = demo_generator.generate_bucket_versioning(True)
    assert versioning['Status'] == 'Enabled'
    
    # Test disabled
    versioning = demo_generator.generate_bucket_versioning(False)
    assert versioning['Status'] == 'Suspended'

def test_generate_bucket_logging(demo_generator):
    """Test logging configuration generation."""
    target_bucket = 'logs-bucket'
    prefix = 'test/'
    logging = demo_generator.generate_bucket_logging(target_bucket, prefix)
    
    assert logging['TargetBucket'] == target_bucket
    assert logging['TargetPrefix'] == prefix

def test_generate_lifecycle_rule(demo_generator):
    """Test lifecycle rule generation."""
    days = 90
    rule = demo_generator.generate_lifecycle_rule(days)
    
    assert rule['Status'] == 'Enabled'
    assert rule['Transitions'][0]['Days'] == days
    assert rule['Expiration']['Days'] == days * 2

def test_generate_bucket_metrics(demo_generator):
    """Test metrics data generation."""
    bucket_name = 'test-bucket'
    days = 5
    metrics = demo_generator.generate_bucket_metrics(bucket_name, days)
    
    assert len(metrics) == days
    for metric in metrics:
        assert metric['BucketName'] == bucket_name
        assert isinstance(metric['StorageBytes'], int)
        assert isinstance(metric['NumberOfObjects'], int)
        assert 'Timestamp' in metric

def test_generate_bucket_inventory_report(demo_generator):
    """Test inventory report generation."""
    bucket_name = 'test-bucket'
    days = 3
    inventory = demo_generator.generate_bucket_inventory_report(bucket_name, days)
    
    assert len(inventory) == days * 10  # 10 items per day
    for item in inventory:
        assert 'Key' in item
        assert 'Size' in item
        assert 'StorageClass' in item
        assert 'LastModified' in item

def test_generate_iam_policy_for_bucket(demo_generator):
    """Test IAM policy generation for a bucket."""
    bucket_name = 'test-bucket'
    policy = demo_generator.generate_iam_policy_for_bucket(bucket_name)
    
    assert policy['Version'] == '2012-10-17'
    assert len(policy['Statement']) == 1
    assert f"arn:aws:s3:::{bucket_name}" in policy['Statement'][0]['Resource']
    assert f"arn:aws:s3:::{bucket_name}/*" in policy['Statement'][0]['Resource']

@patch('boto3.client')
def test_create_demo_environment(mock_boto_client, demo_generator):
    """Test creation of a complete demo environment."""
    # Setup mock clients
    s3_mock = MagicMock()
    iam_mock = MagicMock()
    mock_boto_client.side_effect = [s3_mock, iam_mock]

    # Create stubs against the same clients the generator will use
    s3_stubber = Stubber(s3_mock)
    iam_stubber = Stubber(iam_mock)

    # Add expected responses
    for i in range(3):  # 3 buckets
        bucket_name = f"demo-bucket-{i}-"
        s3_stubber.add_response('create_bucket', {}, {'Bucket': bucket_name})
        s3_stubber.add_response('put_bucket_policy', {})
        s3_stubber.add_response('put_bucket_acl', {})
        s3_stubber.add_response('put_bucket_encryption', {})
        s3_stubber.add_response('put_bucket_versioning', {})
        s3_stubber.add_response('put_bucket_lifecycle_configuration', {})
        s3_stubber.add_response('put_bucket_inventory_configuration', {})
        s3_stubber.add_response('put_bucket_metrics_configuration', {})
        s3_stubber.add_response('put_bucket_analytics_configuration', {})
        s3_stubber.add_response('put_bucket_intelligent_tiering_configuration', {})

        iam_stubber.add_response('create_policy', {
            'Policy': {'Arn': f'arn:aws:iam::123456789012:policy/test-policy-{i}'}
        })

    # Instantiate a new generator that uses the stubbed clients directly
    generator = DemoGenerator(aws_region='us-west-2', s3_client=s3_mock, iam_client=iam_mock)

    with s3_stubber, iam_stubber:
        result = generator.create_demo_environment(bucket_count=3)

    # Verify the result structure
    assert len(result['buckets']) == 3
    assert len(result['policies']) == 3
    assert len(result['metrics']) == 3

    # Verify each bucket has the expected configurations
    for bucket in result['buckets']:
        assert 'Name' in bucket
        assert 'Policy' in bucket
        assert 'ACL' in bucket
        assert 'Encryption' in bucket
        assert 'Versioning' in bucket
        assert 'Lifecycle' in bucket
        assert 'Inventory' in bucket
        assert 'Metrics' in bucket
        assert 'Analytics' in bucket
        assert 'IntelligentTiering' in bucket

def test_generate_bucket_inventory(demo_generator):
    """Test bucket inventory configuration generation."""
    inventory = demo_generator.generate_bucket_inventory()
    
    assert inventory['Id'] == 'DemoInventory'
    assert inventory['IsEnabled'] is True
    assert inventory['IncludedObjectVersions'] == 'All'
    assert inventory['Schedule']['Frequency'] == 'Weekly'
    assert 'S3BucketDestination' in inventory['Destination']

def test_generate_metrics_configuration(demo_generator):
    """Test metrics configuration generation."""
    metrics = demo_generator.generate_metrics_configuration()
    
    assert metrics['Id'] == 'EntireBucket'
    assert metrics['Filter']['Prefix'] == ''

def test_generate_analytics_configuration(demo_generator):
    """Test analytics configuration generation."""
    analytics = demo_generator.generate_analytics_configuration()
    
    assert analytics['Id'] == 'AnalyticsConfiguration'
    assert analytics['Filter']['Prefix'] == 'analytics/'
    assert analytics['StorageClassAnalysis']['DataExport']['OutputSchemaVersion'] == 'V_1'

def test_generate_intelligent_tiering_configuration(demo_generator):
    """Test intelligent tiering configuration generation."""
    config = demo_generator.generate_intelligent_tiering_configuration()
    
    assert config['Id'] == 'IntelligentTieringConfiguration'
    assert config['Status'] == 'Enabled'
    assert config['Filter']['Prefix'] == 'documents/'
    assert config['Tierings'][0]['AccessTier'] == 'ARCHIVE_ACCESS'

def test_generate_bucket_metrics_data_integrity(demo_generator):
    """Test the integrity of generated metrics data."""
    bucket_name = 'test-bucket'
    days = 7
    metrics = demo_generator.generate_bucket_metrics(bucket_name, days)
    
    # Check the time series is in descending order
    timestamps = [m['Timestamp'] for m in metrics]
    assert all(timestamps[i] >= timestamps[i+1] for i in range(len(timestamps)-1))
    
    # Check data ranges
    for metric in metrics:
        assert 1000000 <= metric['StorageBytes'] <= 10000000
        assert 100 <= metric['NumberOfObjects'] <= 1000
        assert 1000 <= metric['AllRequests'] <= 10000
        assert 500 <= metric['GetRequests'] <= 5000
        assert 100 <= metric['PutRequests'] <= 2000
        assert 0 <= metric['Errors4xx'] <= 50
        assert 0 <= metric['Errors5xx'] <= 10

@patch('boto3.client')
def test_create_demo_environment_with_errors(mock_boto_client, demo_generator):
    """Test error handling in demo environment creation."""
    # Setup mock client that raises an error
    s3_mock = MagicMock()
    s3_mock.create_bucket.side_effect = Exception("Bucket creation failed")
    mock_boto_client.return_value = s3_mock
    
    with pytest.raises(Exception, match="Bucket creation failed"):
        demo_generator.create_demo_environment(bucket_count=1)

def test_generate_bucket_name_with_special_chars(demo_generator):
    """Test bucket name generation with special characters in prefix."""
    prefix = "test@bucket#name"
    name = demo_generator.generate_bucket_name(prefix)
    assert name.startswith('testbucketname-')  # Special chars should be removed
    assert len(name) > len('testbucketname-') + 10

def test_generate_bucket_inventory_report_data_integrity(demo_generator):
    """Test the integrity of generated inventory report data."""
    bucket_name = 'test-bucket'
    days = 2
    inventory = demo_generator.generate_bucket_inventory_report(bucket_name, days)
    
    # Should generate 20 items (2 days * 10 items per day)
    assert len(inventory) == 20
    
    # Check data types and ranges
    for item in inventory:
        assert 'object-' in item['Key']
        assert item['Size'] >= 1024
        assert item['Size'] <= 10485760
        assert item['StorageClass'] in ["STANDARD", "STANDARD_IA", "INTELLIGENT_TIERING", "GLACIER"]
        assert isinstance(item['IsLatest'], bool)
        assert isinstance(item['IsDeleteMarker'], bool)