# tests/integration/test_storage_scanner_integration.py
import pytest
import os
import json
import boto3
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from botocore.stub import Stubber
from datetime import datetime, timedelta
from scanners.storage_auditor.scanner import StorageScanner, ScanConfig

# Sample test data
SAMPLE_BUCKETS = [
    {
        "Name": "test-bucket-1",
        "CreationDate": datetime(2023, 1, 1),
        "Region": "us-east-1"
    },
    {
        "Name": "test-bucket-2",
        "CreationDate": datetime(2023, 1, 2),
        "Region": "us-west-2"
    }
]

SAMPLE_OBJECTS = {
    "test-bucket-1": [
        {"Key": "file1.txt", "LastModified": datetime(2023, 1, 1), "Size": 1024},
        {"Key": "folder/file2.txt", "LastModified": datetime(2023, 1, 2), "Size": 2048}
    ],
    "test-bucket-2": [
        {"Key": "data.csv", "LastModified": datetime(2023, 1, 3), "Size": 5120}
    ]
}

@pytest.fixture
def scanner(tmp_path):
    """Create a StorageScanner instance with a temporary output directory."""
    config = ScanConfig(
        regions=["us-east-1", "us-west-2"],
        output_dir=str(tmp_path),
        max_workers=2,
        include_buckets=None,
        exclude_buckets=None
    )
    return StorageScanner(config)

@pytest.fixture
def s3_stub():
    """Create a mock S3 client with Stubber."""
    with patch('boto3.client') as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        with Stubber(mock_s3) as stubber:
            yield mock_s3, stubber

def test_scan_bucket_public_access(scanner, s3_stub):
    """Test scanning a bucket for public access settings."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    stubber.add_response(
        'get_public_access_block',
        service_response={
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        },
        expected_params={'Bucket': bucket_name}
    )
    
    # Scan the bucket
    findings = scanner._scan_bucket_public_access(bucket_name)
    
    # Verify the findings
    assert len(findings) > 0
    assert any(f["finding_type"] == "public_access" for f in findings)

def test_scan_bucket_encryption(scanner, s3_stub):
    """Test scanning a bucket for encryption settings."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    stubber.add_client_error(
        'get_bucket_encryption',
        service_error_code='ServerSideEncryptionConfigurationNotFoundError',
        service_message='The server side encryption configuration was not found'
    )
    
    # Scan the bucket
    findings = scanner._scan_bucket_encryption(bucket_name)
    
    # Verify the findings
    assert len(findings) > 0
    assert any(f["finding_type"] == "unencrypted" for f in findings)

def test_scan_bucket_versioning(scanner, s3_stub):
    """Test scanning a bucket for versioning settings."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    stubber.add_response(
        'get_bucket_versioning',
        service_response={},
        expected_params={'Bucket': bucket_name}
    )
    
    # Scan the bucket
    findings = scanner._scan_bucket_versioning(bucket_name)
    
    # Verify the findings
    assert len(findings) > 0
    assert any(f["finding_type"] == "versioning_disabled" for f in findings)

def test_scan_bucket_logging(scanner, s3_stub):
    """Test scanning a bucket for logging settings."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    stubber.add_response(
        'get_bucket_logging',
        service_response={},
        expected_params={'Bucket': bucket_name}
    )
    
    # Scan the bucket
    findings = scanner._scan_bucket_logging(bucket_name)
    
    # Verify the findings
    assert len(findings) > 0
    assert any(f["finding_type"] == "logging_disabled" for f in findings)

def test_scan_bucket_objects(scanner, s3_stub):
    """Test scanning objects in a bucket."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    stubber.add_response(
        'list_objects_v2',
        service_response={
            'Contents': SAMPLE_OBJECTS[bucket_name],
            'IsTruncated': False
        },
        expected_params={'Bucket': bucket_name}
    )
    
    # Scan the bucket objects
    objects = scanner._scan_bucket_objects(bucket_name)
    
    # Verify the objects
    assert len(objects) == len(SAMPLE_OBJECTS[bucket_name])
    assert all(obj["Bucket"] == bucket_name for obj in objects)

def test_scan_bucket_objects_paginated(scanner, s3_stub):
    """Test scanning objects in a bucket with pagination."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # First page of results
    stubber.add_response(
        'list_objects_v2',
        service_response={
            'Contents': SAMPLE_OBJECTS[bucket_name][:1],
            'NextContinuationToken': 'token123',
            'IsTruncated': True
        },
        expected_params={'Bucket': bucket_name}
    )
    
    # Second page of results
    stubber.add_response(
        'list_objects_v2',
        service_response={
            'Contents': SAMPLE_OBJECTS[bucket_name][1:],
            'IsTruncated': False
        },
        expected_params={'Bucket': bucket_name, 'ContinuationToken': 'token123'}
    )
    
    # Scan the bucket objects
    objects = scanner._scan_bucket_objects(bucket_name)
    
    # Verify all objects were returned
    assert len(objects) == len(SAMPLE_OBJECTS[bucket_name])

def test_scan_bucket_objects_error_handling(scanner, s3_stub, caplog):
    """Test error handling when scanning bucket objects."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Simulate an error
    stubber.add_client_error(
        'list_objects_v2',
        service_error_code='AccessDenied',
        service_message='Access Denied'
    )
    
    # Scan the bucket objects
    objects = scanner._scan_bucket_objects(bucket_name)
    
    # Verify the error was handled
    assert len(objects) == 0
    assert "Error listing objects" in caplog.text

def test_scan_bucket(scanner, s3_stub):
    """Test scanning a single bucket."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    # Public access
    stubber.add_response('get_public_access_block', {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': False}
    })
    # Encryption
    stubber.add_client_error('get_bucket_encryption', 'ServerSideEncryptionConfigurationNotFoundError')
    # Versioning
    stubber.add_response('get_bucket_versioning', {})
    # Logging
    stubber.add_response('get_bucket_logging', {})
    # Objects
    stubber.add_response('list_objects_v2', {'Contents': [], 'IsTruncated': False})
    
    # Scan the bucket
    findings, metrics = scanner._scan_bucket(bucket_name)
    
    # Verify the results
    assert len(findings) > 0
    assert metrics["scanned_objects"] == 0

def test_scan_region(scanner, s3_stub):
    """Test scanning a region for buckets."""
    mock_s3, stubber = s3_stub
    region = "us-east-1"
    
    # Stub the S3 API responses
    # List buckets
    stubber.add_response('list_buckets', {'Buckets': [{'Name': 'test-bucket-1'}]})
    # Get bucket location
    stubber.add_response('get_bucket_location', {'LocationConstraint': region})
    # Bucket scans
    stubber.add_response('get_public_access_block', {'PublicAccessBlockConfiguration': {}})
    stubber.add_response('get_bucket_encryption', {'ServerSideEncryptionConfiguration': {}})
    stubber.add_response('get_bucket_versioning', {'Status': 'Enabled'})
    stubber.add_response('get_bucket_logging', {'LoggingEnabled': {}})
    stubber.add_response('list_objects_v2', {'Contents': [], 'IsTruncated': False})
    
    # Scan the region
    findings, metrics = scanner._scan_region(region)
    
    # Verify the results
    assert len(findings) > 0
    assert metrics["scanned_buckets"] == 1

def test_scan_all_regions(scanner, s3_stub):
    """Test scanning all configured regions."""
    mock_s3, stubber = s3_stub
    
    # Stub the S3 API responses for each region
    for region in scanner.config.regions:
        # List buckets
        stubber.add_response('list_buckets', {'Buckets': [{'Name': f'test-bucket-{region}'}]})
        # Get bucket location
        stubber.add_response('get_bucket_location', {'LocationConstraint': region})
        # Bucket scans
        stubber.add_response('get_public_access_block', {'PublicAccessBlockConfiguration': {}})
        stubber.add_response('get_bucket_encryption', {'ServerSideEncryptionConfiguration': {}})
        stubber.add_response('get_bucket_versioning', {'Status': 'Enabled'})
        stubber.add_response('get_bucket_logging', {'LoggingEnabled': {}})
        stubber.add_response('list_objects_v2', {'Contents': [], 'IsTruncated': False})
    
    # Scan all regions
    results = scanner.scan()
    
    # Verify the results
    assert len(results["findings"]) > 0
    assert results["metrics"]["scanned_buckets"] == len(scanner.config.regions)
    assert os.path.exists(os.path.join(scanner.config.output_dir, "findings.json"))
    assert os.path.exists(os.path.join(scanner.config.output_dir, "metrics.json"))

def test_scan_with_bucket_filters(scanner, s3_stub):
    """Test scanning with bucket include/exclude filters."""
    # Update scanner config with filters
    scanner.config.include_buckets = ["included-bucket"]
    scanner.config.exclude_buckets = ["excluded-bucket"]
    
    mock_s3, stubber = s3_stub
    region = "us-east-1"
    
    # Stub the S3 API responses
    # List buckets (returns all buckets)
    stubber.add_response('list_buckets', {
        'Buckets': [
            {'Name': 'included-bucket'},
            {'Name': 'excluded-bucket'},
            {'Name': 'other-bucket'}
        ]
    })
    
    # Only the included bucket should be scanned
    stubber.add_response('get_bucket_location', {'LocationConstraint': region})
    stubber.add_response('get_public_access_block', {'PublicAccessBlockConfiguration': {}})
    stubber.add_response('get_bucket_encryption', {'ServerSideEncryptionConfiguration': {}})
    stubber.add_response('get_bucket_versioning', {'Status': 'Enabled'})
    stubber.add_response('get_bucket_logging', {'LoggingEnabled': {}})
    stubber.add_response('list_objects_v2', {'Contents': [], 'IsTruncated': False})
    
    # Scan the region
    findings, metrics = scanner._scan_region(region)
    
    # Verify only the included bucket was scanned
    assert metrics["scanned_buckets"] == 1
    assert any("included-bucket" in f["resource_arn"] for f in findings)
    assert not any("excluded-bucket" in f["resource_arn"] for f in findings)
    assert not any("other-bucket" in f["resource_arn"] for f in findings)

def test_scan_with_error_handling(scanner, s3_stub, caplog):
    """Test error handling during scanning."""
    mock_s3, stubber = s3_stub
    region = "us-east-1"
    
    # Simulate an error when listing buckets
    stubber.add_client_error(
        'list_buckets',
        service_error_code='AccessDenied',
        service_message='Access Denied'
    )
    
    # Scan the region
    findings, metrics = scanner._scan_region(region)
    
    # Verify the error was handled
    assert len(findings) == 0
    assert metrics["scanned_buckets"] == 0
    assert "Error listing buckets" in caplog.text

def test_scan_with_partial_failure(scanner, s3_stub):
    """Test scanning with partial failures."""
    mock_s3, stubber = s3_stub
    region = "us-east-1"
    
    # First bucket succeeds
    stubber.add_response('list_buckets', {'Buckets': [{'Name': 'bucket-1'}, {'Name': 'bucket-2'}]})
    stubber.add_response('get_bucket_location', {'LocationConstraint': region})
    stubber.add_response('get_public_access_block', {'PublicAccessBlockConfiguration': {}})
    stubber.add_response('get_bucket_encryption', {'ServerSideEncryptionConfiguration': {}})
    stubber.add_response('get_bucket_versioning', {'Status': 'Enabled'})
    stubber.add_response('get_bucket_logging', {'LoggingEnabled': {}})
    stubber.add_response('list_objects_v2', {'Contents': [], 'IsTruncated': False})
    
    # Second bucket fails
    stubber.add_response('get_bucket_location', {'LocationConstraint': region})
    stubber.add_client_error('get_public_access_block', 'NoSuchBucket')
    
    # Scan the region
    findings, metrics = scanner._scan_region(region)
    
    # Verify partial results
    assert len(findings) > 0
    assert metrics["scanned_buckets"] == 1
    assert metrics["failed_buckets"] == 1