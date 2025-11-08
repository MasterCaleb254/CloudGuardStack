# tests/integration/test_storage_demo_generator_integration.py
import pytest
import os
import json
import boto3
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from botocore.stub import Stubber
from datetime import datetime, timedelta
from scanners.storage_auditor.demo_generator import StorageDemoGenerator

# Sample test data
SAMPLE_CONFIG = {
    "account_id": "123456789012",
    "region": "us-east-1",
    "num_buckets": 2,
    "num_objects_per_bucket": 3,
    "public_access": True,
    "encryption": True,
    "versioning": True,
    "logging": True,
    "tags": {"Environment": "test", "Project": "storage-audit-demo"}
}

@pytest.fixture
def demo_generator(tmp_path):
    """Create a StorageDemoGenerator instance with a temporary output directory."""
    return StorageDemoGenerator(
        config=SAMPLE_CONFIG,
        output_dir=str(tmp_path)
    )

@pytest.fixture
def s3_stub(demo_generator):
    """Create a mock S3 client with Stubber."""
    with patch('boto3.client') as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        with Stubber(mock_s3) as stubber:
            yield mock_s3, stubber

def test_generate_demo_environment(demo_generator, s3_stub, tmp_path):
    """Test generating a complete demo environment."""
    mock_s3, stubber = s3_stub
    
    # Setup S3 stubs
    for i in range(SAMPLE_CONFIG["num_buckets"]):
        bucket_name = f"demo-bucket-{i}"
        
        # CreateBucket
        stubber.add_response(
            'create_bucket',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'CreateBucketConfiguration': {
                    'LocationConstraint': SAMPLE_CONFIG["region"]
                }
            }
        )
        
        # PutBucketVersioning
        stubber.add_response(
            'put_bucket_versioning',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'VersioningConfiguration': {
                    'Status': 'Enabled'
                }
            }
        )
        
        # PutBucketEncryption
        stubber.add_response(
            'put_bucket_encryption',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'ServerSideEncryptionConfiguration': {
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                }
            }
        )
        
        # PutBucketLogging
        stubber.add_response(
            'put_bucket_logging',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'BucketLoggingStatus': {
                    'LoggingEnabled': {
                        'TargetBucket': f"demo-bucket-logs-{i}",
                        'TargetPrefix': 'logs/'
                    }
                }
            }
        )
        
        # PutBucketPolicy for public access
        stubber.add_response(
            'put_bucket_policy',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'Policy': MagicMock()
            }
        )
        
        # PutBucketTagging
        stubber.add_response(
            'put_bucket_tagging',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'Tagging': {
                    'TagSet': [
                        {'Key': k, 'Value': v} 
                        for k, v in SAMPLE_CONFIG["tags"].items()
                    ]
                }
            }
        )
        
        # Add objects
        for j in range(SAMPLE_CONFIG["num_objects_per_bucket"]):
            object_key = f"file_{j}.txt"
            stubber.add_response(
                'put_object',
                service_response={},
                expected_params={
                    'Bucket': bucket_name,
                    'Key': object_key,
                    'Body': MagicMock(),
                    'ContentType': 'text/plain'
                }
            )
    
    # Generate the demo environment
    result = demo_generator.generate_demo_environment()
    
    # Verify the result
    assert len(result["buckets"]) == SAMPLE_CONFIG["num_buckets"]
    assert len(result["objects"]) == SAMPLE_CONFIG["num_buckets"] * SAMPLE_CONFIG["num_objects_per_bucket"]
    
    # Verify output files were created
    assert os.path.exists(os.path.join(demo_generator.output_dir, "demo_environment.json"))
    assert os.path.exists(os.path.join(demo_generator.output_dir, "demo_findings.json"))

def test_generate_demo_findings(demo_generator, tmp_path):
    """Test generating demo findings."""
    # Create a sample environment
    environment = {
        "buckets": [
            {
                "Name": "demo-bucket-0",
                "CreationDate": datetime.utcnow().isoformat(),
                "Region": SAMPLE_CONFIG["region"]
            }
        ],
        "objects": [
            {
                "Bucket": "demo-bucket-0",
                "Key": "file1.txt",
                "LastModified": (datetime.utcnow() - timedelta(days=10)).isoformat(),
                "Size": 1024,
                "StorageClass": "STANDARD"
            }
        ]
    }
    
    # Generate findings
    findings = demo_generator._generate_demo_findings(environment)
    
    # Verify the findings
    assert len(findings) > 0
    assert any(f["resource_type"] == "AWS::S3::Bucket" for f in findings)
    assert any(f["resource_type"] == "AWS::S3::Object" for f in findings)
    
    # Verify finding details
    for finding in findings:
        assert "resource_arn" in finding
        assert "finding_type" in finding
        assert "severity" in finding
        assert "details" in finding

def test_cleanup_demo_environment(demo_generator, s3_stub):
    """Test cleaning up the demo environment."""
    mock_s3, stubber = s3_stub
    
    # Setup S3 stubs
    for i in range(SAMPLE_CONFIG["num_buckets"]):
        bucket_name = f"demo-bucket-{i}"
        
        # ListObjectVersions
        stubber.add_response(
            'list_object_versions',
            service_response={
                'Versions': [{'Key': f'file_{j}.txt', 'VersionId': f'v{j}'} 
                            for j in range(SAMPLE_CONFIG["num_objects_per_bucket"])],
                'DeleteMarkers': []
            },
            expected_params={'Bucket': bucket_name}
        )
        
        # DeleteObjects
        stubber.add_response(
            'delete_objects',
            service_response={},
            expected_params={
                'Bucket': bucket_name,
                'Delete': {
                    'Objects': [
                        {'Key': f'file_{j}.txt', 'VersionId': f'v{j}'} 
                        for j in range(SAMPLE_CONFIG["num_objects_per_bucket"])
                    ]
                }
            }
        )
        
        # DeleteBucket
        stubber.add_response(
            'delete_bucket',
            service_response={},
            expected_params={'Bucket': bucket_name}
        )
    
    # Create a sample environment file
    environment = {
        "buckets": [{"Name": f"demo-bucket-{i}"} 
                   for i in range(SAMPLE_CONFIG["num_buckets"])]
    }
    env_file = os.path.join(demo_generator.output_dir, "demo_environment.json")
    with open(env_file, 'w') as f:
        json.dump(environment, f)
    
    # Clean up the environment
    demo_generator.cleanup_demo_environment()
    
    # Verify the environment file was deleted
    assert not os.path.exists(env_file)

def test_generate_demo_environment_error_handling(demo_generator, s3_stub, caplog):
    """Test error handling during demo environment generation."""
    mock_s3, stubber = s3_stub
    
    # Simulate an error during bucket creation
    stubber.add_client_error(
        'create_bucket',
        service_error_code='BucketAlreadyExists',
        service_message='Bucket already exists'
    )
    
    # Generate the demo environment (should handle the error)
    result = demo_generator.generate_demo_environment()
    
    # Verify error was logged
    assert "Error creating bucket" in caplog.text
    
    # Verify partial results
    assert "buckets" in result
    assert "objects" in result

def test_main_function(tmp_path, monkeypatch):
    """Test the main function with command line arguments."""
    import sys
    from scanners.storage_auditor.demo_generator import main
    
    # Mock command line arguments
    test_args = [
        "demo_generator.py",
        "--num-buckets", "1",
        "--num-objects", "2",
        "--output-dir", str(tmp_path),
        "--region", "us-west-2",
        "--no-public-access",
        "--no-encryption",
        "--no-versioning",
        "--no-logging"
    ]
    
    with patch.object(sys, 'argv', test_args), \
         patch('boto3.client') as mock_client:
        
        # Mock S3 client
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        
        # Call the main function
        main()
        
        # Verify S3 client was created with correct region
        mock_client.assert_called_once_with('s3', region_name='us-west-2')
        
        # Verify output files were created
        assert os.path.exists(os.path.join(tmp_path, "demo_environment.json"))
        assert os.path.exists(os.path.join(tmp_path, "demo_findings.json"))

def test_generate_bucket_policy(demo_generator):
    """Test generating a bucket policy."""
    bucket_name = "test-bucket"
    policy = demo_generator._generate_bucket_policy(bucket_name)
    
    # Verify the policy structure
    assert "Version" in policy
    assert "Statement" in policy
    assert isinstance(policy["Statement"], list)
    
    # Verify the bucket name is in the policy
    policy_str = json.dumps(policy)
    assert bucket_name in policy_str
    assert "s3:GetObject" in policy_str

def test_generate_demo_object(demo_generator):
    """Test generating a demo object."""
    bucket_name = "test-bucket"
    object_key = "test-file.txt"
    obj = demo_generator._generate_demo_object(bucket_name, object_key)
    
    # Verify the object structure
    assert obj["Bucket"] == bucket_name
    assert obj["Key"] == object_key
    assert "Body" in obj
    assert "ContentType" in obj
    assert obj["ContentType"] == "text/plain"