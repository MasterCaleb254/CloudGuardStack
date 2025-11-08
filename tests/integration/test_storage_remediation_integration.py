# tests/integration/test_storage_remediation_integration.py
import pytest
import os
import json
import boto3
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from botocore.stub import Stubber
from datetime import datetime, timedelta
from scanners.storage_auditor.remediation import (
    StorageRemediation,
    RemediationError,
    REMEDIATION_ACTIONS
)

# Sample test data
SAMPLE_FINDINGS = [
    {
        "id": "finding-1",
        "resource_type": "AWS::S3::Bucket",
        "resource_arn": "arn:aws:s3:::test-bucket-1",
        "finding_type": "public_access",
        "severity": "high",
        "details": {
            "public_access": True,
            "block_public_access": False
        }
    },
    {
        "id": "finding-2",
        "resource_type": "AWS::S3::Bucket",
        "resource_arn": "arn:aws:s3:::test-bucket-2",
        "finding_type": "unencrypted",
        "severity": "high",
        "details": {
            "encryption": False
        }
    },
    {
        "id": "finding-3",
        "resource_type": "AWS::S3::Object",
        "resource_arn": "arn:aws:s3:::test-bucket-1/object.txt",
        "finding_type": "public_access",
        "severity": "high",
        "details": {
            "public": True
        }
    }
]

@pytest.fixture
def remediation(tmp_path):
    """Create a StorageRemediation instance with a temporary output directory."""
    return StorageRemediation(
        findings=SAMPLE_FINDINGS,
        output_dir=str(tmp_path),
        dry_run=False
    )

@pytest.fixture
def s3_stub():
    """Create a mock S3 client with Stubber."""
    with patch('boto3.client') as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        with Stubber(mock_s3) as stubber:
            yield mock_s3, stubber

def test_remediate_public_access_bucket(remediation, s3_stub):
    """Test remediating public access for an S3 bucket."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Stub the S3 API responses
    stubber.add_response(
        'put_public_access_block',
        service_response={},
        expected_params={
            'Bucket': bucket_name,
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
    )
    
    # Find the public access finding
    finding = next(f for f in SAMPLE_FINDINGS if f["id"] == "finding-1")
    
    # Remediate the finding
    result = remediation.remediate_finding(finding)
    
    # Verify the result
    assert result["status"] == "remediated"
    assert result["action"] == "enabled_public_access_block"
    assert result["resource_arn"] == finding["resource_arn"]

def test_remediate_unencrypted_bucket(remediation, s3_stub):
    """Test remediating an unencrypted S3 bucket."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-2"
    
    # Stub the S3 API responses
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
    
    # Find the encryption finding
    finding = next(f for f in SAMPLE_FINDINGS if f["id"] == "finding-2")
    
    # Remediate the finding
    result = remediation.remediate_finding(finding)
    
    # Verify the result
    assert result["status"] == "remediated"
    assert result["action"] == "enabled_bucket_encryption"
    assert result["resource_arn"] == finding["resource_arn"]

def test_remediate_public_object(remediation, s3_stub):
    """Test remediating a public S3 object."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    object_key = "object.txt"
    
    # Stub the S3 API responses
    stubber.add_response(
        'put_object_acl',
        service_response={},
        expected_params={
            'Bucket': bucket_name,
            'Key': object_key,
            'ACL': 'private'
        }
    )
    
    # Find the public object finding
    finding = next(f for f in SAMPLE_FINDINGS if f["id"] == "finding-3")
    
    # Remediate the finding
    result = remediation.remediate_finding(finding)
    
    # Verify the result
    assert result["status"] == "remediated"
    assert result["action"] == "removed_public_acl"
    assert result["resource_arn"] == finding["resource_arn"]

def test_remediate_unsupported_finding(remediation):
    """Test attempting to remediate an unsupported finding type."""
    # Create an unsupported finding
    finding = {
        "id": "finding-4",
        "resource_type": "AWS::S3::Bucket",
        "resource_arn": "arn:aws:s3:::test-bucket-3",
        "finding_type": "unsupported_type",
        "severity": "high",
        "details": {}
    }
    
    # Attempt to remediate the finding
    result = remediation.remediate_finding(finding)
    
    # Verify the result
    assert result["status"] == "skipped"
    assert result["reason"] == "No remediation available for finding type: unsupported_type"

def test_remediate_finding_error_handling(remediation, s3_stub, caplog):
    """Test error handling during finding remediation."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-1"
    
    # Simulate an error during remediation
    stubber.add_client_error(
        'put_public_access_block',
        service_error_code='NoSuchBucket',
        service_message='The specified bucket does not exist'
    )
    
    # Find the public access finding
    finding = next(f for f in SAMPLE_FINDINGS if f["id"] == "finding-1")
    
    # Attempt to remediate the finding
    result = remediation.remediate_finding(finding)
    
    # Verify the result
    assert result["status"] == "failed"
    assert "error" in result
    assert "NoSuchBucket" in result["error"]
    
    # Verify the error was logged
    assert "Error remediating finding" in caplog.text

def test_remediate_all_findings(remediation, s3_stub):
    """Test remediating all findings."""
    mock_s3, stubber = s3_stub
    
    # Stub the S3 API responses for each finding
    # Public access bucket
    stubber.add_response('put_public_access_block', {})
    # Unencrypted bucket
    stubber.add_response('put_bucket_encryption', {})
    # Public object
    stubber.add_response('put_object_acl', {})
    
    # Remediate all findings
    results = remediation.remediate_all()
    
    # Verify the results
    assert len(results) == len(SAMPLE_FINDINGS)
    assert all(r["status"] in ["remediated", "skipped"] for r in results)
    
    # Verify the results file was created
    results_file = os.path.join(remediation.output_dir, "remediation_results.json")
    assert os.path.exists(results_file)
    
    # Verify the results file contains the expected data
    with open(results_file, 'r') as f:
        saved_results = json.load(f)
        assert len(saved_results) == len(results)

def test_dry_run_mode(remediation):
    """Test remediation in dry run mode."""
    # Enable dry run mode
    remediation.dry_run = True
    
    # Remediate all findings
    results = remediation.remediate_all()
    
    # Verify the results
    assert len(results) == len(SAMPLE_FINDINGS)
    assert all(r["status"] == "dry_run" for r in results)
    
    # Verify no API calls were made
    assert not hasattr(remediation, 's3_client')

def test_generate_remediation_plan(remediation):
    """Test generating a remediation plan."""
    # Generate the remediation plan
    plan = remediation.generate_remediation_plan()
    
    # Verify the plan structure
    assert "remediation_actions" in plan
    assert "summary" in plan
    assert plan["summary"]["total_findings"] == len(SAMPLE_FINDINGS)
    
    # Verify each finding has a corresponding remediation action
    for finding in SAMPLE_FINDINGS:
        assert any(a["finding_id"] == finding["id"] for a in plan["remediation_actions"])

def test_save_remediation_plan(remediation, tmp_path):
    """Test saving the remediation plan to a file."""
    # Generate and save the remediation plan
    plan_file = os.path.join(tmp_path, "remediation_plan.json")
    remediation.save_remediation_plan(plan_file)
    
    # Verify the file was created
    assert os.path.exists(plan_file)
    
    # Verify the file contains the expected data
    with open(plan_file, 'r') as f:
        plan = json.load(f)
        assert "remediation_actions" in plan
        assert len(plan["remediation_actions"]) > 0

def test_custom_remediation_action(remediation, s3_stub):
    """Test registering and using a custom remediation action."""
    mock_s3, stubber = s3_stub
    bucket_name = "test-bucket-custom"
    
    # Define a custom remediation action
    def custom_remediation(finding, s3_client):
        if finding["finding_type"] == "custom_finding":
            s3_client.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={
                    'TagSet': [{'Key': 'Remediated', 'Value': 'true'}]
                }
            )
            return {
                "status": "remediated",
                "action": "applied_custom_remediation"
            }
        return None
    
    # Register the custom action
    remediation.register_remediation_action("custom_finding", custom_remediation)
    
    # Create a custom finding
    finding = {
        "id": "finding-custom",
        "resource_type": "AWS::S3::Bucket",
        "resource_arn": f"arn:aws:s3:::{bucket_name}",
        "finding_type": "custom_finding",
        "severity": "high",
        "details": {}
    }
    
    # Stub the S3 API response
    stubber.add_response('put_bucket_tagging', {})
    
    # Remediate the finding
    result = remediation.remediate_finding(finding)
    
    # Verify the result
    assert result["status"] == "remediated"
    assert result["action"] == "applied_custom_remediation"