#!/usr/bin/env python3
"""
Integration tests for the Storage Auditor workflow
"""
import os
import json
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from scanners.storage_auditor.scanner import StorageAuditor
from scanners.storage_auditor.reporter import StorageReporter
from scanners.storage_auditor.remediation import StorageRemediation

# Test constants
TEST_BUCKET_NAME = 'test-bucket-integration'
TEST_FILE_NAME = 'test-file.txt'
TEST_REGION = 'us-east-1'

# Sensitive content used for detection
TEST_SENSITIVE_CONTENT = b"""
This is a test file with sensitive data:
- SSN: 123-45-6789
- API_KEY: abc123xyz456
"""


@pytest.fixture
def aws_credentials():
    """Mocked AWS credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = TEST_REGION


@pytest.fixture
def s3_client(aws_credentials):
    """Create a mock S3 client with a test bucket and file."""
    with mock_aws():
        s3 = boto3.client('s3', region_name=TEST_REGION)
        s3.create_bucket(Bucket=TEST_BUCKET_NAME)

        # Upload test file with sensitive data
        s3.put_object(
            Bucket=TEST_BUCKET_NAME,
            Key=TEST_FILE_NAME,
            Body=TEST_SENSITIVE_CONTENT,
            ContentType='text/plain'
        )

        yield s3


@mock_aws
def test_end_to_end_workflow(tmp_path, s3_client):
    """Test the complete storage auditor workflow from scanning to remediation."""
    auditor = StorageAuditor(aws_region=TEST_REGION)

    # Add or verify sensitive patterns for detection
    auditor.sensitive_patterns.update({
        'SSN': [
            r'\b\d{3}-\d{2}-\d{4}\b',
            r'SSN:?\s*\d{3}-\d{2}-\d{4}'
        ],
        'API_KEY': [r'API_KEY:\s*[A-Za-z0-9]{8,}']
    })

    # 1. Scan for buckets
    bucket_findings = auditor.scan_s3_buckets()
    assert isinstance(bucket_findings, list)
    assert any(b['name'] == TEST_BUCKET_NAME for b in bucket_findings)

    # 2. Scan for sensitive data
    findings = auditor.scan_for_sensitive_data(bucket_findings)
    assert isinstance(findings, list)
    assert any('SSN' in str(f.get('sensitive_patterns', [])) for f in findings), \
        f"No SSN found in sensitive data findings: {findings}"

    # 3. Generate a report
    report_data = {
        'buckets': bucket_findings,
        'sensitive_data_findings': findings,
        'public_buckets': [],  # required for reporter compatibility
        'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        'scanned_resources': [f"s3::{TEST_BUCKET_NAME}"]
    }

    reporter = StorageReporter(report_data)

    # Generate report and verify structure
    report = reporter.generate_technical_report()
    assert isinstance(report, dict)
    assert 'findings_by_category' in report
    assert 'storage_security' in report['findings_by_category']

    # 4. Test remediation logic
    remediation = StorageRemediation()
    with patch('boto3.client') as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3

        result = remediation.make_bucket_private(TEST_BUCKET_NAME, TEST_REGION)
        assert result['status'] == 'success'
        mock_s3.put_public_access_block.assert_called_once()


@mock_aws
def test_sensitive_data_detection(s3_client):
    """Ensure sensitive data patterns are correctly detected."""
    auditor = StorageAuditor(aws_region=TEST_REGION)

    # Define known test patterns
    auditor.sensitive_patterns.update({
        'SSN': [r'SSN:\s*\d{3}-\d{2}-\d{4}'],
        'API_KEY': [r'API_KEY:\s*[A-Za-z0-9]{8,}']
    })

    # Upload new test file with both patterns
    test_file = 'test-sensitive-detection.txt'
    s3_client.put_object(
        Bucket=TEST_BUCKET_NAME,
        Key=test_file,
        Body=TEST_SENSITIVE_CONTENT,
        ContentType='text/plain'
    )

    # Scan bucket for sensitive data
    bucket_list = [{'name': TEST_BUCKET_NAME, 'region': TEST_REGION}]
    findings = auditor.scan_for_sensitive_data(bucket_list)

    assert isinstance(findings, list), "Findings should be a list"
    file_findings = [f for f in findings if f.get('file') == test_file]
    assert file_findings, f"No findings detected for {test_file}"

    patterns_found = str(file_findings[0].get('sensitive_patterns', []))
    assert 'SSN' in patterns_found, "SSN pattern not detected"
    assert 'API_KEY' in patterns_found, "API_KEY pattern not detected"


def test_report_generation(tmp_path):
    """Test technical report generation with different input data."""
    # Empty case
    empty_data = {
        'buckets': [],
        'sensitive_data_findings': [],
        'public_buckets': [],
        'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        'scanned_resources': []
    }

    reporter = StorageReporter(empty_data)
    empty_report = reporter.generate_technical_report()
    assert isinstance(empty_report, dict)
    assert empty_report['findings_by_category']['storage_security']['summary']['public_buckets'] == 0
    assert empty_report['findings_by_category']['storage_security']['summary']['sensitive_data_findings'] == 0

    # Sample populated case
    sample_data = {
        'buckets': [{'name': 'test-bucket', 'region': TEST_REGION}],
        'sensitive_data_findings': [
            {'file': 'test-file.txt', 'sensitive_patterns': ['SSN'], 'severity': 'high', 'bucket': 'test-bucket'}
        ],
        'public_buckets': [],
        'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        'scanned_resources': ['s3::test-bucket']
    }

    reporter = StorageReporter(sample_data)
    sample_report = reporter.generate_technical_report()
    assert isinstance(sample_report, dict)
    summary = sample_report['findings_by_category']['storage_security']['summary']
    assert summary['public_buckets'] == 0
    assert summary['sensitive_data_findings'] == 1


if __name__ == '__main__':
    pytest.main()
