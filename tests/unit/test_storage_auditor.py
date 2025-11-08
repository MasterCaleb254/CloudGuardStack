#!/usr/bin/env python3
"""
Comprehensive unit tests for the Storage Auditor & Reporter modules
Expands coverage to include:
- StorageAuditor core methods (pattern matching, scanning, configs)
- StorageReporter reporting, summaries, compliance, and file saving
"""

import io
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timezone

from scanners.storage_auditor.scanner import StorageAuditor
from scanners.storage_auditor.reporter import StorageReporter


# --- Mock Azure imports for safety ---
import sys
sys.modules['azure'] = MagicMock()
sys.modules['azure.storage'] = MagicMock()
sys.modules['azure.storage.blob'] = MagicMock()
sys.modules['azure.identity'] = MagicMock()

# === Shared Constants ===
TEST_BUCKET_NAME = "test-bucket"
TEST_REGION = "us-west-2"
TEST_SENSITIVE_CONTENT = b"User SSN: 123-45-6789\nAPI_KEY: abc123xyz456"


# ---------------------------------------------------------------------
# STORAGE AUDITOR TESTS
# ---------------------------------------------------------------------
@pytest.fixture
def storage_auditor():
    """Create a StorageAuditor instance with mock AWS session"""
    with patch('boto3.Session') as mock_session:
        mock_s3 = MagicMock()
        mock_session.return_value.client.return_value = mock_s3
        auditor = StorageAuditor(aws_profile='test-profile', aws_region=TEST_REGION)
        auditor.s3 = mock_s3
        return auditor


def test_scan_s3_buckets_public_access(storage_auditor):
    """Ensure public bucket detection works"""
    storage_auditor.s3.list_buckets.return_value = {
        'Buckets': [{'Name': TEST_BUCKET_NAME, 'CreationDate': datetime(2024, 1, 1, tzinfo=timezone.utc)}]
    }
    storage_auditor.s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': False,
            'IgnorePublicAcls': False,
            'BlockPublicPolicy': False,
            'RestrictPublicBuckets': False
        }
    }
    storage_auditor.s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}]
    }

    results = storage_auditor.scan_s3_buckets()
    assert results
    assert any('public' in str(f).lower() for r in results for f in r['findings'])


def test_check_for_sensitive_patterns(storage_auditor):
    """Verify regex detection of sensitive strings"""
    matches = storage_auditor._check_for_sensitive_patterns("SSN: 123-45-6789\nAPI_KEY: x")
    assert any("SSN" in str(m) or "API_KEY" in str(m) for m in matches)


def test_scan_s3_bucket_for_sensitive_data(storage_auditor):
    """Ensure S3 bucket content scanning works"""
    storage_auditor.s3.list_objects_v2.return_value = {'Contents': [{'Key': 'data.txt'}]}
    storage_auditor.s3.get_object.return_value = {'Body': MagicMock(read=lambda: TEST_SENSITIVE_CONTENT)}
    results = storage_auditor._scan_s3_bucket_for_sensitive_data(TEST_BUCKET_NAME)
    assert isinstance(results, list)
    assert any('SSN' in str(f['sensitive_patterns']) for f in results)


def test_get_bucket_public_access_variants(storage_auditor):
    """Check both public and private access flags"""
    storage_auditor.s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': False, 'IgnorePublicAcls': False,
            'BlockPublicPolicy': False, 'RestrictPublicBuckets': False
        }
    }
    assert storage_auditor._get_bucket_public_access(TEST_BUCKET_NAME)['is_public'] is True

    storage_auditor.s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
        }
    }
    assert storage_auditor._get_bucket_public_access(TEST_BUCKET_NAME)['is_public'] is False


def test_check_bucket_encryption_and_versioning(storage_auditor):
    """Check encryption and versioning detection"""
    storage_auditor.s3.get_bucket_encryption.return_value = {
        'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}
    }
    enc = storage_auditor._check_bucket_encryption(TEST_BUCKET_NAME)
    assert enc['encryption'] == 'AES256'

    storage_auditor.s3.get_bucket_encryption.side_effect = Exception("no encryption")
    assert storage_auditor._check_bucket_encryption(TEST_BUCKET_NAME)['encryption'] is None

    storage_auditor.s3.get_bucket_versioning.return_value = {'Status': 'Enabled'}
    assert storage_auditor._check_versioning(TEST_BUCKET_NAME)['versioning'] is True

    storage_auditor.s3.get_bucket_versioning.return_value = {}
    assert storage_auditor._check_versioning(TEST_BUCKET_NAME)['versioning'] is False


# ---------------------------------------------------------------------
# STORAGE REPORTER TESTS
# ---------------------------------------------------------------------
@pytest.fixture
def sample_report_data():
    return {
        "buckets": [
            {"name": TEST_BUCKET_NAME, "region": TEST_REGION, "findings": ["public access"]}
        ],
        "sensitive_data_findings": [
            {"file": "data.txt", "bucket": TEST_BUCKET_NAME, "sensitive_patterns": ["SSN"], "severity": "high"}
        ],
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scanned_resources": [f"s3::{TEST_BUCKET_NAME}"]
    }


def test_generate_executive_summary(sample_report_data):
    """Ensure executive summary contains correct aggregated information"""
    reporter = StorageReporter(sample_report_data)
    summary = reporter.generate_executive_summary()
    assert isinstance(summary, dict)
    assert summary["total_buckets"] == len(sample_report_data["buckets"])
    assert summary["total_findings"] == len(sample_report_data["sensitive_data_findings"])
    assert "high_risk_findings" in summary


def test_generate_compliance_report(sample_report_data):
    """Validate compliance report formatting and section generation"""
    reporter = StorageReporter(sample_report_data)
    report = reporter.generate_compliance_report()
    assert "compliance_summary" in report
    assert "policy_gaps" in report
    assert isinstance(report["compliance_summary"], dict)


@patch("builtins.open", new_callable=mock_open)
def test_save_reports_json_and_txt(mock_file, sample_report_data):
    """Ensure save_reports writes files in different formats"""
    reporter = StorageReporter(sample_report_data)
    reporter.save_reports(base_path="/tmp/test_report")

    # Ensure open() was called for at least one file type
    assert mock_file.called
    written_files = [call.args[0] for call in mock_file.mock_calls if call[0] == '']
    assert any(".json" in f or ".txt" in f for f in written_files)


def test_generate_technical_report_and_invalid_input(sample_report_data):
    """Ensure technical report generation and input validation work"""
    reporter = StorageReporter(sample_report_data)
    report = reporter.generate_technical_report()
    assert isinstance(report, dict)
    assert "summary" in report

    # Test invalid input handling
    with pytest.raises((TypeError, KeyError)):
        StorageReporter(None).generate_technical_report()


def test_report_formatting_edge_cases():
    """Edge case: empty and malformed data handling"""
    empty_reporter = StorageReporter({
        "buckets": [],
        "sensitive_data_findings": [],
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scanned_resources": []
    })
    report = empty_reporter.generate_technical_report()
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["total_buckets"] == 0

    # malformed bucket data
    malformed_data = {"buckets": [{}], "sensitive_data_findings": []}
    malformed_reporter = StorageReporter(malformed_data)
    malformed_report = malformed_reporter.generate_technical_report()
    assert "summary" in malformed_report
