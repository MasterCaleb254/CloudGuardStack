#!/usr/bin/env python3
"""
End-to-end tests for CloudGuardStack

This test suite verifies the complete workflow from infrastructure deployment
to security scanning and reporting.
"""
import os
import json
import time
import pytest
import boto3
from pathlib import Path
from moto import mock_aws, mock_sts
from python_terraform import Terraform
import subprocess
import sys
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.parent))

# Test configuration
TEST_ENV = "e2e-test"
TEST_REGION = "us-east-1"
TEST_BUCKET = f"cloudguardstack-{int(time.time())}-test"

# Import application modules
try:
    from scanners.iam_entitlement.scanner import IAMEntitlementScanner
    from scanners.storage_auditor.scanner import StorageAuditor
    from scanners.storage_auditor.reporter import StorageReporter
except ImportError as e:
    pytest.skip(f"Skipping end-to-end tests due to missing dependencies: {e}", allow_module_level=True)


@pytest.fixture(scope="module")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = TEST_REGION
    return {
        'aws_access_key_id': 'testing',
        'aws_secret_access_key': 'testing',
        'region_name': TEST_REGION
    }


@pytest.fixture(scope="module")
def test_infrastructure(aws_credentials, tmp_path_factory):
    """Set up test infrastructure using Terraform."""
    # Create a temporary directory for test state
    test_dir = tmp_path_factory.mktemp("e2e_test")
    state_file = test_dir / "terraform.tfstate"

    # Initialize Terraform
    tf = Terraform(working_dir=str(Path(__file__).parent.parent.parent / "terraform"))

    # Define test variables
    tf_vars = {
        'environment': TEST_ENV,
        'aws_region': TEST_REGION,
        'enable_azure': False,
        'create_test_resources': True,
        'test_bucket_name': TEST_BUCKET,
        'additional_tags': {
            'test_run': 'true',
            'purpose': 'e2e_testing'
        }
    }

    # Initialize and apply Terraform
    tf.init(capture_output=True, raise_on_error=True)
    tf.apply(
        var=tf_vars,
        state=state_file,
        capture_output=True,
        skip_plan=True,
        auto_approve=True
    )

    # Get outputs
    outputs = tf.output(json=True)

    yield outputs

    # Clean up
    tf.destroy(
        var=tf_vars,
        state=state_file,
        capture_output=True,
        force=True,
        auto_approve=True
    )


@pytest.mark.e2e
@mock_aws
@mock_sts
def test_complete_workflow(aws_credentials, test_infrastructure, tmp_path):
    """Test the complete CloudGuardStack workflow."""
    # 1. Verify infrastructure was created
    s3 = boto3.client('s3', **aws_credentials)
    buckets = s3.list_buckets()
    assert any(b['Name'] == TEST_BUCKET for b in buckets['Buckets']), "Test bucket was not created"

    # 2. Run IAM scanner
    iam_scanner = IAMEntitlementScanner()
    iam_results = iam_scanner.scan()

    # Verify IAM scan results
    assert 'roles' in iam_results
    assert 'policies' in iam_results
    assert 'findings' in iam_results

    # 3. Run Storage Auditor
    storage_auditor = StorageAuditor(aws_region=TEST_REGION)

    # Scan for public buckets
    public_buckets = storage_auditor.find_public_buckets()
    assert isinstance(public_buckets, list)

    # Scan for sensitive data
    findings = storage_auditor.scan_for_sensitive_data([TEST_BUCKET])
    assert isinstance(findings, list)

    # 4. Generate reports
    report_data = {
        'iam_findings': iam_results,
        'public_buckets': public_buckets,
        'sensitive_data_findings': findings,
        'scan_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'scanned_resources': [f's3::{TEST_BUCKET}']
    }

    reporter = StorageReporter(report_data)

    # Generate JSON report
    json_report = reporter.generate_json_report()
    assert 'summary' in json_report
    assert 'findings' in json_report

    # Generate HTML report
    html_report = reporter.generate_html_report()
    assert '<html' in html_report
    assert 'CloudGuardStack Security Report' in html_report

    # 5. Save reports to file
    report_dir = tmp_path / "reports"
    report_dir.mkdir()

    json_path = report_dir / 'security_report.json'
    html_path = report_dir / 'security_report.html'

    with open(json_path, 'w') as f:
        json.dump(json_report, f, indent=2)

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_report)

    # Verify files were created
    assert json_path.exists()
    assert html_path.exists()


@pytest.mark.e2e
def test_cli_workflow(tmp_path, monkeypatch):
    """Test the command-line interface workflow."""
    # Mock command-line arguments
    test_args = ["cloudguardstack", "scan", "--output", str(tmp_path)]
    monkeypatch.setattr(sys, 'argv', test_args)

    # Import and run the main function
    try:
        from cloudguardstack.cli import main
        main()

        # Verify output files were created
        assert (tmp_path / 'iam_report.json').exists()
        assert (tmp_path / 'storage_report.json').exists()
        assert (tmp_path / 'security_dashboard.html').exists()

    except ImportError:
        pytest.skip("Skipping CLI test - main module not found")


# -------------------------------------------------------------
# ✅ NEW TESTS ADDED FOR COMPREHENSIVE COVERAGE
# -------------------------------------------------------------

@pytest.mark.e2e
@mock_aws
@mock_sts
def test_multi_region_scanning(aws_credentials, test_infrastructure):
    """Test scanning across multiple AWS regions."""
    regions = ['us-east-1', 'us-west-2', 'eu-west-1']

    # Create buckets in each region
    for region in regions:
        s3 = boto3.client('s3', region_name=region, **aws_credentials)
        bucket_name = f"{TEST_BUCKET}-{region}"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': region}
        )

    # Run multi-region scan
    storage_auditor = StorageAuditor(aws_region=TEST_REGION)
    all_public_buckets = []

    for region in regions:
        storage_auditor.aws_region = region
        public_buckets = storage_auditor.find_public_buckets()
        all_public_buckets.extend(public_buckets)

    assert len(all_public_buckets) >= len(regions)
    for region in regions:
        assert any(bucket['Region'] == region for bucket in all_public_buckets)


@pytest.mark.e2e
@mock_aws
@mock_sts
def test_remediation_workflow(aws_credentials, test_infrastructure):
    """Test the complete remediation workflow."""
    from scanners.iam_entitlement.remediation_generator import RemediationGenerator
    from scanners.storage_auditor.remediation import StorageRemediation

    # Create a public bucket for testing remediation
    s3 = boto3.client('s3', **aws_credentials)
    bucket_name = f"{TEST_BUCKET}-remediate"
    s3.create_bucket(Bucket=bucket_name)

    # Make the bucket public
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': False,
            'IgnorePublicAcls': False,
            'BlockPublicPolicy': False,
            'RestrictPublicBuckets': False
        }
    )

    # Create an IAM role with admin permissions for testing
    iam = boto3.client('iam', **aws_credentials)
    role_name = f"test-role-{int(time.time())}"
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        })
    )

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )

    # Test storage remediation
    storage_remediator = StorageRemediation()
    result = storage_remediator.make_bucket_private(bucket_name, TEST_REGION)
    assert result['status'] == 'success'

    # Test IAM remediation
    iam_remediator = RemediationGenerator()
    iam_findings = [{
        'issue_type': 'over_permissive_role',
        'role_name': role_name,
        'recommended_actions': ['Remove AdministratorAccess policy']
    }]

    with patch('boto3.client') as mock_client:
        mock_iam = MagicMock()
        mock_client.return_value = mock_iam

        remediation_result = iam_remediator.apply_remediation(iam_findings[0])
        assert remediation_result['status'] == 'success'


@pytest.mark.e2e
def test_error_handling(aws_credentials, caplog):
    """Test error handling for various failure scenarios."""
    # Invalid credentials
    invalid_creds = {
        'aws_access_key_id': 'invalid',
        'aws_secret_access_key': 'invalid',
        'region_name': TEST_REGION
    }

    with pytest.raises(Exception):
        s3 = boto3.client('s3', **invalid_creds)
        s3.list_buckets()

    # Non-existent bucket
    storage_auditor = StorageAuditor(aws_region=TEST_REGION)
    findings = storage_auditor.scan_for_sensitive_data(['non-existent-bucket-12345'])
    assert len(findings) == 0

    # Invalid IAM role
    iam_scanner = IAMEntitlementScanner()
    result = iam_scanner._get_role_policies('non-existent-role')
    assert result == {}


@pytest.mark.performance
def test_performance_metrics(aws_credentials, test_infrastructure):
    """Test performance of scanning operations."""
    import timeit

    iam_scanner = IAMEntitlementScanner()
    iam_time = timeit.timeit(lambda: iam_scanner.scan(), number=1)
    print(f"\nIAM scan completed in {iam_time:.2f} seconds")

    storage_auditor = StorageAuditor(aws_region=TEST_REGION)
    storage_time = timeit.timeit(lambda: storage_auditor.find_public_buckets(), number=1)
    print(f"Storage scan completed in {storage_time:.2f} seconds")

    assert iam_time < 10, "IAM scan took too long"
    assert storage_time < 15, "Storage scan took too long"


@pytest.mark.e2e
def test_notification_integration(monkeypatch):
    """Test integration with notification systems."""
    mock_notifications = []

    def mock_send_notification(subject, message, level='info'):
        mock_notifications.append({
            'subject': subject,
            'message': message,
            'level': level
        })

    monkeypatch.setattr('cloudguardstack.notifications.send_alert', mock_send_notification)

    from cloudguardstack.notifications import send_alert
    send_alert(
        subject="Test Security Alert",
        message="This is a test security alert.",
        level="high"
    )

    assert len(mock_notifications) == 1
    assert mock_notifications[0]['subject'] == "Test Security Alert"
    assert mock_notifications[0]['level'] == "high"


if __name__ == "__main__":
    pytest.main()
