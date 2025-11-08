#!/usr/bin/env python3
"""
Integration tests for Terraform deployment
"""
import os
import json
import pytest
import boto3
from python_terraform import Terraform, IsFlagged, IsNotFlagged
from moto import mock_aws, mock_sts
from pathlib import Path
import time

# Add the project root to the Python path
import sys
sys.path.append(str(Path(__file__).parent.parent))

# Test configuration
TEST_ENV = "test"
TF_DIR = str(Path(__file__).parent.parent.parent / "terraform")
TF_VARS = {
    "environment": TEST_ENV,
    "aws_region": "us-east-1",
    "enable_azure": False,
    "additional_tags": {
        "test_run_id": f"test_{int(time.time())}"
    }
}

@pytest.fixture(scope="module")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = TF_VARS["aws_region"]

@pytest.fixture(scope="module")
def terraform():
    """Initialize and return a Terraform instance."""
    tf = Terraform(working_dir=TF_DIR)
    return tf

@pytest.fixture(scope="module")
def terraform_init(terraform):
    """Initialize Terraform and return the output."""
    return terraform.init(capture_output=True, raise_on_error=True)

@pytest.mark.integration
@mock_aws
@mock_sts
def test_terraform_plan(terraform, terraform_init, aws_credentials):
    """Test that Terraform plan runs successfully."""
    # Run terraform plan
    return_code, stdout, stderr = terraform.plan(
        var=TF_VARS,
        capture_output=True,
        raise_on_error=True
    )
    
    assert return_code == 0, f"Terraform plan failed with: {stderr}"
    assert "Plan:" in stdout, "Terraform plan output is not as expected"

@pytest.mark.integration
@mock_aws
@mock_sts
def test_terraform_apply(terraform, terraform_init, aws_credentials, tmp_path):
    """Test that Terraform apply runs successfully and creates expected resources."""
    # Create a test state file in a temporary directory
    state_file = tmp_path / "terraform.tfstate"
    
    # Run terraform apply
    return_code, stdout, stderr = terraform.apply(
        var=TF_VARS,
        state=state_file,
        capture_output=True,
        skip_plan=True,
        input=False,
        auto_approve=True
    )
    
    assert return_code == 0, f"Terraform apply failed with: {stderr}"
    assert "Apply complete!" in stdout, "Terraform apply did not complete successfully"
    
    # Verify the state file was created
    assert state_file.exists(), "Terraform state file was not created"
    
    # Load the state file and verify its structure
    with open(state_file) as f:
        state = json.load(f)
    
    # Verify the state contains the expected resources
    assert 'resources' in state, "No resources found in the state file"
    
    # Get the AWS account ID from the state
    account_id = None
    for resource in state.get('resources', []):
        if resource.get('type') == 'aws_caller_identity' and resource.get('name') == 'current':
            account_id = resource.get('instances', [{}])[0].get('attributes', {}).get('account_id')
            break
    
    assert account_id is not None, "AWS account ID not found in the state file"
    
    # Verify the outputs
    outputs = terraform.output(json=True)
    assert 'account_info' in outputs, "account_info output not found"
    assert outputs['account_info']['value']['aws_account_id'] == account_id

@pytest.mark.integration
@mock_aws
@mock_sts
def test_terraform_destroy(terraform, terraform_init, aws_credentials, tmp_path):
    """Test that Terraform destroy runs successfully."""
    # Use the same state file as the apply test
    state_file = tmp_path / "terraform.tfstate"
    
    # Run terraform destroy
    return_code, stdout, stderr = terraform.destroy(
        var=TF_VARS,
        state=state_file,
        capture_output=True,
        force=True,
        auto_approve=True
    )
    
    assert return_code == 0, f"Terraform destroy failed with: {stderr}"
    assert "Destroy complete!" in stdout, "Terraform destroy did not complete successfully"

@pytest.mark.integration
def test_terraform_validate(terraform, terraform_init):
    """Test that Terraform configuration is valid."""
    return_code, stdout, stderr = terraform.validate(
        capture_output=True,
        json=True
    )
    
    assert return_code == 0, f"Terraform validate failed with: {stderr}"
    
    # Parse the JSON output
    try:
        validation = json.loads(stdout)
        assert validation['valid'], "Terraform configuration is not valid"
    except json.JSONDecodeError:
        pytest.fail("Terraform validate did not return valid JSON")

if __name__ == "__main__":
    pytest.main()