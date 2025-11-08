# CI/CD Configuration Guide

This document outlines the configuration required for the CloudGuardStack CI/CD pipelines, including required secrets, environment variables, and workflow descriptions.

## GitHub Actions Workflows

The following workflows are defined in `.github/workflows/`:

1. **CI/CD Pipeline** (`ci-cd.yml`)
   - Runs on: Push to `main`/`develop` branches and pull requests to `main`
   - Jobs:
     - Security Scanning (Checkov, TFLint, tfsec)
     - Terraform Validation (fmt, init, validate)
     - Python Testing (unit tests, linting, type checking)
     - Pre-commit Hooks
     - Documentation Generation

2. **Deployment Verification** (`deploy-verify.yml`)
   - Verifies infrastructure deployments

3. **Infrastructure as Code Scanning** (`iac-scan.yml`)
   - Scans Terraform configurations for security and compliance

4. **Policy Enforcement** (`policy-enforce.yml`)
   - Enforces organizational policies

5. **Release Process** (`release.yml`)
   - Manages versioned releases

6. **Security Scanning** (`security-scan.yml`)
   - Performs security scanning of the codebase

## Required GitHub Secrets

The following secrets must be configured in your GitHub repository settings (Settings > Secrets and variables > Actions):

| Secret Name | Description | Required For |
|-------------|-------------|--------------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID | Terraform deployments, AWS CLI operations |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key | Terraform deployments, AWS CLI operations |
| `AWS_REGION` | Default AWS region | Terraform deployments |
| `TF_API_TOKEN` | Terraform Cloud API token | Remote state management |
| `CODECOV_TOKEN` | Codecov upload token | Test coverage reporting |
| `SLACK_WEBHOOK_URL` | Slack webhook URL | Notifications |

## Required Environment Variables

These variables should be set in your GitHub repository settings or workflow files:

| Variable | Default | Description |
|----------|---------|-------------|
| `TERRAFORM_VERSION` | 1.5.0 | Version of Terraform to use |
| `PYTHON_VERSION` | 3.9 | Version of Python to use |
| `ENVIRONMENT` | dev | Deployment environment (dev/stage/prod) |

## Setup Instructions

1. **Repository Configuration**
   - Enable GitHub Actions in your repository settings
   - Add all required secrets in GitHub repository settings
   - Ensure branch protection rules are configured for `main` and `develop` branches

2. **Local Development Setup**
   ```bash
   # Install pre-commit hooks
   pre-commit install
   
   # Install development dependencies
   pip install -e .[dev]
   ```

3. **Workflow Configuration**
   - Customize workflow files in `.github/workflows/` as needed
   - Update Python and Terraform versions in the workflow files if required

## Troubleshooting

1. **Workflow Failures**
   - Check the Actions tab in GitHub for detailed error logs
   - Ensure all required secrets are properly configured
   - Verify that IAM permissions are correctly set up

2. **Local Testing**
   ```bash
   # Run tests locally
   pytest tests/ -v
   
   # Run security scans
   checkov -d .
   tflint
   tfsec .
   ```

## Best Practices

1. **Branch Protection**
   - Require status checks to pass before merging
   - Require pull request reviews before merging
   - Restrict who can push to protected branches

2. **Secret Management**
   - Never commit secrets to version control
   - Use GitHub Secrets for sensitive values
   - Rotate credentials regularly

3. **Workflow Optimization**
   - Use caching for dependencies
   - Run jobs in parallel when possible
   - Set appropriate timeouts for long-running jobs
