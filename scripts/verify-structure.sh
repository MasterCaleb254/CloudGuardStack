#!/bin/bash

echo "📁 Verifying CloudGuardStack directory structure..."

expected_files=(
    "scripts/setup/install-tools.sh"
    "scripts/setup/setup-python-env.sh" 
    "scripts/setup/setup-cloud-cli.sh"
    "scripts/setup/verify-setup.sh"
    "scripts/setup/setup-ephemeral-accounts.sh"
    "scripts/utilities/teardown-ephemeral-accounts.sh"
    "scripts/utilities/teardown-aws-account.sh"
    "scripts/utilities/backup-config.sh"
    "scripts/cleanup/remove-resources.sh"
    "terraform/modules/aws-baseline/main.tf"
    "terraform/modules/azure-baseline/main.tf" 
    "terraform/modules/gcp-baseline/main.tf"
    "scanners/iam-entitlement/scanner.py"
    "scanners/storage-auditor/scanner.py"
    "policies/aws-scp.json"
    "pyproject.toml"
    "README.md"
)

all_good=true
for file in "${expected_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file - MISSING"
        all_good=false
    fi
done

if [ "$all_good" = true ]; then
    echo "🎉 All files are in correct locations!"
else
    echo "⚠️ Some files are missing. Please check the structure."
    exit 1
fi