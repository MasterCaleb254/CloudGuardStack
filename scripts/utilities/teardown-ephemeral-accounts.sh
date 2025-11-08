#!/bin/bash
set -e

echo "🌐 Starting ephemeral account teardown..."

# AWS Teardown
if command -v aws &> /dev/null; then
    echo "🗑️ Tearing down AWS resources..."
    ./scripts/teardown-aws-account.sh
fi

# Azure Teardown
if command -v az &> /dev/null; then
    echo "🗑️ Tearing down Azure resources..."
    az group delete --name "rg-cloudguardstack-ephemeral" --yes --no-wait || true
fi

# GCP Teardown
if command -v gcloud &> /dev/null; then
    echo "🗑️ Tearing down GCP resources..."
    gcloud projects delete "$(gcloud config get-value project)" --quiet || true
fi

echo "✅ Ephemeral account teardown complete!"
echo "⏰ Remember: Full account deletion may require manual intervention in the cloud console"