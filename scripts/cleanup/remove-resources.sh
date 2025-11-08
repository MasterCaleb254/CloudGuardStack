#!/bin/bash
set -e

echo "🧹 Cleaning up CloudGuardStack resources..."

# Remove Python virtual environment
if [ -d ".venv" ]; then
    echo "🗑️ Removing Python virtual environment..."
    rm -rf .venv
fi

# Remove Terraform cache
if [ -d "terraform/.terraform" ]; then
    echo "🗑️ Removing Terraform cache..."
    rm -rf terraform/.terraform
fi

# Remove log files
if [ -d "logs" ]; then
    echo "🗑️ Removing log files..."
    rm -rf logs
fi

echo "✅ Local resources cleaned up!"