#!/bin/bash
set -e

echo "🧪 Testing Ephemeral Account Automation"
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
TEST_TIMEOUT=1800  # 30 minutes
EPHEMERAL_LIFETIME=48  # 48 hours

# Create test directory
TEST_DIR="test-results/$(date +%Y%m%d_%H%M%S)"
mkdir -p $TEST_DIR

echo -e "${BLUE}1. Setting up ephemeral accounts...${NC}"
./scripts/setup/setup-ephemeral-accounts.sh

echo -e "${BLUE}2. Deploying security baseline...${NC}"
cd terraform/environments/ephemeral
terraform init
terraform apply -auto-approve

echo -e "${BLUE}3. Running security scans...${NC}"
cd ../../..
./scripts/iam-scan/run-entitlement-scan.sh
./scripts/storage-scan/run-storage-audit.sh

echo -e "${BLUE}4. Testing CI/CD workflows...${NC}"
# Simulate CI/CD pipeline
python scripts/ci/simulate-p