#!/bin/bash
set -e

echo "🔧 Setting up CI/CD Configuration"
echo "================================"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Setup GitHub Actions symlink
if [ ! -d ".github/workflows" ] && [ -d "ci-cd/github-actions/workflows" ]; then
    echo -e "${BLUE}🔗 Setting up GitHub Actions symlink...${NC}"
    mkdir -p .github
    ln -sf ../ci-cd/github-actions/workflows .github/workflows
    echo -e "${GREEN}✅ GitHub Actions symlink created${NC}"
else
    echo -e "${GREEN}✅ GitHub Actions already configured${NC}"
fi

# Setup pre-commit
if command -v pre-commit &> /dev/null; then
    echo -e "${BLUE}⚙️ Setting up pre-commit hooks...${NC}"
    pre-commit install
    pre-commit install --hook-type commit-msg
    echo -e "${GREEN}✅ pre-commit hooks installed${NC}"
else
    echo -e "${YELLOW}⚠️ pre-commit not installed, skipping hook setup${NC}"
fi

echo ""
echo -e "${GREEN}✅ CI/CD setup completed!${NC}"
echo ""
echo "📋 Available CI/CD workflows:"
echo "  - ${BLUE}ci-cd/github-actions/workflows/ci-cd.yml${NC} - Main CI/CD pipeline"
echo "  - ${BLUE}ci-cd/github-actions/workflows/security-scan.yml${NC} - Security scanning"
echo "  - ${BLUE}ci-cd/github-actions/workflows/release.yml${NC} - Release automation"
echo "  - ${BLUE}ci-cd/gitlab-ci/.gitlab-ci.yml${NC} - GitLab CI configuration"