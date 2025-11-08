#!/bin/bash


#!/bin/bash

echo "🔍 Verifying CloudGuardStack setup..."

# Check if setup scripts are executable
echo "📋 Checking script permissions..."
chmod +x scripts/setup/*.sh
chmod +x scripts/utilities/*.sh


# Check tool versions
echo "📋 Tool Versions:"
terraform version | head -1
checkov --version | head -1
tfsec --version | head -1
conftest --version | head -1
opa version

# Check Python environment
echo "🐍 Python Environment:"
if [ -d ".venv" ]; then
    source .venv/bin/activate
    python --version
    pip list | grep -E "(boto3|azure|google-cloud)"
else
    echo "❌ Python virtual environment not found. Run scripts/setup-python-env.sh"
fi

# Check cloud authentication
echo "🌐 Cloud Authentication:"
aws sts get-caller-identity --query "Account" --output text && echo "✅ AWS Authenticated" || echo "❌ AWS Auth Failed"
az account show --query "name" --output tsv && echo "✅ Azure Authenticated" || echo "❌ Azure Auth Failed"
gcloud config list --format="value(core.project)" 2>/dev/null && echo "✅ GCP Authenticated" || echo "❌ GCP Auth Failed"

# Validate Terraform modules
echo "🏗️ Terraform Validation:"
cd terraform
terraform validate
cd ..

# Check directory structure
echo "📁 Project Structure:"
find . -type f -name "*.tf" -o -name "*.py" -o -name "*.md" -o -name "*.sh" -o -name "*.yml" -o -name "*.yaml" | grep -v ".git" | sort

echo "✅ Enhanced setup verification complete!"

echo "✅ Enhanced setup verification complete!"
echo "📋 All scripts are in correct locations:"


echo ""
echo "🔄 CI/CD & Automation Tools:"
echo "---------------------------"

# Check CI/CD tools
ci_tools=("pre-commit" "gh" "jq" "yq")
for tool in "${ci_tools[@]}"; do
    if command -v $tool &> /dev/null; then
        version=$($tool --version 2>/dev/null | head -n1)
        echo -e "${GREEN}✅ $tool: $version${NC}"
    else
        echo -e "${RED}❌ $tool: NOT FOUND${NC}"
    fi
done

# Check CI/CD configuration
echo ""
echo "🔧 CI/CD Configuration:"
echo "----------------------"

if [ -f "ci-cd/github-actions/workflows/ci-cd.yml" ]; then
    echo -e "${GREEN}✅ GitHub Actions: Workflows configured${NC}"
else
    echo -e "${YELLOW}⚠️  GitHub Actions: Workflows not found${NC}"
fi

if [ -f "ci-cd/gitlab-ci/.gitlab-ci.yml" ]; then
    echo -e "${GREEN}✅ GitLab CI: Configuration found${NC}"
else
    echo -e "${YELLOW}⚠️  GitLab CI: Configuration not found${NC}"
fi

if [ -f ".pre-commit-config.yaml" ]; then
    echo -e "${GREEN}✅ pre-commit: Config found${NC}"
    if pre-commit run --all-files &> /dev/null; then
        echo -e "${GREEN}✅ pre-commit hooks: Installed${NC}"
    else
        echo -e "${YELLOW}⚠️  pre-commit hooks: Not installed (run 'pre-commit install')${NC}"
    fi
fi

# Check if GitHub Actions symlink exists
if [ -L ".github/workflows" ] && [ -d "ci-cd/github-actions/workflows" ]; then
    echo -e "${GREEN}✅ GitHub Actions: Symlink configured${NC}"
else
    echo -e "${YELLOW}⚠️  GitHub Actions: Symlink not configured${NC}"
    echo -e "${BLUE}💡 Run: mkdir -p .github && ln -sf ../ci-cd/github-actions/workflows .github/workflows${NC}"
fi