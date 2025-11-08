#!/bin/bash
set -e

echo "🚀 Installing CloudGuardStack Dependencies"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
    else
        echo -e "${RED}❌ $2${NC}"
        if [ "$3" = "exit" ]; then
            exit 1
        fi
    fi
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package with apt
apt_install() {
    echo -e "${BLUE}📦 Installing $1...${NC}"
    sudo apt-get install -y $1
}

# Function to install via curl
curl_install() {
    local tool_name=$1
    local install_cmd=$2
    echo -e "${BLUE}📦 Installing $tool_name...${NC}"
    eval $install_cmd
}

# Detect OS
OS=$(uname -s)
ARCH=$(uname -m)

echo -e "${YELLOW}🔍 Detected OS: $OS, Architecture: $ARCH${NC}"

# Update package lists
echo -e "${BLUE}🔄 Updating package lists...${NC}"
sudo apt-get update

echo ""
echo "1. INSTALLING TERRAFORM & INFRASTRUCTURE TOOLS"
echo "----------------------------------------------"

# Install tfenv for Terraform version management
if ! command_exists tfenv; then
    echo -e "${BLUE}📦 Installing tfenv...${NC}"
    git clone https://github.com/tfutils/tfenv.git ~/.tfenv
    sudo ln -sf ~/.tfenv/bin/* /usr/local/bin
    print_status $? "tfenv installed"
else
    echo -e "${GREEN}✅ tfenv already installed${NC}"
fi

# Install Terraform using tfenv
if command_exists tfenv; then
    echo -e "${BLUE}📦 Installing Terraform 1.5.0...${NC}"
    tfenv install 1.5.0
    tfenv use 1.5.0
    print_status $? "Terraform 1.5.0 installed"
else
    # Fallback: Install Terraform directly
    echo -e "${YELLOW}⚠️  tfenv not available, installing Terraform directly...${NC}"
    curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
    sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
    sudo apt-get update && sudo apt-get install terraform
    print_status $? "Terraform installed"
fi

echo ""
echo "2. INSTALLING SECURITY SCANNING TOOLS"
echo "-------------------------------------"

# Install Checkov
if ! command_exists checkov; then
    echo -e "${BLUE}📦 Installing Checkov...${NC}"
    pip3 install checkov
    print_status $? "Checkov installed"
else
    echo -e "${GREEN}✅ Checkov already installed${NC}"
fi

# Install tfsec
if ! command_exists tfsec; then
    echo -e "${BLUE}📦 Installing tfsec...${NC}"
    curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
    print_status $? "tfsec installed"
else
    echo -e "${GREEN}✅ tfsec already installed${NC}"
fi

# Install TFLint
if ! command_exists tflint; then
    echo -e "${BLUE}📦 Installing TFLint...${NC}"
    curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash
    print_status $? "TFLint installed"
else
    echo -e "${GREEN}✅ TFLint already installed${NC}"
fi

echo ""
echo "3. INSTALLING POLICY-AS-CODE TOOLS"
echo "----------------------------------"

# Install OPA
if ! command_exists opa; then
    echo -e "${BLUE}📦 Installing OPA...${NC}"
    curl -L -o opa https://openpolicyagent.org/downloads/v0.58.0/opa_linux_amd64_static
    chmod +x opa
    sudo mv opa /usr/local/bin/
    print_status $? "OPA installed"
else
    echo -e "${GREEN}✅ OPA already installed${NC}"
fi

# Install Conftest
if ! command_exists conftest; then
    echo -e "${BLUE}📦 Installing Conftest...${NC}"
    curl -L https://github.com/open-policy-agent/conftest/releases/download/v0.42.1/conftest_0.42.1_Linux_x86_64.tar.gz | tar xz
    sudo mv conftest /usr/local/bin/
    print_status $? "Conftest installed"
else
    echo -e "${GREEN}✅ Conftest already installed${NC}"
fi

echo ""
echo "4. INSTALLING CLOUD CLIs"
echo "------------------------"

# Install AWS CLI v2
if ! command_exists aws; then
    echo -e "${BLUE}📦 Installing AWS CLI v2...${NC}"
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    sudo ./aws/install --update
    rm -rf awscliv2.zip aws/
    print_status $? "AWS CLI v2 installed"
else
    echo -e "${GREEN}✅ AWS CLI already installed${NC}"
fi

# Install Azure CLI
if ! command_exists az; then
    echo -e "${BLUE}📦 Installing Azure CLI...${NC}"
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    print_status $? "Azure CLI installed"
else
    echo -e "${GREEN}✅ Azure CLI already installed${NC}"
fi

# Install Google Cloud CLI
if ! command_exists gcloud; then
    echo -e "${BLUE}📦 Installing Google Cloud CLI...${NC}"
    curl https://sdk.cloud.google.com | bash -s -- --disable-prompts
    source ~/.bashrc
    print_status $? "Google Cloud CLI installed"
else
    echo -e "${GREEN}✅ Google Cloud CLI already installed${NC}"
fi

echo ""
echo "5. INSTALLING CI/CD & AUTOMATION TOOLS"
echo "--------------------------------------"

# Install GitHub CLI
if ! command_exists gh; then
    echo -e "${BLUE}📦 Installing GitHub CLI...${NC}"
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y gh
    print_status $? "GitHub CLI installed"
else
    echo -e "${GREEN}✅ GitHub CLI already installed${NC}"
fi

# Install pre-commit
if ! command_exists pre-commit; then
    echo -e "${BLUE}📦 Installing pre-commit...${NC}"
    pip3 install pre-commit
    print_status $? "pre-commit installed"
else
    echo -e "${GREEN}✅ pre-commit already installed${NC}"
fi

# Install jq for JSON processing
if ! command_exists jq; then
    echo -e "${BLUE}📦 Installing jq...${NC}"
    sudo apt-get install -y jq
    print_status $? "jq installed"
else
    echo -e "${GREEN}✅ jq already installed${NC}"
fi

# Install yq for YAML processing
if ! command_exists yq; then
    echo -e "${BLUE}📦 Installing yq...${NC}"
    sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq
    sudo chmod +x /usr/local/bin/yq
    print_status $? "yq installed"
else
    echo -e "${GREEN}✅ yq already installed${NC}"
fi

echo ""
echo "6. INSTALLING DEVELOPMENT DEPENDENCIES"
echo "--------------------------------------"

# Install Python development tools
echo -e "${BLUE}📦 Installing Python development tools...${NC}"
pip3 install --upgrade pip
pip3 install black flake8 mypy pytest

# Install Go (for potential custom tool development)
if ! command_exists go; then
    echo -e "${BLUE}📦 Installing Go...${NC}"
    wget https://golang.org/dl/go1.20.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
    rm go1.20.linux-amd64.tar.gz
    print_status $? "Go installed"
else
    echo -e "${GREEN}✅ Go already installed${NC}"
fi

echo ""
echo "7. VERIFICATION & POST-INSTALLATION"
echo "-----------------------------------"

# Verify installations
echo -e "${BLUE}🔍 Verifying installations...${NC}"

tools=(
    "terraform:1.5"
    "checkov:2.3"
    "tfsec:0.63"
    "tflint:0.47"
    "opa:0.58"
    "conftest:0.42"
    "aws:2."
    "az:2."
    "gcloud:4."
    "gh:2."
    "pre-commit:3."
    "jq:1.6"
    "yq:4."
)

all_verified=true
for tool_spec in "${tools[@]}"; do
    tool=$(echo $tool_spec | cut -d: -f1)
    min_version=$(echo $tool_spec | cut -d: -f2)
    
    if command_exists $tool; then
        version=$($tool --version 2>/dev/null | head -n1 || echo "unknown")
        if [[ $version == *"$min_version"* ]]; then
            echo -e "${GREEN}✅ $tool: $version${NC}"
        else
            echo -e "${YELLOW}⚠️  $tool: $version (expected: $min_version*)${NC}"
        fi
    else
        echo -e "${RED}❌ $tool: NOT FOUND${NC}"
        all_verified=false
    fi
done

echo ""
echo "8. SETUP CI/CD CONFIGURATION"
echo "---------------------------"

# Create symlink for GitHub Actions if .github doesn't exist
if [ ! -d ".github" ] && [ -d "ci-cd/github-actions" ]; then
    echo -e "${BLUE}🔗 Setting up GitHub Actions symlink...${NC}"
    mkdir -p .github
    ln -sf ../ci-cd/github-actions/workflows .github/workflows
    print_status $? "GitHub Actions configured"
fi

# Initialize pre-commit
if command_exists pre-commit; then
    echo -e "${BLUE}⚙️ Initializing pre-commit...${NC}"
    pre-commit install
    pre-commit install --hook-type commit-msg
    print_status $? "pre-commit hooks installed"
fi


echo ""
echo "📋 INSTALLATION SUMMARY"
echo "----------------------"

if [ "$all_verified" = true ]; then
    echo -e "${GREEN}🎉 All tools installed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  Some tools may need manual installation or configuration${NC}"
fi

echo ""
echo "🚀 NEXT STEPS"
echo "------------"
echo "1. Setup Python environment: ${BLUE}./scripts/setup/setup-python-env.sh${NC}"
echo "2. Configure cloud CLI: ${BLUE}./scripts/setup/setup-cloud-cli.sh${NC}"
echo "3. Verify complete setup: ${BLUE}./scripts/setup/verify-setup.sh${NC}"
echo "4. Authenticate with cloud providers:"
echo "   - ${BLUE}aws configure${NC}"
echo "   - ${BLUE}az login${NC}"
echo "   - ${BLUE}gcloud auth login${NC}"
echo "5. Setup ephemeral accounts: ${BLUE}./scripts/setup/setup-ephemeral-accounts.sh${NC}"

echo ""
echo -e "${GREEN}✅ CloudGuardStack tool installation completed at: $(date)${NC}"