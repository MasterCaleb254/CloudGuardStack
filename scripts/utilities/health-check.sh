#!/bin/bash
set -e

echo "🏥 CloudGuardStack Health Check"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
    else
        echo -e "${RED}❌ $2${NC}"
    fi
}

# Function to check command availability
check_command() {
    if command -v $1 &> /dev/null; then
        echo 0
    else
        echo 1
    fi
}

# Function to check service status
check_service() {
    case $1 in
        "aws")
            aws sts get-caller-identity &> /dev/null
            echo $?
            ;;
        "azure")
            az account show &> /dev/null
            echo $?
            ;;
        "gcp")
            gcloud config list --format="value(core.project)" &> /dev/null
            echo $?
            ;;
        *)
            echo 1
            ;;
    esac
}

echo ""
echo "🔧 Tool Availability Check:"
echo "---------------------------"

# Check required tools
tools=("terraform" "python3" "pip" "aws" "az" "gcloud" "checkov" "tfsec" "opa" "conftest")
for tool in "${tools[@]}"; do
    status=$(check_command $tool)
    print_status $status "$tool"
done

echo ""
echo "🌐 Cloud Service Connectivity:"
echo "-----------------------------"

# Check cloud connectivity
clouds=("aws" "azure" "gcp")
for cloud in "${clouds[@]}"; do
    status=$(check_service $cloud)
    if [ $status -eq 0 ]; then
        echo -e "${GREEN}✅ $cloud - Authenticated${NC}"
        
        # Additional cloud-specific checks
        case $cloud in
            "aws")
                # Check if we're in an ephemeral account
                account_id=$(aws sts get-caller-identity --query "Account" --output text 2>/dev/null || echo "unknown")
                region=$(aws configure get region || echo "us-east-1")
                echo -e "   📋 Account: $account_id, Region: $region"
                
                # Check CloudTrail status
                if aws cloudtrail describe-trails --trail-name-list cloudguardstack-audit-trail &> /dev/null; then
                    echo -e "   📊 CloudTrail: ${GREEN}Enabled${NC}"
                else
                    echo -e "   📊 CloudTrail: ${YELLOW}Not Found${NC}"
                fi
                ;;
            "azure")
                subscription=$(az account show --query "name" --output tsv 2>/dev/null || echo "unknown")
                echo -e "   📋 Subscription: $subscription"
                ;;
            "gcp")
                project=$(gcloud config get-value project 2>/dev/null || echo "unknown")
                echo -e "   📋 Project: $project"
                ;;
        esac
    else
        echo -e "${YELLOW}⚠️  $cloud - Not authenticated${NC}"
    fi
done

echo ""
echo "📁 Project Structure Check:"
echo "---------------------------"

# Check critical directories and files
critical_paths=(
    "terraform/modules/aws-baseline/main.tf"
    "terraform/modules/azure-baseline/main.tf"
    "terraform/modules/gcp-baseline/main.tf"
    "scanners/iam-entitlement/scanner.py"
    "scanners/storage-auditor/scanner.py"
    "policies/aws-scp.json"
    "pyproject.toml"
    "scripts/setup/install-tools.sh"
)

for path in "${critical_paths[@]}"; do
    if [ -f "$path" ]; then
        echo -e "${GREEN}✅ $path${NC}"
    else
        echo -e "${RED}❌ $path - Missing${NC}"
    fi
done

echo ""
echo "🐍 Python Environment Check:"
echo "---------------------------"

# Check Python environment
if [ -d ".venv" ]; then
    source .venv/bin/activate
    python_version=$(python --version 2>&1)
    pip_version=$(pip --version 2>&1 | cut -d' ' -f2)
    
    echo -e "${GREEN}✅ Virtual Environment: Active${NC}"
    echo -e "   📋 Python: $python_version"
    echo -e "   📦 pip: $pip_version"
    
    # Check critical Python packages
    packages=("boto3" "azure-identity" "google-cloud-storage" "pandas" "matplotlib")
    for pkg in "${packages[@]}"; do
        if pip show $pkg &> /dev/null; then
            version=$(pip show $pkg | grep Version | cut -d' ' -f2)
            echo -e "   📦 $pkg: ${GREEN}$version${NC}"
        else
            echo -e "   📦 $pkg: ${RED}Not Installed${NC}"
        fi
    done
else
    echo -e "${YELLOW}⚠️  Virtual Environment: Not found${NC}"
    echo -e "   💡 Run: ./scripts/setup/setup-python-env.sh"
fi

echo ""
echo "💾 Resource Usage:"
echo "------------------"

# Check disk space
disk_usage=$(df -h . | awk 'NR==2 {print $5 " used (" $3 "/" $2 ")"}')
echo -e "📊 Disk Usage: $disk_usage"

# Check memory usage
memory_usage=$(free -h | awk 'NR==2 {print $3 "/" $2 " used"}')
echo -e "🧠 Memory Usage: $memory_usage"

echo ""
echo "🔍 Security Baseline Status:"
echo "---------------------------"

# Check if security tools are functioning
if command -v checkov &> /dev/null; then
    echo -e "${GREEN}✅ Checkov: Operational${NC}"
else
    echo -e "${RED}❌ Checkov: Not working${NC}"
fi

if command -v tfsec &> /dev/null; then
    echo -e "${GREEN}✅ tfsec: Operational${NC}"
else
    echo -e "${RED}❌ tfsec: Not working${NC}"
fi

if command -v opa &> /dev/null; then
    echo -e "${GREEN}✅ OPA: Operational${NC}"
else
    echo -e "${RED}❌ OPA: Not working${NC}"
fi

echo ""
echo "📋 Health Check Summary:"
echo "-----------------------"

# Count successes and failures
success_count=$(grep -c "✅" <<< "$(grep -e "✅" -e "❌" -e "⚠️" <<< "$(cat $0)")")
fail_count=$(grep -c "❌" <<< "$(grep -e "✅" -e "❌" -e "⚠️" <<< "$(cat $0)")")
warn_count=$(grep -c "⚠️" <<< "$(grep -e "✅" -e "❌" -e "⚠️" <<< "$(cat $0)")")

echo -e "✅ Success: $success_count | ⚠️  Warnings: $warn_count | ❌ Failures: $fail_count"

if [ $fail_count -eq 0 ]; then
    echo -e "\n🎉 ${GREEN}All systems operational! CloudGuardStack is healthy.${NC}"
else
    echo -e "\n🔧 ${YELLOW}Some issues detected. Please check the failed items above.${NC}"
fi

echo ""
echo "💡 Recommended Actions:"
if [ ! -d ".venv" ]; then
    echo "   - Run: ./scripts/setup/setup-python-env.sh"
fi
if ! aws sts get-caller-identity &> /dev/null; then
    echo "   - Configure AWS credentials"
fi
if ! az account show &> /dev/null; then
    echo "   - Run: az login"
fi
if ! gcloud config list &> /dev/null; then
    echo "   - Run: gcloud auth login"
fi

echo ""
echo "🏥 Health check completed at: $(date)"