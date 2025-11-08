#!/bin/bash
set -e

echo "📁 CloudGuardStack Storage Security Auditor"
echo "==========================================="

# Configuration
AWS_PROFILE=${1:-default}
AWS_REGION=${2:-us-east-1}
OUTPUT_DIR="reports/storage-audit-$(date +%Y%m%d_%H%M%S)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create output directory
mkdir -p $OUTPUT_DIR

echo -e "${BLUE}1. Running Storage Security Scan...${NC}"
python scanners/storage-auditor/scanner.py \
  --aws-profile $AWS_PROFILE \
  --aws-region $AWS_REGION \
  --output $OUTPUT_DIR/storage_audit_report.json

echo -e "${BLUE}2. Generating Reports...${NC}"
python scanners/storage-auditor/reporter.py \
  --scan-file $OUTPUT_DIR/storage_audit_report.json \
  --output-dir $OUTPUT_DIR

echo -e "${BLUE}3. Creating Demo Findings (Optional)...${NC}"
python scanners/storage-auditor/demo_generator.py \
  --output $OUTPUT_DIR/storage_demo_findings.json \
  --include-remediation-plan

echo -e "${GREEN}✅ Storage Security Audit Complete!${NC}"
echo ""
echo "📊 Output Files:"
echo "   - Audit Report: $OUTPUT_DIR/storage_audit_report.json"
echo "   - Executive Summary: $OUTPUT_DIR/storage_executive_summary_*.json"
echo "   - Technical Report: $OUTPUT_DIR/storage_technical_report_*.json"
echo "   - Compliance Report: $OUTPUT_DIR/storage_compliance_report_*.json"
echo "   - Demo Findings: $OUTPUT_DIR/storage_demo_findings.json"
echo ""
echo "🚀 Next Steps:"
echo "   1. Review the executive summary for critical issues"
echo "   2. Implement immediate remediation for public buckets"
echo "   3. Use demo findings for training and case studies"
echo "   4. Schedule regular storage security scans"