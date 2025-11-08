#!/bin/bash
set -e

echo "🔍 CloudGuardStack IAM Entitlement Scanner"
echo "=========================================="

# Configuration
PROFILE=${1:-default}
REGION=${2:-us-east-1}
OUTPUT_DIR="reports/iam-scan-$(date +%Y%m%d_%H%M%S)"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create output directory
mkdir -p $OUTPUT_DIR

echo -e "${BLUE}1. Running IAM Entitlement Scan...${NC}"
python scanners/iam-entitlement/scanner.py \
  --profile $PROFILE \
  --region $REGION \
  --output $OUTPUT_DIR/entitlement_report.json \
  --generate-visualization

echo -e "${BLUE}2. Generating Visualizations...${NC}"
python scanners/iam-entitlement/visualizer.py

echo -e "${BLUE}3. Creating Remediation Templates...${NC}"
python scanners/iam-entitlement/remediation_generator.py \
  --report $OUTPUT_DIR/entitlement_report.json \
  --output-dir $OUTPUT_DIR/remediation_templates \
  --generate-plan

echo -e "${BLUE}4. Copying Notebook for Analysis...${NC}"
cp notebooks/iam_entitlement_analysis.ipynb $OUTPUT_DIR/

echo -e "${GREEN}✅ IAM Entitlement Scan Complete!${NC}"
echo ""
echo "📊 Output Files:"
echo "   - Full Report: $OUTPUT_DIR/entitlement_report.json"
echo "   - Visualizations: iam_privilege_graph.png, iam_risk_dashboard.png"
echo "   - Remediation: $OUTPUT_DIR/remediation_templates/"
echo "   - Analysis Notebook: $OUTPUT_DIR/iam_entitlement_analysis.ipynb"
echo ""
echo "🚀 Next Steps:"
echo "   1. Review the entitlement report"
echo "   2. Analyze findings in the Jupyter notebook"
echo "   3. Implement remediation templates"
echo "   4. Schedule regular IAM entitlement scans"