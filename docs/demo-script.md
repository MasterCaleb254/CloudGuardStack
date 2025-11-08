# Demo Script: CloudGuardStack Security Analysis Tool

## Video Duration: 3-5 minutes

### 1. Introduction (30 seconds)
"Hi everyone! Today I'm excited to showcase CloudGuardStack, a multi-cloud security analysis tool I developed. While it's designed to work with AWS, Azure, and GCP, I'll demonstrate its capabilities using our demo environment."

### 2. Tool Components (45 seconds)
Show the project structure:
```
- IAM Entitlement Scanner
- Storage Security Scanner
- Policy Analysis Tools
- Automated Remediation Planning
```

### 3. Live Demo Steps

#### Step 1: Generate Demo Data (30 seconds)
Run commands:
```powershell
# Generate IAM findings
python scanners/iam_entitlement/demo_generator.py

# Generate storage findings
python scanners/storage_auditor/demo_generator.py --include-remediation-plan
```

#### Step 2: Analysis Notebook (60 seconds)
Open security_analysis.ipynb and show:
- Loading and processing security findings
- Risk score visualizations
- Storage security analysis
- Critical findings identification

#### Step 3: Key Findings (45 seconds)
Highlight:
- High-risk IAM accounts
- Public storage containers
- Exposed sensitive data
- Configuration issues

#### Step 4: Remediation Planning (30 seconds)
Show:
- Prioritized remediation steps
- Case studies
- Best practices recommendations

### 4. Technical Highlights (30 seconds)
Mention:
- Python data analysis stack
- Visualization capabilities
- Extensible architecture
- Security best practices

### 5. Conclusion (30 seconds)
"This tool demonstrates how we can automate security analysis and provide actionable insights for cloud environments. While we used demo data today, the same principles apply to live cloud environments."

## Recording Tips
1. Use Windows PowerShell with clear font and good contrast
2. Zoom in when showing code or findings
3. Highlight mouse movements when explaining features
4. Keep terminal commands visible for a few seconds
5. Pause briefly after each major section

## Key Points to Emphasize
1. Automated security analysis
2. Comprehensive risk assessment
3. Visual data presentation
4. Actionable remediation steps
5. Multi-cloud architecture

## Tools Needed for Recording
1. PowerShell with clear formatting
2. VS Code with Jupyter extension
3. Screen recording software (e.g., OBS Studio)
4. External microphone for clear audio