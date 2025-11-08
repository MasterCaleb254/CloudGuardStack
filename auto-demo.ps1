function Write-Highlight {
    param($Message)
    Write-Host "`n→ $Message" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
}

Clear-Host
Write-Host "CloudGuardStack Security Analysis Demo" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Step 1: Show project structure
Write-Highlight "Analyzing Cloud Security Components..."
tree /F /A | Select-Object -First 20
Start-Sleep -Seconds 4

# Step 2: Generate demo findings
Write-Highlight "Generating IAM Security Findings..."
python scanners/iam_entitlement/demo_generator.py
Start-Sleep -Seconds 3

Write-Highlight "Analyzing Storage Security..."
python scanners/storage_auditor/demo_generator.py --include-remediation-plan
Start-Sleep -Seconds 3

# Step 3: Open and run analysis notebook
Write-Highlight "Launching Security Analysis Dashboard..."
jupyter notebook notebooks/security_analysis.ipynb --no-browser

# Step 4: Display key findings summary
Write-Highlight "Security Analysis Summary"
Write-Host "----------------------------------------"
Write-Host "Critical Findings:"
Write-Host "✗ 3 Public Storage Buckets Exposed" -ForegroundColor Red
Write-Host "✗ Admin Account with Unrestricted Access" -ForegroundColor Red
Write-Host "✗ Sensitive Data in Config Files" -ForegroundColor Red
Start-Sleep -Seconds 4

Write-Host "`nRemediation Actions:" -ForegroundColor Yellow
Write-Host "✓ Generated Access Control Recommendations" -ForegroundColor Green
Write-Host "✓ Created Storage Security Baseline" -ForegroundColor Green
Write-Host "✓ Identified Policy Updates Required" -ForegroundColor Green
Start-Sleep -Seconds 4

# Step 5: Show completion
Write-Host "`n✨ Security Analysis Complete" -ForegroundColor Cyan
Write-Host "Identified 12 security findings and generated remediation plan." -ForegroundColor White
Start-Sleep -Seconds 3