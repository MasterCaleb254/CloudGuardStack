Write-Host "🎬 Starting CloudGuardStack Demo" -ForegroundColor Cyan

# Clear the terminal
Clear-Host

Write-Host "Step 1: Generating Demo Security Findings..." -ForegroundColor Yellow
Write-Host "Generating IAM security findings..." -ForegroundColor Green
python scanners/iam_entitlement/demo_generator.py

Write-Host "`nGenerating storage security findings..." -ForegroundColor Green
python scanners/storage_auditor/demo_generator.py --include-remediation-plan

Write-Host "`nStep 2: Opening Security Analysis Notebook..." -ForegroundColor Yellow
code notebooks/security_analysis.ipynb

Write-Host "`n✨ Demo environment is ready!" -ForegroundColor Cyan
Write-Host "You can now start your screen recording and follow the demo script."