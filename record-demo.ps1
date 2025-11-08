Write-Host "🎥 Setting up for automatic demo recording..." -ForegroundColor Cyan
Write-Host "Make sure OBS Studio is ready to record!" -ForegroundColor Yellow
Write-Host "Starting in 5 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Clear terminal and set window size
$pshost = Get-Host
$pswindow = $pshost.UI.RawUI
$newsize = $pswindow.BufferSize
$newsize.Height = 3000
$newsize.Width = 120
$pswindow.BufferSize = $newsize

Clear-Host

# Function to display animated text
function Write-AnimatedText {
    param($Text, $Color = "White", $Speed = 50)
    $Text.ToCharArray() | ForEach-Object {
        Write-Host $_ -NoNewline -ForegroundColor $Color
        Start-Sleep -Milliseconds $Speed
    }
    Write-Host
}

# Start Demo
Write-AnimatedText "🔒 CloudGuardStack Security Analysis Tool" "Cyan" 30
Write-AnimatedText "Initializing security scan..." "Yellow" 30
Start-Sleep -Seconds 2

# Generate findings
Write-Host "`n→ Scanning IAM configurations..." -ForegroundColor Green
python scanners/iam_entitlement/demo_generator.py
Start-Sleep -Seconds 2

Write-Host "`n→ Analyzing storage security..." -ForegroundColor Green
python scanners/storage_auditor/demo_generator.py --include-remediation-plan
Start-Sleep -Seconds 2

# Launch notebook analysis
Write-AnimatedText "`n📊 Launching Security Analysis Dashboard..." "Cyan" 30
code notebooks/demo_analysis.ipynb

# Display summary findings
Write-Host "`n----------------------------------------" -ForegroundColor White
Write-AnimatedText "🚨 Critical Security Findings" "Red" 30
Write-Host "----------------------------------------" -ForegroundColor White
Start-Sleep -Seconds 1

$findings = @(
    "✗ Public Storage Buckets: 3",
    "✗ Critical IAM Issues: 2",
    "✗ Sensitive Data Exposed: 3",
    "✗ Configuration Issues: 4"
)

foreach ($finding in $findings) {
    Write-Host $finding -ForegroundColor Red
    Start-Sleep -Milliseconds 800
}

Write-Host "`n----------------------------------------" -ForegroundColor White
Write-AnimatedText "📝 Remediation Plan Generated" "Green" 30
Write-Host "----------------------------------------" -ForegroundColor White
Start-Sleep -Seconds 1

$remediation = @(
    "✓ Access Control Updates",
    "✓ Storage Security Baseline",
    "✓ Policy Recommendations",
    "✓ Monitoring Implementation"
)

foreach ($step in $remediation) {
    Write-Host $step -ForegroundColor Green
    Start-Sleep -Milliseconds 800
}

# Completion
Write-Host "`n----------------------------------------" -ForegroundColor White
Write-AnimatedText "✨ Security Analysis Complete" "Cyan" 30
Write-AnimatedText "Generated comprehensive security report and remediation plan" "Yellow" 30
Start-Sleep -Seconds 3

# End recording reminder
Write-Host "`n🎬 Demo Complete - Stop Recording" -ForegroundColor Magenta