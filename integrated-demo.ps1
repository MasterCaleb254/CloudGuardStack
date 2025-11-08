# Configure terminal appearance
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

$global:previewOpened = $false

function Write-Animated {
    param(
        [string]$Text,
        [string]$ForegroundColor = "White",
        [int]$Speed = 30
    )
    $Text.ToCharArray() | ForEach-Object {
        Write-Host $_ -NoNewline -ForegroundColor $ForegroundColor
        Start-Sleep -Milliseconds $Speed
    }
    Write-Host
}

# Header
Write-Host "`n"
Write-Host " CloudGuardStack Security Analysis" -ForegroundColor Cyan
Write-Host "Initializing security assessment..." -ForegroundColor Yellow
Start-Sleep -Seconds 1

# Stage 1: IAM Analysis
Write-Host "`n Running IAM Security Scan..." -ForegroundColor Green
python scanners/iam_entitlement/demo_generator.py
Start-Sleep -Seconds 1

# Render initial graphs (IAM) in terminal
Write-Host "`n→ Rendering IAM Analysis Graphs..." -ForegroundColor Magenta
python scripts/render_demo_graphs.py
Start-Sleep -Seconds 1

# Stage 2: Storage Analysis
Write-Host "`n Analyzing Storage Security..." -ForegroundColor Green
python scanners/storage_auditor/demo_generator.py --include-remediation-plan
Start-Sleep -Seconds 1

# Render updated graphs in terminal with storage analysis
Write-Host "`n→ Rendering Storage Analysis Graphs..." -ForegroundColor Magenta
python scripts/render_demo_graphs.py
Start-Sleep -Seconds 1

# Stage 3: Results Summary
Write-Host "`n"
Write-Host "" -ForegroundColor Cyan
Write-Host " Critical Security Findings" -ForegroundColor Red
Write-Host "" -ForegroundColor Cyan

$findings = @(
    @{Text=" High-Risk Admin Account Detected"; Details="Unrestricted access, immediate action required"},
    @{Text=" Public Storage Buckets: 3"; Details="Exposed to internet access"},
    @{Text=" Sensitive Data Exposed"; Details="Credentials found in config files"},
    @{Text=" Configuration Issues: 4"; Details="Non-compliant security settings"}
)

foreach ($finding in $findings) {
    Write-Host $finding.Text -ForegroundColor Red
    Write-Host "   $($finding.Details)" -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 800
}

# Stage 4: Remediation Plan
Write-Host "`n"
Write-Host "" -ForegroundColor Green
Write-Host " Generated Remediation Plan" -ForegroundColor Green
Write-Host "" -ForegroundColor Green

$remediation = @(
    "1. Implement least-privilege access model",
    "2. Secure public storage endpoints",
    "3. Encrypt sensitive configurations",
    "4. Apply security baseline"
)

foreach ($step in $remediation) {
    Write-Host "  $step" -ForegroundColor Green
    Start-Sleep -Milliseconds 600
}

# Completion
Write-Host "`n"
Write-Host " Security Analysis Complete" -ForegroundColor Cyan
Write-Host "Security Analysis Complete - Report Generated" -ForegroundColor DarkGray
