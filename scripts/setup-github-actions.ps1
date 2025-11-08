# Setup-GitHubActions.ps1
# This script sets up the .github/workflows directory and moves workflow files

# Create .github/workflows directory if it doesn't exist
$workflowsDir = ".github/workflows"
if (-not (Test-Path -Path $workflowsDir)) {
    New-Item -ItemType Directory -Path $workflowsDir -Force
    Write-Host "Created directory: $workflowsDir"
}

# Source directory containing workflow files
$sourceDir = "ci-cd/github-actions/workflows"

# Check if source directory exists
if (-not (Test-Path -Path $sourceDir)) {
    Write-Error "Source directory $sourceDir does not exist"
    exit 1
}

# Copy all YAML files from source to destination
Get-ChildItem -Path $sourceDir -Include '*.yaml','*.yml' -Recurse | ForEach-Object {
    $destination = Join-Path $workflowsDir $_.Name
    Copy-Item -Path $_.FullName -Destination $destination -Force
    Write-Host "Copied $($_.Name) to $workflowsDir"
}

Write-Host "`nGitHub Actions setup complete. Please verify the following:"
Write-Host "1. Review the workflow files in the .github/workflows/ directory"
Write-Host "2. Add required secrets to your GitHub repository settings"
Write-Host "3. Update any file paths in the workflow files if needed"
Write-Host "4. Commit and push the changes to your repository"
