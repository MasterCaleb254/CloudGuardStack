Write-Host "🐍 Setting up Python virtual environment..."

# Check if Python 3.9+ is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python 3 is not installed. Please install Python 3.9 or higher."
    exit 1
}

$PYTHON_VERSION = (python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
Write-Host "📋 Found Python $PYTHON_VERSION"

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
if (Test-Path "pyproject.toml") {
    Write-Host "📦 Installing from pyproject.toml..."
    pip install -e .[dev]
} else {
    Write-Host "📦 Installing from requirements.txt..."
    pip install -r requirements.txt
}

# Verify installation
Write-Host "✅ Python environment setup complete!"
Write-Host "🔧 To activate the environment, run: .\.venv\Scripts\Activate.ps1"
Write-Host "📚 Installed packages:"
pip list