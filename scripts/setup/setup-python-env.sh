#!/bin/bash
set -e

echo "🐍 Setting up Python virtual environment..."

# Check if Python 3.9+ is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.9 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "📋 Found Python $PYTHON_VERSION"

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
if [ -f "pyproject.toml" ]; then
    echo "📦 Installing from pyproject.toml..."
    pip install -e .[dev]
else
    echo "📦 Installing from requirements.txt..."
    pip install -r requirements.txt
fi

# Verify installation
echo "✅ Python environment setup complete!"
echo "🔧 To activate the environment, run: source .venv/bin/activate"
echo "📚 Installed packages:"
pip list