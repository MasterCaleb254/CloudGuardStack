#!/bin/bash
set -e

echo "☁️ Setting up Cloud CLI environment..."

# Add cloud CLI binaries to PATH if not already present
add_to_path() {
    local path_to_add="$1"
    if [[ ":$PATH:" != *":$path_to_add:"* ]]; then
        echo "🔧 Adding $path_to_add to PATH"
        export PATH="$path_to_add:$PATH"
        echo "export PATH=\"$path_to_add:\$PATH\"" >> ~/.bashrc
    fi
}

# Add common cloud CLI paths
add_to_path "/usr/local/bin"
add_to_path "$HOME/.local/bin"
add_to_path "/snap/bin"

# GCloud SDK path
if [ -d "$HOME/google-cloud-sdk" ]; then
    add_to_path "$HOME/google-cloud-sdk/bin"
    source "$HOME/google-cloud-sdk/path.bash.inc"
    source "$HOME/google-cloud-sdk/completion.bash.inc"
fi

# Azure CLI completion
if command -v az &> /dev/null; then
    echo "🔧 Setting up Azure CLI completion..."
    az completion bash | sudo tee /etc/bash_completion.d/azure-cli > /dev/null
fi

# AWS CLI completion
if command -v aws &> /dev/null; then
    echo "🔧 Setting up AWS CLI completion..."
    complete -C aws_completer aws
fi

# Set environment variables
echo "🔧 Setting cloud environment variables..."
export TF_VAR_ephemeral_lifetime_hours=48
export CLOUDGUARD_STACK_ENV=ephemeral
export AWS_DEFAULT_REGION=us-east-1
export AZURE_LOCATION=eastus
export GCP_REGION=us-central1

echo "✅ Cloud CLI environment setup complete!"
echo "📋 Current PATH: $PATH"