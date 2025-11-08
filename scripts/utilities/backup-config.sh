#!/bin/bash
set -e

echo "💾 Backing up CloudGuardStack configuration..."

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup Terraform state files
if [ -d "terraform" ]; then
    cp -r terraform/*.tfstate* "$BACKUP_DIR/" 2>/dev/null || true
fi

# Backup configuration files
cp -r terraform/environments/ephemeral/*.tfvars "$BACKUP_DIR/" 2>/dev/null || true
cp -r policies/ "$BACKUP_DIR/" 2>/dev/null || true

echo "✅ Configuration backed up to: $BACKUP_DIR"