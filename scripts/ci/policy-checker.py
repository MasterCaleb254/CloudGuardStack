#!/usr/bin/env python3
"""
CI/CD Policy Checker
Validates Terraform configurations against custom policies
"""

import json
import os
import sys
from pathlib import Path
import re

class PolicyChecker:
    def __init__(self):
        self.violations = []
        self.policies = self._load_policies()
    
    def _load_policies(self):
        """Load custom policy rules"""
        return {
            'naming_convention': {
                'pattern': r'^[a-z][a-z0-9-]*[a-z0-9]$',
                'message': 'Resource names must be lowercase with hyphens'
            },
            'required_tags': {
                'tags': ['Environment', 'Project', 'ManagedBy'],
                'message': 'Required tags missing'
            },
            'no_hardcoded_secrets': {
                'patterns': [
                    r'password\s*=\s*["\']([^"\']+)["\']',
                    r'secret\s*=\s*["\']([^"\']+)["\']',
                    r'api_key\s*=\s*["\']([^"\']+)["\']'
                ],
                'message': 'Hardcoded secrets detected'
            }
        }
    
    def check_terraform_files(self, directory="terraform"):
        """Check all Terraform files against policies"""
        tf_files = list(Path(directory).rglob("*.tf"))
        
        for tf_file in tf_files:
            self._check_file(tf_file)
        
        return self.violations
    
    def _check_file(self, file_path):
        """Check a single Terraform file"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check naming conventions
        self._check_naming_conventions(content, file_path)
        
        # Check for hardcoded secrets
        self._check_hardcoded_secrets(content, file_path)
        
        # Check resource configurations
        self._check_resource_configs(content, file_path)
    
    def _check_naming_conventions(self, content, file_path):
        """Check resource naming conventions"""
        # Find all resource definitions
        resource_pattern = r'resource\s+"[^"]+"\s+"([^"]+)"'
        resources = re.findall(resource_pattern, content)
        
        for resource_name in resources:
            if not re.match(self.policies['naming_convention']['pattern'], resource_name):
                self.violations.append({
                    'file': str(file_path),
                    'resource': resource_name,
                    'policy': 'naming_convention',
                    'message': self.policies['naming_convention']['message']
                })
    
    def _check_hardcoded_secrets(self, content, file_path):
        """Check for hardcoded secrets"""
        for pattern in self.policies['no_hardcoded_secrets']['patterns']:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.violations.append({
                    'file': str(file_path),
                    'policy': 'no_hardcoded_secrets',
                    'message': f"{self.policies['no_hardcoded_secrets']['message']}: {matches[:3]}"
                })
    
    def _check_resource_configs(self, content, file_path):
        """Check resource-specific configurations"""
        # Check for unencrypted storage
        if 'aws_s3_bucket' in content and 'server_side_encryption_configuration' not in content:
            self.violations.append({
                'file': str(file_path),
                'policy': 'encryption_required',
                'message': 'S3 buckets should have encryption enabled'
            })
        
        # Check for public access blocks
        if 'aws_s3_bucket' in content and 'public_access_block' not in content:
            self.violations.append({
                'file': str(file_path),
                'policy': 'public_access_control',
                'message': 'S3 buckets should have public access blocks configured'
            })
    
    def generate_report(self):
        """Generate policy violation report"""
        if not self.violations:
            print("✅ All policies passed!")
            return True
        
        print("❌ Policy violations found:")
        for violation in self.violations:
            print(f"  File: {violation['file']}")
            print(f"  Policy: {violation['policy']}")
            print(f"  Message: {violation['message']}")
            print()
        
        return False

def main():
    checker = PolicyChecker()
    violations = checker.check_terraform_files()
    
    if checker.generate_report():
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()