#!/usr/bin/env python3
"""
CloudGuardStack Storage Auditor
Scans for public cloud storage and sensitive data patterns across AWS, Azure, and GCP
"""

import json
import boto3
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from google.cloud import storage
from typing import Dict, List, Any, Optional, Union
import re
from datetime import datetime,timezone
import argparse
import sys


class StorageAuditor:
    def __init__(self, aws_profile: str = None, aws_region: str = 'us-east-1'):
        """Initialize storage auditor with multi-cloud clients"""
        self.aws_session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        self.s3 = self.aws_session.client('s3')

        # Initialize Azure client
        try:
            self.azure_credential = DefaultAzureCredential()
        except Exception as e:
            print(f"⚠️  Azure credential initialization failed: {e}")
            self.azure_credential = None

        # Initialize GCP client
        try:
            self.gcp_storage = storage.Client()
        except Exception as e:
            print(f"⚠️  GCP client initialization failed: {e}")
            self.gcp_storage = None

        self.findings = {
            'public_buckets': [],
            'sensitive_data_findings': [],
            'insecure_configurations': [],
            'remediation_suggestions': []
        }

        # Sensitive data patterns
        self.sensitive_patterns = {
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'[0-9a-zA-Z/+]{40}'
            ],
            'private_keys': [
                r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                r'-----BEGIN PRIVATE KEY-----'
            ],
            'passwords': [
                r'password[=:\s]+([^\s]+)',
                r'pwd[=:\s]+([^\s]+)',
                r'pass[=:\s]+([^\s]+)'
            ],
            'api_keys': [
                r'api[_-]?key[=:\s]*([^\s]+)',
                r'secret[=:\s]*([^\s]+)'
            ],
            'database_connections': [
                r'mongodb[+]srv://[^:]+:[^@]+@',
                r'postgresql://[^:]+:[^@]+@',
                r'mysql://[^:]+:[^@]+@'
            ]
        }

    def _is_text_file(self, file_name: str) -> bool:
        """Check if a file is a text file based on its extension."""
        text_extensions = {
            '.txt', '.csv', '.json', '.yaml', '.yml', '.xml',
            '.log', '.md', '.rst', '.py', '.js', '.html', '.css',
            '.conf', '.config', '.properties', '.ini', '.toml',
            '.sh', '.bat', '.ps1', '.cmd'
        }
        return any(file_name.lower().endswith(ext) for ext in text_extensions)

    def _check_for_sensitive_patterns(self, content: str) -> List[str]:
        """Check content for sensitive data patterns."""
        found_patterns = []
        for pattern_name, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_patterns.append(pattern_name)
        return found_patterns

    def scan_all_clouds(self) -> Dict[str, Any]:
        """Run comprehensive storage audit across all cloud providers"""
        print("🔍 Starting Multi-Cloud Storage Security Scan...")

        # Scan AWS S3
        aws_findings = self.scan_aws_s3()
        print(f"✅ AWS S3 Scan Complete: {len(aws_findings['public_buckets'])} public buckets found")

        # Scan Azure Blob Storage
        azure_findings = self.scan_azure_blobs()
        print(f"✅ Azure Blob Scan Complete: {len(azure_findings['public_buckets'])} public containers found")

        # Scan GCP Cloud Storage
        gcp_findings = self.scan_gcp_storage()
        print(f"✅ GCP Storage Scan Complete: {len(gcp_findings['public_buckets'])} public buckets found")

        # Combine all findings
        combined_findings = self._combine_findings(aws_findings, azure_findings, gcp_findings)

        # Generate remediation suggestions
        combined_findings['remediation_suggestions'] = self._generate_remediation_suggestions(combined_findings)

        return combined_findings

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan all S3 buckets for security issues and return detailed findings."""
        print("🔍 Scanning S3 buckets for security issues...")
        findings = []

        try:
            response = self.s3.list_buckets()
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                bucket_findings = {
                    'name': bucket_name,
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'findings': [],
                    'is_public': False,
                    'public_access_type': None,
                    'encryption': 'Not enabled',
                    'versioning': 'Not enabled',
                    'logging': 'Not enabled'
                }

                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if 'URI' in grantee and 'AllUsers' in grantee['URI']:
                            bucket_findings['findings'].append(
                                f"Public access granted to AllUsers via {grant['Permission']} permission"
                            )
                            bucket_findings['is_public'] = True
                            bucket_findings['public_access_type'] = 'ACL'
                except Exception as e:
                    print(f"⚠️  Error scanning bucket {bucket_name}: {str(e)}")
                    bucket_findings['findings'].append(f"Error during scan: {str(e)}")

                findings.append(bucket_findings)
        except Exception as e:
            print(f"❌ Error listing S3 buckets: {str(e)}")

        print(f"✅ Scanned {len(findings)} S3 buckets")
        return findings

    def _scan_s3_bucket_for_sensitive_data(self, bucket_name: str, max_files: int = 100) -> List[Dict[str, Any]]:
        """Scan an S3 bucket for sensitive data patterns."""
        findings = []
        scanned_files = 0

        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name)

            for page in page_iterator:
                if 'Contents' not in page:
                    continue
                for obj in page['Contents']:
                    if scanned_files >= max_files:
                        break
                    file_name = obj['Key']
                    file_size = obj['Size']
                    if file_size > 10 * 1024 * 1024 or not self._is_text_file(file_name):
                        continue
                    try:
                        response = self.s3.get_object(Bucket=bucket_name, Key=file_name)
                        content = response['Body'].read().decode('utf-8', errors='ignore')
                        matched_patterns = self._check_for_sensitive_patterns(content)
                        if matched_patterns:
                            findings.append({
                                'bucket': bucket_name,
                                'file': file_name,
                                'sensitive_patterns': matched_patterns,
                                'size': file_size,
                                'last_modified': obj['LastModified'].isoformat()
                            })
                        scanned_files += 1
                    except Exception as e:
                        print(f"⚠️  Error scanning {file_name} in {bucket_name}: {str(e)}")
                        continue
                    if scanned_files >= max_files:
                        break
        except Exception as e:
            print(f"❌ Error scanning bucket {bucket_name} for sensitive data: {str(e)}")

        return findings

    def scan_for_sensitive_data(self, buckets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan multiple S3 buckets for sensitive data patterns."""
        all_findings = []
        for bucket in buckets:
            bucket_name = bucket.get('name')
            if not bucket_name:
                continue
            try:
                findings = self._scan_s3_bucket_for_sensitive_data(bucket_name)
                all_findings.extend(findings)
                self.findings['sensitive_data_findings'].extend(findings)
            except Exception as e:
                print(f"⚠️  Error scanning {bucket_name} for sensitive data: {str(e)}")
        return all_findings


def main():
    """Main function for command line usage"""
    parser = argparse.ArgumentParser(description='CloudGuardStack Storage Auditor')
    parser.add_argument('--aws-profile', help='AWS profile to use')
    parser.add_argument('--aws-region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', default='storage_audit_report.json', help='Output file')
    parser.add_argument('--apply-tags', action='store_true', help='Apply security tags to public resources')

    args = parser.parse_args()

    auditor = StorageAuditor(aws_profile=args.aws_profile, aws_region=args.aws_region)
    report = auditor.scan_all_clouds()

    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"✅ Storage Security Audit Complete!")
    print(f"📄 Report saved to: {args.output}")
    if 'summary' in report:
        print(f"📊 Summary: {report['summary']}")
    else:
        print("📊 Summary data unavailable.")


if __name__ == '__main__':
    main()
