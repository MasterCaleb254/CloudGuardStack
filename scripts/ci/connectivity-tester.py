#!/usr/bin/env python3
"""
Connectivity Tester for CI/CD
Tests cross-cloud connectivity and service health
"""

import boto3
import requests
import json
import sys
from typing import Dict, List

class ConnectivityTester:
    def __init__(self):
        self.results = []
        
    def test_aws_connectivity(self):
        """Test AWS service connectivity"""
        try:
            # Test S3 access
            s3 = boto3.client('s3')
            buckets = s3.list_buckets()
            self.results.append({
                'service': 'AWS S3',
                'status': 'SUCCESS',
                'details': f"Access to {len(buckets['Buckets'])} buckets"
            })
            
            # Test CloudTrail
            cloudtrail = boto3.client('cloudtrail')
            trails = cloudtrail.describe_trails()
            self.results.append({
                'service': 'AWS CloudTrail',
                'status': 'SUCCESS',
                'details': f"{len(trails['trailList'])} trails configured"
            })
            
        except Exception as e:
            self.results.append({
                'service': 'AWS Services',
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_azure_connectivity(self):
        """Test Azure service connectivity"""
        try:
            # This would use Azure SDK in a real implementation
            self.results.append({
                'service': 'Azure Storage',
                'status': 'SKIPPED',
                'details': 'Azure connectivity test placeholder'
            })
            
        except Exception as e:
            self.results.append({
                'service': 'Azure Services',
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_gcp_connectivity(self):
        """Test GCP service connectivity"""
        try:
            # This would use GCP SDK in a real implementation
            self.results.append({
                'service': 'GCP Storage',
                'status': 'SKIPPED',
                'details': 'GCP connectivity test placeholder'
            })
            
        except Exception as e:
            self.results.append({
                'service': 'GCP Services',
                'status': 'FAILED',
                'details': str(e)
            })
    
    def test_siem_connectivity(self):
        """Test SIEM connectivity"""
        try:
            response = requests.get('http://localhost:5601', timeout=10)
            if response.status_code == 200:
                self.results.append({
                    'service': 'Kibana SIEM',
                    'status': 'SUCCESS',
                    'details': 'Kibana dashboard accessible'
                })
            else:
                self.results.append({
                    'service': 'Kibana SIEM',
                    'status': 'FAILED',
                    'details': f"HTTP {response.status_code}"
                })
                
        except Exception as e:
            self.results.append({
                'service': 'Kibana SIEM',
                'status': 'FAILED',
                'details': str(e)
            })
    
    def run_all_tests(self):
        """Run all connectivity tests"""
        print("🌐 Running connectivity tests...")
        
        self.test_aws_connectivity()
        self.test_azure_connectivity()
        self.test_gcp_connectivity()
        self.test_siem_connectivity()
        
        return self.results
    
    def generate_report(self):
        """Generate connectivity test report"""
        print("\n📊 Connectivity Test Results:")
        print("=" * 50)
        
        success_count = sum(1 for r in self.results if r['status'] == 'SUCCESS')
        total_count = len(self.results)
        
        for result in self.results:
            status_icon = "✅" if result['status'] == 'SUCCESS' else "❌"
            print(f"{status_icon} {result['service']}: {result['details']}")
        
        print(f"\n🎯 Summary: {success_count}/{total_count} tests passed")
        
        return success_count == total_count

def main():
    tester = ConnectivityTester()
    tester.run_all_tests()
    
    if tester.generate_report():
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()