#!/usr/bin/env python3
"""
Post-Deployment Security Scans
Run security scans after infrastructure deployment
"""

import json
import subprocess
import sys
import argparse
from pathlib import Path

class PostDeployScanner:
    def __init__(self, environment: str):
        self.environment = environment
        self.scan_results = {}
    
    def run_iam_entitlement_scan(self) -> bool:
        """Run IAM entitlement scan on deployed environment"""
        print("🔍 Running IAM Entitlement Scan...")
        
        try:
            result = subprocess.run([
                'python', 'scanners/iam-entitlement/scanner.py',
                '--output', f'reports/iam_scan_{self.environment}.json',
                '--generate-visualization'
            ], capture_output=True, text=True)
            
            self.scan_results['iam_entitlement'] = {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
            
            return result.returncode == 0
        except Exception as e:
            print(f"❌ IAM scan failed: {e}")
            return False
    
    def run_storage_audit(self) -> bool:
        """Run storage security audit on deployed environment"""
        print("🔍 Running Storage Security Audit...")
        
        try:
            result = subprocess.run([
                'python', 'scanners/storage-auditor/scanner.py',
                '--output', f'reports/storage_audit_{self.environment}.json'
            ], capture_output=True, text=True)
            
            self.scan_results['storage_audit'] = {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
            
            return result.returncode == 0
        except Exception as e:
            print(f"❌ Storage audit failed: {e}")
            return False
    
    def check_cloudtrail_status(self) -> bool:
        """Verify CloudTrail is enabled and logging"""
        print("🔍 Checking CloudTrail Status...")
        
        try:
            result = subprocess.run([
                'aws', 'cloudtrail', 'describe-trails',
                '--query', 'trailList[0]'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                trail_info = json.loads(result.stdout)
                is_logging = trail_info.get('IsLogging', False)
                
                self.scan_results['cloudtrail'] = {
                    'enabled': is_logging,
                    'trail_arn': trail_info.get('TrailARN'),
                    'multi_region': trail_info.get('IsMultiRegionTrail', False)
                }
                
                return is_logging
            return False
        except Exception as e:
            print(f"❌ CloudTrail check failed: {e}")
            return False
    
    def verify_security_hub(self) -> bool:
        """Verify AWS Security Hub is enabled"""
        print("🔍 Checking Security Hub Status...")
        
        try:
            result = subprocess.run([
                'aws', 'securityhub', 'describe-hub'
            ], capture_output=True, text=True)
            
            self.scan_results['security_hub'] = {
                'enabled': result.returncode == 0
            }
            
            return result.returncode == 0
        except Exception as e:
            print(f"⚠️  Security Hub not enabled: {e}")
            return False
    
    def generate_verification_report(self) -> dict:
        """Generate comprehensive verification report"""
        report = {
            'environment': self.environment,
            'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
            'scans': self.scan_results,
            'summary': {
                'total_checks': len(self.scan_results),
                'passed_checks': sum(1 for scan in self.scan_results.values() if scan.get('success', False)),
                'failed_checks': sum(1 for scan in self.scan_results.values() if not scan.get('success', True))
            },
            'recommendations': []
        }
        
        # Generate recommendations based on scan results
        if not self.scan_results.get('cloudtrail', {}).get('enabled'):
            report['recommendations'].append('Enable CloudTrail logging for audit trail')
        
        if not self.scan_results.get('security_hub', {}).get('enabled'):
            report['recommendations'].append('Enable AWS Security Hub for centralized security findings')
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Post-Deployment Security Scans')
    parser.add_argument('--environment', required=True, 
                       choices=['ephemeral', 'production'],
                       help='Environment to scan')
    parser.add_argument('--output', default='deployment-verification-report.json',
                       help='Output file for verification report')
    
    args = parser.parse_args()
    
    scanner = PostDeployScanner(args.environment)
    
    # Run all verification scans
    scans_passed = True
    
    if not scanner.run_iam_entitlement_scan():
        scans_passed = False
    
    if not scanner.run_storage_audit():
        scans_passed = False
    
    if not scanner.check_cloudtrail_status():
        scans_passed = False
    
    scanner.verify_security_hub()  # This one is optional
    
    # Generate report
    report = scanner.generate_verification_report()
    
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📊 Deployment Verification Complete:")
    print(f"   - Environment: {args.environment}")
    print(f"   - Checks Passed: {report['summary']['passed_checks']}/{report['summary']['total_checks']}")
    print(f"   - Report: {args.output}")
    
    if report['recommendations']:
        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"   - {rec}")
    
    sys.exit(0 if scans_passed else 1)

if __name__ == '__main__':
    main()