#!/usr/bin/env python3
"""
Storage Auditor Reporter
Generates comprehensive reports from storage security scans
"""

import json
import csv
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any

from jinja2 import Environment, FileSystemLoader
from ..reports.templates import ReportTemplates, MarkdownTemplates


class StorageAuditReporter:
    """Simple reporter used by unit tests to export storage findings to JSON/HTML/CSV."""

    def __init__(self, output_dir: str, template_dir: str | None = None):
        self.output_dir = Path(output_dir)
        self.template_dir = Path(template_dir) if template_dir else None
        # Configure Jinja2 environment; loader points to provided templates if any
        search_paths = [str(self.template_dir)] if self.template_dir else []
        self.env = Environment(loader=FileSystemLoader(search_paths or ['.']))

    def _timestamp(self) -> str:
        # Tests patch datetime.utcnow().strftime
        return datetime.utcnow().strftime('%Y%m%d_%H%M%S')

    def generate_json_report(self, findings: Dict[str, Any], report_name: str | None = None) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = report_name or f'storage_audit_{self._timestamp()}.json'
        path = self.output_dir / filename
        with open(path, 'w') as f:
            json.dump(findings, f, indent=2)
        return str(path)

    def generate_html_report(self, findings: Dict[str, Any], report_name: str | None = None) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = report_name or f'storage_audit_{self._timestamp()}.html'
        path = self.output_dir / filename
        # Expect a template named 'storage_audit.html' in template_dir
        template = self.env.get_template('storage_audit.html')
        content = template.render(findings=findings)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return str(path)

    def generate_csv_report(self, findings: Dict[str, Any], report_name: str | None = None) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = report_name or f'storage_audit_{self._timestamp()}.csv'
        path = self.output_dir / filename
        
        # Flatten the findings into a single list
        all_items = []
        for items in findings.values():
            if isinstance(items, list):
                all_items.extend(items)
        
        if not all_items:
            # Create an empty file if no findings
            path.touch()
            return str(path)

        # Get all unique fieldnames from the items
        fieldnames = set()
        for item in all_items:
            if isinstance(item, dict):
                fieldnames.update(item.keys())
        
        # Ensure required fields are included
        required_fields = ['bucket_name', 'severity', 'resource_type', 'issue_type']
        for field in required_fields:
            if field not in fieldnames:
                fieldnames.add(field)
        
        # Convert to list for consistent ordering
        fieldnames = sorted(fieldnames)
        
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write each item, ensuring all fields are present
            for item in all_items:
                if not isinstance(item, dict):
                    continue
                # Ensure all fields are present in the row
                row = {field: item.get(field, '') for field in fieldnames}
                writer.writerow(row)
                
        return str(path)

    def generate_report(self, findings: Dict[str, Any], fmt: str) -> str:
        fmt = fmt.lower()
        if fmt == 'json':
            return self.generate_json_report(findings)
        if fmt == 'html':
            return self.generate_html_report(findings)
        if fmt == 'csv':
            return self.generate_csv_report(findings)
        raise ValueError(f"Unsupported report format: {fmt}")

    def generate_summary(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        items = []
        for _, lst in (findings or {}).items():
            if isinstance(lst, list):
                items.extend(lst)
        by_severity: Dict[str, int] = {}
        by_resource_type: Dict[str, int] = {}
        by_issue_type: Dict[str, int] = {}
        for it in items:
            by_severity[it.get('severity', '')] = by_severity.get(it.get('severity', ''), 0) + 1
            by_resource_type[it.get('resource_type', '')] = by_resource_type.get(it.get('resource_type', ''), 0) + 1
            by_issue_type[it.get('issue_type', '')] = by_issue_type.get(it.get('issue_type', ''), 0) + 1
        return {
            'timestamp': self._timestamp(),
            'total_findings': len(items),
            'by_severity': {k: v for k, v in by_severity.items() if k},
            'by_resource_type': {k: v for k, v in by_resource_type.items() if k},
            'by_issue_type': {k: v for k, v in by_issue_type.items() if k},
        }


class StorageReporter:
    """Generates storage security reports in multiple formats"""

    def __init__(self, storage_data: Dict[str, Any]):
        self.data = storage_data
        # Use timezone-aware datetime for consistency
        self.timestamp = datetime.now(timezone.utc)

    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary for leadership"""
        summary = ReportTemplates.executive_summary_template()

        public_buckets = self.data.get('public_buckets', [])
        sensitive_data_findings = self.data.get('sensitive_data_findings', [])
        insecure_configurations = self.data.get('insecure_configurations', [])
        summary_data = self.data.get('summary', {})

        summary['metadata'].update({
            'generated_at': self.timestamp.isoformat(),
            'report_id': f"storage_audit_{self.timestamp.strftime('%Y%m%d_%H%M%S')}",
            'scanner': 'CloudGuardStack Storage Auditor'
        })

        summary['overview'].update({
            'total_findings': (
                summary_data.get('total_public_buckets', len(public_buckets))
                + summary_data.get('total_sensitive_findings', len(sensitive_data_findings))
                + summary_data.get('total_configuration_issues', len(insecure_configurations))
            ),
            'critical_findings': len([b for b in public_buckets if b.get('risk_level') == 'CRITICAL']),
            'high_findings': len([b for b in public_buckets if b.get('risk_level') == 'HIGH']),
            'overall_risk_level': 'HIGH' if public_buckets else 'MEDIUM',
            'scan_coverage': {
                'storage_buckets': 'Multi-cloud (AWS, Azure, GCP)',
                'sensitive_data_scan': 'Pattern-based detection',
                'configuration_audit': 'Security best practices'
            }
        })

        for bucket in public_buckets[:3]:
            summary['key_findings'].append({
                'type': 'PUBLIC_STORAGE',
                'severity': bucket.get('risk_level', 'MEDIUM'),
                'description': f"Public {bucket.get('cloud_provider', 'unknown')} bucket: "
                               f"{bucket.get('bucket_name', bucket.get('container_name', 'N/A'))}",
                'impact': bucket.get('business_impact', 'Data exposure risk')
            })

        for finding in sensitive_data_findings[:2]:
            summary['key_findings'].append({
                'type': 'SENSITIVE_DATA',
                'severity': finding.get('risk_level', 'HIGH'),
                'description': f"Sensitive data in {finding.get('bucket_name', 'unknown')}/"
                               f"{finding.get('object_key', '')}",
                'impact': 'Credential exposure risk'
            })

        summary['risk_assessment'].update({
            'business_impact': 'HIGH - Potential data breach',
            'compliance_status': 'REQUIRES_IMPROVEMENT',
            'remediation_priority': 'IMMEDIATE'
        })

        summary['recommended_actions'].extend([
            {'priority': 'IMMEDIATE', 'action': 'Secure public storage buckets', 'owner': 'Cloud Security Team', 'timeline': '48 hours'},
            {'priority': 'IMMEDIATE', 'action': 'Remove exposed sensitive data', 'owner': 'Data Protection Team', 'timeline': '24 hours'},
            {'priority': 'HIGH', 'action': 'Implement storage security baseline', 'owner': 'Cloud Engineering', 'timeline': '1 week'}
        ])

        summary['next_steps'] = [
            'Review detailed findings report',
            'Implement immediate remediation actions',
            'Schedule security training for cloud teams',
            'Establish continuous storage monitoring'
        ]

        return summary

    def generate_technical_report(self) -> Dict[str, Any]:
        """Generate detailed technical report"""
        technical = ReportTemplates.technical_detailed_template()

        public_buckets = self.data.get('public_buckets', [])
        sensitive_data_findings = self.data.get('sensitive_data_findings', [])
        insecure_configurations = self.data.get('insecure_configurations', [])
        summary_data = self.data.get('summary', {})

        technical['metadata'].update({
            'generated_at': self.timestamp.isoformat(),
            'scanner_versions': {
                'storage_auditor': '1.0',
                'sensitive_data_detection': '1.0'
            },
            'scan_duration': 'varies_by_environment'
        })

        technical['methodology'].update({
            'scan_scope': {
                'cloud_providers': ['aws', 'azure', 'gcp'],
                'check_types': ['public_access', 'sensitive_data', 'configurations']
            },
            'tools_used': ['boto3', 'azure-storage-blob', 'google-cloud-storage'],
            'assessment_criteria': {
                'public_access': 'Any bucket/container accessible without authentication',
                'sensitive_data': 'Pattern matching for credentials, keys, and secrets',
                'configurations': 'Industry best practices and compliance requirements'
            }
        })

        technical['findings_by_category']['storage_security'] = {
            'summary': {
                'public_buckets': len(public_buckets),
                'sensitive_data_findings': len(sensitive_data_findings),
                'configuration_issues': len(insecure_configurations)
            },
            'detailed_findings': {
                'public_buckets': public_buckets,
                'sensitive_data': sensitive_data_findings,
                'configurations': insecure_configurations
            }
        }

        technical['risk_scores'] = {
            'overall_risk': summary_data.get('risk_score', 0),
            'public_access_risk': len([b for b in public_buckets if b.get('risk_level') in ['CRITICAL', 'HIGH']]) * 10,
            'sensitive_data_risk': len(sensitive_data_findings) * 15,
            'configuration_risk': len(insecure_configurations) * 5
        }

        technical['technical_recommendations'] = [
            'Implement S3 Block Public Access on all AWS accounts',
            'Enable default encryption on all storage buckets',
            'Set up sensitive data scanning in CI/CD pipelines',
            'Implement storage security policies using Terraform',
            'Enable access logging on all storage resources'
        ]

        return technical

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance assessment report"""
        compliance = ReportTemplates.compliance_template("CIS")
        compliance['metadata']['assessment_date'] = self.timestamp.isoformat()

        public_buckets = self.data.get('public_buckets', [])
        insecure_configurations = self.data.get('insecure_configurations', [])

        controls = {
            'CIS-2.1.3': {
                'description': 'Ensure S3 buckets are not publicly accessible',
                'status': 'FAIL' if public_buckets else 'PASS',
                'evidence': [b.get('bucket_name') for b in public_buckets],
                'remediation': 'Enable S3 Block Public Access and remove public policies'
            },
            'CIS-2.1.4': {
                'description': 'Ensure S3 buckets have default encryption enabled',
                'status': 'FAIL' if any('encryption' in str(c).lower() for c in insecure_configurations) else 'PASS',
                'evidence': [c.get('bucket_name') for c in insecure_configurations if 'encryption' in c.get('issue', '').lower()],
                'remediation': 'Enable default encryption using SSE-S3 or SSE-KMS'
            }
        }

        compliance['control_assessments'] = controls

        total_controls = len(controls)
        passed_controls = sum(1 for c in controls.values() if c['status'] == 'PASS')
        compliance_score = (passed_controls / total_controls) * 100 if total_controls > 0 else 0

        compliance['executive_summary'].update({
            'compliance_score': round(compliance_score, 1),
            'status': (
                'COMPLIANT' if compliance_score >= 90
                else 'PARTIALLY_COMPLIANT' if compliance_score >= 70
                else 'NON_COMPLIANT'
            ),
            'assessed_controls': total_controls,
            'passed_controls': passed_controls,
            'failed_controls': total_controls - passed_controls
        })

        return compliance

    def save_reports(self, output_dir: str = 'reports') -> Dict[str, str]:
        """Save all report types to files"""
        import os
        os.makedirs(output_dir, exist_ok=True)

        timestamp = self.timestamp.strftime('%Y%m%d_%H%M%S')
        report_files = {}

        exec_summary = self.generate_executive_summary()
        exec_file = f'{output_dir}/storage_executive_summary_{timestamp}.json'
        with open(exec_file, 'w') as f:
            json.dump(exec_summary, f, indent=2, default=str)
        report_files['executive_summary'] = exec_file

        technical_report = self.generate_technical_report()
        technical_file = f'{output_dir}/storage_technical_report_{timestamp}.json'
        with open(technical_file, 'w') as f:
            json.dump(technical_report, f, indent=2, default=str)
        report_files['technical_report'] = technical_file

        compliance_report = self.generate_compliance_report()
        compliance_file = f'{output_dir}/storage_compliance_report_{timestamp}.json'
        with open(compliance_file, 'w') as f:
            json.dump(compliance_report, f, indent=2, default=str)
        report_files['compliance_report'] = compliance_file

        md_summary = MarkdownTemplates.executive_summary_md(exec_summary)
        md_file = f'{output_dir}/storage_summary_{timestamp}.md'
        with open(md_file, 'w') as f:
            f.write(md_summary)
        report_files['markdown_summary'] = md_file

        return report_files


def generate_storage_reports_from_file(report_file: str, output_dir: str = 'reports'):
    """Generate storage reports from a saved scan file"""
    with open(report_file, 'r') as f:
        storage_data = json.load(f)

    reporter = StorageReporter(storage_data)
    return reporter.save_reports(output_dir)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Storage Security Reporter')
    parser.add_argument('--scan-file', required=True, help='Storage scan JSON file')
    parser.add_argument('--output-dir', default='reports', help='Output directory')

    args = parser.parse_args()

    report_files = generate_storage_reports_from_file(args.scan_file, args.output_dir)
    print("✅ Storage reports generated:")
    for report_type, file_path in report_files.items():
        print(f"   {report_type}: {file_path}")
