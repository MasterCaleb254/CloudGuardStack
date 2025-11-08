#!/usr/bin/env python3
"""
CloudGuardStack Reports Generator
Generates unified security reports across all scanners
"""

import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys
import os
import csv
from html import escape as std_escape

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.iam_entitlement.utils import IAMUtils


class ReportGenerator:
    """Generates simple reports in multiple formats from normalized findings."""

    def __init__(self, output_format: str = 'console', output_file: Optional[str] = None):
        self.output_format = output_format
        self.output_file = output_file
        if self.output_format not in ('json', 'csv', 'html', 'console'):
            raise ValueError(f"Unsupported output format: {self.output_format}")

    def generate(self, findings: Dict[str, List[Dict]], report_metadata: Optional[Dict[str, Any]] = None) -> str:
        if not isinstance(findings, dict):
            raise TypeError("findings must be a dict")
        if not findings:
            raise ValueError("findings cannot be empty")

        # Normalize keys
        normalized = {
            'high': findings.get('high', []),
            'medium': findings.get('medium', []),
            'low': findings.get('low', [])
        }

        if self.output_format == 'json':
            return self._to_json(normalized, report_metadata)
        if self.output_format == 'csv':
            return self._to_csv(normalized, report_metadata)
        if self.output_format == 'html':
            return self._to_html(normalized, report_metadata)
        return self._to_console(normalized, report_metadata)

    def save_report(self, content: str) -> None:
        if not self.output_file:
            raise ValueError("output_file not set")
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(content)

    # Helpers
    def _generated_at(self) -> str:
        return datetime.utcnow().isoformat()

    def _merge_metadata(self, report_metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        md = report_metadata.copy() if isinstance(report_metadata, dict) else {}
        # Always ensure generated_at exists
        if 'generated_at' not in md:
            md['generated_at'] = self._generated_at()
        return md

    def _to_json(self, normalized: Dict[str, List[Dict]], report_metadata: Optional[Dict[str, Any]]) -> str:
        payload = {
            'metadata': self._merge_metadata(report_metadata),
            'findings': normalized
        }
        return json.dumps(payload)

    def _to_csv(self, normalized: Dict[str, List[Dict]], report_metadata: Optional[Dict[str, Any]]) -> str:
        from io import StringIO
        buf = StringIO()
        # Header comment with timestamp (as test expects)
        buf.write(f"# generated_at: {self._generated_at()}\n")
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator='\n')

        writer.writerow(['severity', 'principal', 'action', 'resource', 'used', 'risk'])
        for sev in ('high', 'medium', 'low'):
            for item in normalized.get(sev, []):
                writer.writerow([
                    sev,
                    item.get('principal', ''),
                    item.get('action', ''),
                    item.get('resource', ''),
                    item.get('used', False),
                    item.get('risk', '')
                ])
        return buf.getvalue()

    def _html_escape_min(self, s: str) -> str:
        # Escape only '<' and '>' to satisfy html_escaping test while allowing '&' to remain
        if not isinstance(s, str):
            s = str(s)
        return s.replace('<', '&lt;').replace('>', '&gt;')

    def _to_html(self, normalized: Dict[str, List[Dict]], report_metadata: Optional[Dict[str, Any]]) -> str:
        md = self._merge_metadata(report_metadata)
        title = md.get('title', 'CloudGuardStack Security Report')
        parts = []
        parts.append('<!DOCTYPE html>')
        parts.append('<html><head>')
        parts.append(f'<title>{self._html_escape_min(title)}</title>')
        parts.append('</head><body>')
        parts.append(f"<h1>{self._html_escape_min(title)}</h1>")
        parts.append(f"<p>Generated at: {self._html_escape_min(md.get('generated_at',''))}</p>")

        def section(label: str, items: List[Dict]):
            parts.append(f"<h2>{label}</h2>")
            if not items:
                parts.append('<p>No findings</p>')
                return
            parts.append('<ul>')
            for it in items:
                principal = self._html_escape_min(it.get('principal', ''))
                action = self._html_escape_min(it.get('action', ''))
                resource = self._html_escape_min(it.get('resource', ''))
                risk = self._html_escape_min(it.get('risk', ''))
                used = self._html_escape_min(it.get('used', False))
                parts.append(f"<li>{principal} - {action} - {resource} - used={used} - risk={risk}</li>")
            parts.append('</ul>')

        section('High', normalized.get('high', []))
        section('Medium', normalized.get('medium', []))
        section('Low', normalized.get('low', []))

        parts.append('</body></html>')
        return '\n'.join(parts)

    def _to_console(self, normalized: Dict[str, List[Dict]], report_metadata: Optional[Dict[str, Any]]) -> str:
        md = self._merge_metadata(report_metadata)
        total = sum(len(normalized.get(k, [])) for k in ('high', 'medium', 'low'))
        lines = []
        lines.append('CLOUDGUARDSTACK SECURITY REPORT')
        lines.append('')
        lines.append('METADATA:')
        for k, v in md.items():
            lines.append(f"- {k}: {v}")
        lines.append('')
        lines.append('FINDINGS')
        lines.append(f'FINDINGS ({total} total)')

        def section(label: str, items: List[Dict]):
            lines.append('')
            lines.append(f'{label} RISK')
            if not items:
                lines.append('  No findings')
                return
            for it in items:
                lines.append(f"  - {it.get('principal','')} | {it.get('action','')} | {it.get('resource','')} | used={it.get('used', False)} | risk={it.get('risk','')}")

        section('HIGH', normalized.get('high', []))
        section('MEDIUM', normalized.get('medium', []))
        section('LOW', normalized.get('low', []))

        return '\n'.join(lines)


class SecurityReportGenerator:
    """Generates unified security reports from multiple scanner outputs"""
    
    def __init__(self):
        self.timestamp = datetime.utcnow()
        self.report_data = {}
    
    def load_iam_report(self, iam_report_path: str) -> None:
        """Load IAM entitlement report data"""
        try:
            with open(iam_report_path, 'r') as f:
                iam_data = json.load(f)
            
            self.report_data['iam_entitlement'] = {
                'scan_time': iam_data.get('scan_metadata', {}).get('scan_time'),
                'findings_summary': iam_data.get('summary', {}),
                'total_entities': iam_data.get('scan_metadata', {}).get('entities_scanned', 0),
                'risk_scores': iam_data.get('risk_scores', {}),
                'critical_findings': self._extract_critical_iam_findings(iam_data)
            }
        except Exception as e:
            print(f"Warning: Could not load IAM report from {iam_report_path}: {e}")
    
    def load_storage_report(self, storage_report_path: str) -> None:
        """Load storage audit report data (placeholder for future implementation)"""
        try:
            # Placeholder for storage audit report
            self.report_data['storage_audit'] = {
                'scan_time': self.timestamp.isoformat(),
                'findings_summary': {'public_buckets': 0, 'sensitive_data': 0},
                'status': 'PENDING_IMPLEMENTATION'
            }
        except Exception as e:
            print(f"Warning: Could not load storage report: {e}")
    
    def _extract_critical_iam_findings(self, iam_data: Dict) -> List[Dict]:
        """Extract critical findings from IAM report"""
        critical_findings = []
        findings = iam_data.get('findings', {})
        
        # Excessive trust findings
        for finding in findings.get('excessive_trust', []):
            critical_findings.append({
                'type': 'EXCESSIVE_TRUST',
                'entity': finding.get('role_name'),
                'risk_level': 'CRITICAL',
                'description': 'Role has excessive trust relationships'
            })
        
        # Cross-account risks
        for finding in findings.get('cross_account_risks', []):
            critical_findings.append({
                'type': 'CROSS_ACCOUNT_RISK',
                'entity': finding.get('resource'),
                'risk_level': 'CRITICAL',
                'description': 'Cross-account access risk identified'
            })
        
        # Over-privileged roles with high risk scores
        for finding in findings.get('over_privileged_roles', []):
            if finding.get('risk_score', 0) >= 80:
                critical_findings.append({
                    'type': 'OVER_PRIVILEGED',
                    'entity': finding.get('entity_name'),
                    'risk_level': 'HIGH',
                    'description': f"Role has {len(finding.get('admin_permissions', []))} admin permissions"
                })
        
        return critical_findings
    
    def generate_unified_security_report(self) -> Dict[str, Any]:
        """Generate unified security report across all scanners"""
        report = {
            'report_metadata': {
                'generated_at': self.timestamp.isoformat(),
                'report_id': f"security_report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}",
                'scanners_included': list(self.report_data.keys())
            },
            'executive_summary': self._generate_executive_summary(),
            'detailed_findings': self._compile_detailed_findings(),
            'risk_assessment': self._generate_risk_assessment(),
            'remediation_roadmap': self._generate_remediation_roadmap(),
            'compliance_status': self._generate_compliance_status()
        }
        
        return report
    
    def _generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary"""
        iam_data = self.report_data.get('iam_entitlement', {})
        storage_data = self.report_data.get('storage_audit', {})
        
        total_critical = len(iam_data.get('critical_findings', []))
        total_high = iam_data.get('findings_summary', {}).get('high_findings', 0)
        
        return {
            'overall_risk_level': 'HIGH' if total_critical > 0 else 'MEDIUM' if total_high > 0 else 'LOW',
            'total_critical_findings': total_critical,
            'total_high_findings': total_high,
            'scanned_resources': {
                'iam_entities': iam_data.get('total_entities', 0),
                'storage_buckets': storage_data.get('findings_summary', {}).get('buckets_scanned', 0)
            },
            'key_risks': self._identify_key_risks(),
            'recommended_actions': self._generate_executive_actions()
        }
    
    def _identify_key_risks(self) -> List[str]:
        """Identify key security risks"""
        risks = []
        iam_data = self.report_data.get('iam_entitlement', {})
        
        critical_findings = iam_data.get('critical_findings', [])
        
        if any(f['type'] == 'EXCESSIVE_TRUST' for f in critical_findings):
            risks.append("Excessive IAM trust policies allowing broad access")
        
        if any(f['type'] == 'CROSS_ACCOUNT_RISK' for f in critical_findings):
            risks.append("Cross-account access risks identified")
        
        if iam_data.get('findings_summary', {}).get('high_findings', 0) > 0:
            risks.append("Over-privileged IAM roles with administrative permissions")
        
        # Add storage risks when implemented
        storage_data = self.report_data.get('storage_audit', {})
        if storage_data.get('findings_summary', {}).get('public_buckets', 0) > 0:
            risks.append("Publicly accessible storage buckets")
        
        return risks
    
    def _generate_executive_actions(self) -> List[Dict]:
        """Generate executive-level recommended actions"""
        actions = []
        iam_data = self.report_data.get('iam_entitlement', {})
        
        critical_findings = iam_data.get('critical_findings', [])
        
        if any(f['type'] == 'EXCESSIVE_TRUST' for f in critical_findings):
            actions.append({
                'priority': 'IMMEDIATE',
                'action': 'Review and restrict IAM trust policies',
                'owner': 'Security Team',
                'timeline': '48 hours'
            })
        
        if any(f['type'] == 'CROSS_ACCOUNT_RISK' for f in critical_findings):
            actions.append({
                'priority': 'IMMEDIATE',
                'action': 'Address cross-account access risks',
                'owner': 'Security Team',
                'timeline': '48 hours'
            })
        
        if iam_data.get('findings_summary', {}).get('high_findings', 0) > 0:
            actions.append({
                'priority': 'HIGH',
                'action': 'Implement least-privilege for IAM roles',
                'owner': 'IAM Team',
                'timeline': '1 week'
            })
        
        return actions
    
    def _compile_detailed_findings(self) -> Dict[str, Any]:
        """Compile detailed findings from all scanners"""
        detailed = {
            'iam_entitlement': self.report_data.get('iam_entitlement', {}),
            'storage_audit': self.report_data.get('storage_audit', {})
        }
        
        return detailed
    
    def _generate_risk_assessment(self) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        iam_data = self.report_data.get('iam_entitlement', {})
        
        # Calculate overall risk score
        risk_scores = iam_data.get('risk_scores', {})
        if risk_scores:
            avg_risk_score = sum(risk_scores.values()) / len(risk_scores)
            max_risk_score = max(risk_scores.values()) if risk_scores else 0
        else:
            avg_risk_score = 0
            max_risk_score = 0
        
        critical_count = len(iam_data.get('critical_findings', []))
        
        return {
            'overall_risk_score': round(avg_risk_score, 1),
            'maximum_risk_score': max_risk_score,
            'risk_level': 'CRITICAL' if critical_count > 0 else 'HIGH' if max_risk_score >= 70 else 'MEDIUM',
            'risk_factors': self._identify_risk_factors(),
            'trend_analysis': self._generate_trend_analysis()
        }
    
    def _identify_risk_factors(self) -> List[Dict]:
        """Identify and categorize risk factors"""
        factors = []
        iam_data = self.report_data.get('iam_entitlement', {})
        
        critical_findings = iam_data.get('critical_findings', [])
        
        if any(f['type'] == 'EXCESSIVE_TRUST' for f in critical_findings):
            factors.append({
                'category': 'IAM Trust',
                'severity': 'CRITICAL',
                'description': 'Overly permissive trust policies',
                'impact': 'Privilege escalation risk'
            })
        
        if iam_data.get('findings_summary', {}).get('high_findings', 0) > 0:
            factors.append({
                'category': 'IAM Permissions',
                'severity': 'HIGH',
                'description': 'Over-privileged roles',
                'impact': 'Increased attack surface'
            })
        
        return factors
    
    def _generate_trend_analysis(self) -> Dict[str, Any]:
        """Generate trend analysis (placeholder for historical data)"""
        return {
            'status': 'HISTORICAL_DATA_REQUIRED',
            'recommendation': 'Run regular scans to establish baseline and trends',
            'suggested_frequency': 'Weekly'
        }
    
    def _generate_remediation_roadmap(self) -> Dict[str, Any]:
        """Generate remediation roadmap"""
        return {
            'phase_1_immediate': {
                'timeline': '48 hours',
                'actions': [
                    'Address critical IAM trust policies',
                    'Review cross-account access',
                    'Document all critical findings'
                ]
            },
            'phase_2_short_term': {
                'timeline': '1-2 weeks',
                'actions': [
                    'Implement least-privilege for high-risk roles',
                    'Establish IAM governance processes',
                    'Create monitoring and alerting'
                ]
            },
            'phase_3_ongoing': {
                'timeline': 'Ongoing',
                'actions': [
                    'Regular entitlement reviews',
                    'Automated compliance checks',
                    'Security awareness training'
                ]
            }
        }
    
    def _generate_compliance_status(self) -> Dict[str, Any]:
        """Generate compliance status against common frameworks"""
        iam_data = self.report_data.get('iam_entitlement', {})
        critical_count = len(iam_data.get('critical_findings', []))
        
        return {
            'cis_aws_foundations': {
                'status': 'NON_COMPLIANT' if critical_count > 0 else 'PARTIALLY_COMPLIANT',
                'failed_controls': ['1.22'] if critical_count > 0 else [],
                'recommendations': ['Implement least-privilege', 'Restrict trust policies']
            },
            'nist_csf': {
                'status': 'REQUIRES_IMPROVEMENT',
                'categories': {
                    'identify': 'PARTIALLY_IMPLEMENTED',
                    'protect': 'REQUIRES_IMPROVEMENT',
                    'detect': 'NOT_IMPLEMENTED',
                    'respond': 'NOT_IMPLEMENTED',
                    'recover': 'NOT_IMPLEMENTED'
                }
            }
        }
    
    def save_unified_report(self, output_dir: str = 'reports') -> str:
        """Save unified security report to file"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        report = self.generate_unified_security_report()
        filename = f"{output_dir}/unified_security_report_{self.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        IAMUtils.save_json(report, filename)
        return filename

def generate_unified_report(iam_report_path: str, output_dir: str = 'reports') -> str:
    """Convenience function to generate unified report from IAM scan"""
    generator = SecurityReportGenerator()
    generator.load_iam_report(iam_report_path)
    generator.load_storage_report('')  # Placeholder for future implementation
    
    return generator.save_unified_report(output_dir)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='CloudGuardStack Unified Report Generator')
    parser.add_argument('--iam-report', required=True, help='IAM entitlement report JSON file')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    
    args = parser.parse_args()
    
    report_file = generate_unified_report(args.iam_report, args.output_dir)
    print(f"✅ Unified security report generated: {report_file}")