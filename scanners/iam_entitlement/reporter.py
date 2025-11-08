#!/usr/bin/env python3
"""
IAM Entitlement Reporter
Generates comprehensive reports from IAM entitlement scans
"""

import json
import pandas as pd
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from .utils import IAMUtils


class IAMReporter:
    """Generates various report formats from IAM entitlement data"""

    def __init__(self, entitlement_data: Dict[str, Any] = None, output_dir: str = 'reports', template_dir: str = None):
        """
        Initialize the IAMReporter.
        
        Args:
            entitlement_data: Dictionary containing IAM entitlement data
            output_dir: Directory where report files will be saved (default: 'reports')
            template_dir: Directory containing report templates (optional)
        """
        self.data = entitlement_data or {}
        self.timestamp = datetime.now(timezone.utc)
        self.output_dir = Path(output_dir)
        self.template_dir = Path(template_dir) if template_dir else None
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------
    # Report Generation Methods
    # --------------------------------------------------------

    def generate_json_report(self, findings: Dict[str, Any] = None) -> str:
        """
        Generate a JSON report from the findings.
        
        Args:
            findings: Optional findings to use instead of the data provided in the constructor
            
        Returns:
            Path to the generated JSON report
        """
        if findings is not None:
            self.data = findings
            
        report = self.generate_report()
        output_file = self.output_dir / 'iam_entitlement_report.json'
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        return str(output_file)

    def generate_html_report(self, findings: Dict[str, Any] = None) -> str:
        """
        Generate an HTML report from the findings.
        
        Args:
            findings: Optional findings to use instead of the data provided in the constructor
            
        Returns:
            Path to the generated HTML report
        """
        if findings is not None:
            self.data = findings
            
        report = self.generate_report()
        output_file = self.output_dir / 'iam_entitlement_report.html'
        
        # Simple HTML template
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>IAM Entitlement Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
                h1 { color: #2c3e50; }
                .finding { margin-bottom: 20px; padding: 10px; border-left: 4px solid #3498db; }
                .critical { border-color: #e74c3c; }
                .high { border-color: #e67e22; }
                .medium { border-color: #f39c12; }
                .low { border-color: #3498db; }
                .metadata { color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <h1>IAM Entitlement Report</h1>
            <div class="metadata">
                Generated at: {generated_at}<br>
                Source: {source}
            </div>
            
            <h2>Executive Summary</h2>
            <div>
                <h3>Key Findings</h3>
                <ul>
        """.format(
            generated_at=report['metadata']['generated_at'],
            source=report['metadata']['source']
        )
        
        # Add key findings
        for finding in report['executive_summary'].get('key_findings', []):
            html += f'<li class="finding {finding["type"].lower()}">{finding["description"]} - {finding["impact"]}</li>\n'
        html += """
                </ul>
                
                <h3>Recommendations</h3>
                <ul>
        """
        
        # Add recommendations
        for rec in report['executive_summary'].get('recommendations', []):
            html += f'<li><strong>{rec["priority"]}</strong>: {rec["action"]} ({rec["timeline"]})</li>\n'
        html += """
                </ul>
            </div>
            
            <h2>Detailed Findings</h2>
            <table border="1" cellpadding="8" cellspacing="0" style="width:100%; border-collapse: collapse;">
                <tr>
                    <th>Principal</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Used</th>
                    <th>Risk</th>
                </tr>
        """
        
        # Add detailed findings
        for finding in report['detailed_findings']:
            html += f"""
                <tr>
                    <td>{finding['principal']}</td>
                    <td>{finding['action']}</td>
                    <td>{finding['resource']}</td>
                    <td>{'Yes' if finding['used'] else 'No'}</td>
                    <td class="{finding['risk'].lower()}">{finding['risk']}</td>
                </tr>
            """.format(
                principal=finding.get('principal', ''),
                action=finding.get('action', ''),
                resource=finding.get('resource', ''),
                used='Yes' if finding.get('used', False) else 'No',
                risk=finding.get('risk', 'medium').capitalize()
            )
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html)
            
        return str(output_file)

    def generate_csv_report(self, findings: Dict[str, Any] = None) -> str:
        """
        Generate a CSV report from the findings.
        
        Args:
            findings: Optional findings to use instead of the data provided in the constructor
            
        Returns:
            Path to the generated CSV report
        """
        if findings is not None:
            self.data = findings
            
        report = self.generate_report()
        output_file = self.output_dir / 'iam_entitlement_report.csv'
        
        # Prepare CSV data
        fieldnames = ['principal', 'action', 'resource', 'used', 'risk']
        rows = []
        
        for finding in report['detailed_findings']:
            rows.append({
                'principal': finding.get('principal', ''),
                'action': finding.get('action', ''),
                'resource': finding.get('resource', ''),
                'used': 'Yes' if finding.get('used', False) else 'No',
                'risk': finding.get('risk', 'medium').capitalize()
            })
        
        # Write CSV file
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            
        return str(output_file)

    # --------------------------------------------------------
    # High-level reporting
    # --------------------------------------------------------

    def generate_report(self, scan_results: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """
        Generate a unified report combining all report types.
        Optionally accepts scan_results (for testing or dynamic updates).
        
        Args:
            scan_results: Optional scan results to use instead of the data provided in the constructor

        Returns:
            Dict containing the complete report

        Raises:
            ValueError: If scan_results is provided but has an invalid format
        """
        print("🧾 Generating unified entitlement report...")

        # Accept dynamic scan results from test or external input
        if scan_results is not None:
            self._validate_scan_results(scan_results)
            self.data = scan_results

        report = {
            "executive_summary": self.generate_executive_summary(),
            "detailed_findings": self.generate_detailed_findings_report().to_dict(orient="records"),
            "risk_prioritization": self.generate_risk_prioritization_matrix(),
            "compliance_report": self.generate_compliance_report(),
            "metadata": {
                "generated_at": self.timestamp.isoformat(),
                "source": "IAMReporter",
            },
        }
        return report

    # --------------------------------------------------------
    # Individual report sections
    # --------------------------------------------------------

    def _validate_scan_results(self, scan_results: Dict[str, Any]) -> None:
        """Validate the structure of scan results.
        
        Args:
            scan_results: The scan results to validate
            
        Raises:
            ValueError: If the scan results are invalid
        """
        if not isinstance(scan_results, dict):
            raise ValueError("Scan results must be a dictionary")
            
        required_sections = ["report_metadata", "detailed_findings"]
        for section in required_sections:
            if section not in scan_results:
                raise ValueError(f"Scan results missing required section: {section}")
                
        # Validate detailed_findings structure
        if not isinstance(scan_results.get("detailed_findings"), list):
            raise ValueError("detailed_findings must be a list")

    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        # Get the risk summary from the correct location in the data structure
        risk_summary = self.data.get("report_metadata", {}).get("risk_summary", {})
        
        summary = {
            "report_date": self.timestamp.isoformat(),
            "scan_metadata": self.data.get("report_metadata", {}).get("scan_metadata", {}),
            "risk_summary": risk_summary,  # Use the properly located risk summary
            "key_findings": [],
            "recommendations": [],
        }

        findings = self.data.get("findings", {})

        # Handle missing or empty fields gracefully
        if not findings:
            summary["key_findings"].append({
                "type": "INFO",
                "description": "No findings available in the provided data.",
                "impact": "None"
            })
            return summary

        # Critical findings
        critical_count = len(findings.get("excessive_trust", [])) + len(findings.get("cross_account_risks", []))
        if critical_count > 0:
            summary["key_findings"].append({
                "type": "CRITICAL",
                "description": f"{critical_count} critical trust and cross-account issues found",
                "impact": "High risk of privilege escalation",
            })

        # High findings
        high_count = len(findings.get("over_privileged_roles", []))
        if high_count > 0:
            summary["key_findings"].append({
                "type": "HIGH",
                "description": f"{high_count} over-privileged roles identified",
                "impact": "Increased attack surface",
            })

        # Medium findings
        medium_count = len(findings.get("risky_permissions", []))
        if medium_count > 0:
            summary["key_findings"].append({
                "type": "MEDIUM",
                "description": f"{medium_count} roles with risky permissions",
                "impact": "Potential security risks",
            })

        # Recommendations
        if critical_count > 0:
            summary["recommendations"].append({
                "priority": "IMMEDIATE",
                "action": "Review and restrict trust policies",
                "timeline": "Within 48 hours",
            })
        if high_count > 0:
            summary["recommendations"].append({
                "priority": "HIGH",
                "action": "Implement least-privilege principles",
                "timeline": "Within 1 week",
            })

        total_entities = self.data.get("scan_metadata", {}).get("entities_scanned", 0)
        if total_entities > 50:
            summary["recommendations"].append({
                "priority": "MEDIUM",
                "action": "Establish IAM governance processes",
                "timeline": "Within 2 weeks",
            })

        return summary

    def generate_detailed_findings_report(self) -> pd.DataFrame:
        """Generate detailed findings as a DataFrame"""
        findings_data = []
        
        # First check if we have detailed_findings in the data structure
        detailed_findings = self.data.get("detailed_findings", [])
        if detailed_findings:
            for finding in detailed_findings:
                if not isinstance(finding, dict) or "principal" not in finding:
                    continue
                    
                principal = finding["principal"]
                findings_list = finding.get("findings", [])
                
                for finding_detail in findings_list:
                    if not isinstance(finding_detail, dict):
                        continue
                        
                    risk = finding_detail.get("risk", "medium").lower()
                    findings_data.append({
                        "principal": principal,
                        "action": finding_detail.get("action", ""),
                        "resource": finding_detail.get("resource", ""),
                        "used": finding_detail.get("used", False),
                        "risk": risk,
                        "risk_score": 90 if risk == "high" else 60 if risk == "medium" else 30
                    })
            
            if findings_data:
                return pd.DataFrame(findings_data)
        
        # Fall back to the old format if detailed_findings is not available
        findings = self.data.get("findings", {})

        for finding_type, items in findings.items():
            for item in items:
                base_record = {
                    "finding_type": finding_type,
                    "entity_name": item.get("entity_name", item.get("RoleName", "unknown")),
                    "entity_type": item.get("entity_type", "role"),
                    "risk_level": item.get("risk_level", "MEDIUM"),
                }

                if finding_type == "over_privileged_roles":
                    base_record.update({
                        "admin_permissions_count": len(item.get("admin_permissions", [])),
                        "total_permissions": item.get("total_permissions", 0),
                        "risk_score": item.get("risk_score", 0),
                    })
                elif finding_type == "unused_roles":
                    base_record.update({
                        "days_since_creation": item.get("days_since_creation", 0),
                        "last_used": item.get("last_used", "Never"),
                    })
                elif finding_type == "excessive_trust":
                    trust_issues = item.get("trust_issues", [])
                    base_record.update({
                        "trust_issues_count": len(trust_issues),
                        "critical_trust_issues": len([t for t in trust_issues if t.get("risk_level") == "CRITICAL"]),
                    })
                elif finding_type == "risky_permissions":
                    base_record.update({
                        "risky_permissions_count": len(item.get("risky_permissions", [])),
                        "risk_level": item.get("risk_level", "MEDIUM"),
                    })

                findings_data.append(base_record)

        return pd.DataFrame(findings_data)

    def generate_risk_prioritization_matrix(self) -> Dict[str, Any]:
        """Generate risk prioritization matrix for remediation"""
        # Initialize risk scores from the data if available
        risk_scores = self.data.get("risk_scores", {})
        
        # Process detailed findings to build risk scores if not already in risk_scores
        detailed_findings = self.data.get("detailed_findings", [])
        for finding in detailed_findings:
            principal = finding.get("principal")
            if not principal:
                continue
                
            # Initialize risk score for this principal if not exists
            if principal not in risk_scores:
                risk_scores[principal] = 0
                
            # Process each finding for this principal
            for detail in finding.get("findings", []):
                risk = detail.get("risk", "").lower()
                if risk == "high":
                    risk_scores[principal] = max(risk_scores[principal], 90)
                elif risk == "medium":
                    risk_scores[principal] = max(risk_scores[principal], 60)
                elif risk == "low":
                    risk_scores[principal] = max(risk_scores[principal], 30)

        # Categorize risks
        high_risk = {e: s for e, s in risk_scores.items() if s >= 70}
        medium_risk = {e: s for e, s in risk_scores.items() if 40 <= s < 70}
        low_risk = {e: s for e, s in risk_scores.items() if s < 40 and s > 0}

        # Generate remediation suggestions based on findings
        remediation_suggestions = []
        for principal, score in risk_scores.items():
            if score >= 70:
                priority = "IMMEDIATE"
            elif score >= 40:
                priority = "HIGH"
            else:
                priority = "MEDIUM"
                
            suggestion = {
                "principal": principal,
                "title": f"Review and remediate access for {principal}",
                "description": f"Principal has {len([f for f in self.data.get('findings', []) if f.get('principal') == principal])} findings",
                "priority": priority,
                "risk_score": score,
                "recommended_actions": ["Review permissions", "Apply principle of least privilege"]
            }
            remediation_suggestions.append(suggestion)

        return {
            "high_risk_entities": {
                "count": len(high_risk),
                "entities": high_risk,
                "remediation_priority": "IMMEDIATE",
                "timeline": "Within 48 hours",
            },
            "medium_risk_entities": {
                "count": len(medium_risk),
                "entities": medium_risk,
                "remediation_priority": "HIGH",
                "timeline": "Within 1 week",
            },
            "low_risk_entities": {
                "count": len(low_risk),
                "entities": low_risk,
                "remediation_priority": "MEDIUM",
                "timeline": "Within 2 weeks",
            },
            "top_remediation_actions": self._get_top_remediation_actions(remediation_suggestions),
        }

    def _get_top_remediation_actions(self, suggestions: List[Dict]) -> List[Dict]:
        """Extract top remediation actions by priority"""
        critical_actions = [s for s in suggestions if s.get("priority") in ["CRITICAL", "IMMEDIATE"]]
        high_actions = [s for s in suggestions if s.get("priority") == "HIGH"]
        top_actions = (critical_actions + high_actions)[:5]

        for action in top_actions:
            action["estimated_effort"] = self._estimate_remediation_effort(action)
            action["business_impact"] = self._assess_business_impact(action)
        return top_actions

    def _estimate_remediation_effort(self, action: Dict) -> str:
        """Estimate remediation effort level"""
        finding_type = action.get("finding_type", "")
        if finding_type == "excessive_trust":
            return "Medium"
        elif finding_type == "over_privileged_roles":
            return "High"
        elif finding_type == "unused_roles":
            return "Low"
        return "Medium"

    def _assess_business_impact(self, action: Dict) -> str:
        """Assess potential business impact of remediation"""
        finding_type = action.get("finding_type", "")
        if finding_type in ["excessive_trust", "cross_account_risks"]:
            return "High - Security critical"
        elif finding_type == "over_privileged_roles":
            return "Medium - May affect functionality"
        elif finding_type == "unused_roles":
            return "Low - No impact expected"
        return "Medium"

    def generate_compliance_report(self, framework: str = "CIS") -> Dict[str, Any]:
        """Generate compliance report against a security framework"""
        findings = self.data.get("findings", {})
        cis_controls = {
            "CIS-1.4": {
                "description": "Ensure no root user access key exists",
                "status": "N/A",
                "findings": [],
            },
            "CIS-1.16": {
                "description": "Ensure IAM policies are attached only to groups or roles",
                "status": "PASS",
                "findings": [],
            },
            "CIS-1.22": {
                "description": 'Ensure IAM policies with "*" administrative privileges are not created',
                "status": "FAIL" if findings.get("over_privileged_roles") else "PASS",
                # ✅ Prevent None values in findings
                "findings": [f.get("entity_name") for f in findings.get("over_privileged_roles", []) if f],
            },
        }

        total_controls = len(cis_controls)
        passed_controls = sum(1 for c in cis_controls.values() if c["status"] == "PASS")
        compliance_score = (passed_controls / total_controls) * 100

        return {
            "framework": framework,
            "assessment_date": self.timestamp.isoformat(),
            "compliance_score": round(compliance_score, 1),
            "controls": cis_controls,
            "recommendations": self._generate_compliance_recommendations(cis_controls),
        }

    def _generate_compliance_recommendations(self, controls: Dict) -> List[str]:
        """Generate compliance improvement recommendations"""
        recommendations = []
        for cid, ctrl in controls.items():
            if ctrl["status"] == "FAIL":
                # ✅ Safely convert findings to strings to avoid TypeError
                findings = [str(f) if f is not None else "Unknown" for f in ctrl.get("findings", [])]
                recommendations.append(
                    f"Address {cid}: {ctrl['description']}. "
                    f"Affected entities: {', '.join(findings) if findings else 'None'}"
                )
        return recommendations

    # --------------------------------------------------------
    # Persistence
    # --------------------------------------------------------

    def save_reports(self, output_dir: str = "reports") -> Dict[str, str]:
        """Save all report types to files"""
        import os
        os.makedirs(output_dir, exist_ok=True)

        timestamp = self.timestamp.strftime("%Y%m%d_%H%M%S")
        report_files = {}

        exec_summary = self.generate_executive_summary()
        exec_file = f"{output_dir}/executive_summary_{timestamp}.json"
        IAMUtils.save_json(exec_summary, exec_file)
        report_files["executive_summary"] = exec_file

        detailed_df = self.generate_detailed_findings_report()
        if not detailed_df.empty:
            detailed_file = f"{output_dir}/detailed_findings_{timestamp}.csv"
            detailed_df.to_csv(detailed_file, index=False)
            report_files["detailed_findings"] = detailed_file

        risk_matrix = self.generate_risk_prioritization_matrix()
        risk_file = f"{output_dir}/risk_prioritization_{timestamp}.json"
        IAMUtils.save_json(risk_matrix, risk_file)
        report_files["risk_prioritization"] = risk_file

        compliance_report = self.generate_compliance_report()
        compliance_file = f"{output_dir}/compliance_report_{timestamp}.json"
        IAMUtils.save_json(compliance_report, compliance_file)
        report_files["compliance_report"] = compliance_file

        combined_report = {
            "executive_summary": exec_summary,
            "risk_prioritization": risk_matrix,
            "compliance_report": compliance_report,
            "metadata": {
                "generated_at": self.timestamp.isoformat(),
                "report_files": report_files,
            },
        }
        combined_file = f"{output_dir}/combined_report_{timestamp}.json"
        IAMUtils.save_json(combined_report, combined_file)
        report_files["combined_report"] = combined_file

        return report_files
