#!/usr/bin/env python3
"""
IAM Privilege Visualization Generator
Creates network graphs and charts for IAM entitlement analysis
"""

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
from typing import Dict, Any, Optional
import json
import os


class PrivilegeVisualizer:
    def __init__(self, entitlement_report: Optional[Dict[str, Any]] = None):
        """Initialize visualizer with entitlement data."""
        self.report = entitlement_report or {}
        self.colors = {
            'CRITICAL': '#FF6B6B',
            'HIGH': '#FFA726',
            'MEDIUM': '#FFE082',
            'LOW': '#C8E6C9'
        }

    # ------------------------------------------------------------
    # High-level interface
    # ------------------------------------------------------------
    def generate_visualizations(self, output_dir: str = "visuals") -> Dict[str, str]:
        """
        Generate both the privilege graph and risk dashboard.
        Used by tests or scripts for end-to-end workflow validation.
        """
        os.makedirs(output_dir, exist_ok=True)
        print("🎨 Generating IAM visualizations...")

        privilege_graph_file = os.path.join(output_dir, "iam_privilege_graph.png")
        risk_dashboard_file = os.path.join(output_dir, "iam_risk_dashboard.png")

        self.generate_privilege_graph(privilege_graph_file)
        self.generate_risk_dashboard(risk_dashboard_file)

        print("✅ Visualization generation completed.")
        return {
            "privilege_graph": privilege_graph_file,
            "risk_dashboard": risk_dashboard_file
        }

    # ------------------------------------------------------------
    # Graph visualization
    # ------------------------------------------------------------
    def generate_privilege_graph(self, output_file: str = 'iam_privilege_graph.png'):
        """Generate network graph of IAM privileges and relationships"""
        if not self.report:
            print("⚠️ No report data provided — skipping privilege graph generation.")
            return

        plt.figure(figsize=(16, 12))
        G = nx.DiGraph()

        self._add_entities_to_graph(G)
        self._add_findings_to_graph(G)
        self._add_relationships_to_graph(G)

        if not G.nodes:
            print("⚠️ No graph data to visualize.")
            plt.close()
            return

        pos = nx.spring_layout(G, k=3, iterations=50)
        self._draw_graph_elements(G, pos)

        plt.title('IAM Entitlement Analysis - Privilege Relationships', size=16, pad=20)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"📊 Privilege graph saved to: {output_file}")

    def _add_entities_to_graph(self, graph: nx.DiGraph):
        """Add IAM entities as nodes to the graph"""
        risk_scores = self.report.get('risk_scores', {})
        if not risk_scores:
            return

        for entity, score in risk_scores.items():
            if score >= 80:
                color, size = self.colors['CRITICAL'], 800
            elif score >= 60:
                color, size = self.colors['HIGH'], 600
            elif score >= 40:
                color, size = self.colors['MEDIUM'], 400
            else:
                color, size = self.colors['LOW'], 300

            graph.add_node(entity, node_type='entity', risk_score=score,
                           color=color, size=size)

    def _add_findings_to_graph(self, graph: nx.DiGraph):
        """Add finding types as nodes to the graph"""
        findings = self.report.get('findings', {})
        if not findings:
            return

        for finding_type, items in findings.items():
            if items:
                graph.add_node(finding_type, node_type='finding',
                               count=len(items), color='#90CAF9', size=500)

    def _add_relationships_to_graph(self, graph: nx.DiGraph):
        """Add relationships between entities and findings"""
        findings = self.report.get('findings', {})
        if not findings:
            return

        for finding_type, items in findings.items():
            for item in items:
                entity_name = item.get('entity_name')
                if entity_name and entity_name in graph.nodes():
                    graph.add_edge(entity_name, finding_type,
                                   relationship='has_finding')

    def _draw_graph_elements(self, graph: nx.DiGraph, pos: Dict):
        """Draw all graph elements with appropriate styling"""
        node_colors = [graph.nodes[n].get('color', '#CCCCCC') for n in graph.nodes()]
        node_sizes = [graph.nodes[n].get('size', 300) for n in graph.nodes()]

        nx.draw_networkx_nodes(graph, pos, node_color=node_colors,
                               node_size=node_sizes, alpha=0.9)
        nx.draw_networkx_edges(graph, pos, edge_color='gray',
                               arrows=True, arrowsize=20, alpha=0.6)

        labels = {}
        for node in graph.nodes():
            node_data = graph.nodes[node]
            if node_data.get('node_type') == 'entity':
                risk_score = node_data.get('risk_score', 0)
                labels[node] = f"{node}\n({risk_score})"
            else:
                count = node_data.get('count', 0)
                labels[node] = f"{node}\n[{count}]"

        nx.draw_networkx_labels(graph, pos, labels, font_size=8, font_weight='bold')

    # ------------------------------------------------------------
    # Dashboard visualization
    # ------------------------------------------------------------
    def generate_risk_dashboard(self, output_file: str = 'iam_risk_dashboard.png'):
        """Generate comprehensive risk dashboard"""
        if not self.report:
            print("⚠️ No report data provided — skipping risk dashboard.")
            return

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 16))
        self._plot_risk_distribution(ax1)
        self._plot_finding_types(ax2)
        self._plot_entity_risk_scores(ax3)
        self._plot_remediation_priority(ax4)

        plt.suptitle('IAM Entitlement Risk Dashboard', fontsize=20, y=0.95)
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close(fig)

        print(f"📈 Risk dashboard saved to: {output_file}")

    def _plot_risk_distribution(self, ax):
        risk_scores = list(self.report.get('risk_scores', {}).values())
        if not risk_scores:
            ax.text(0.5, 0.5, "No risk scores available", ha='center', va='center')
            return

        ax.hist(risk_scores, bins=20, color='#4FC3F7', alpha=0.7, edgecolor='black')
        ax.set_title('Risk Score Distribution')
        ax.set_xlabel('Risk Score')
        ax.set_ylabel('Number of Entities')
        ax.grid(True, alpha=0.3)

    def _plot_finding_types(self, ax):
        findings = self.report.get('findings', {})
        finding_counts = {k: len(v) for k, v in findings.items() if v}

        if not finding_counts:
            ax.text(0.5, 0.5, "No findings available", ha='center', va='center')
            return

        colors = [self.colors['CRITICAL'], self.colors['HIGH'],
                  self.colors['MEDIUM'], self.colors['LOW']]
        ax.pie(finding_counts.values(), labels=finding_counts.keys(),
               autopct='%1.1f%%', colors=colors[:len(finding_counts)])
        ax.set_title('Finding Types Distribution')

    def _plot_entity_risk_scores(self, ax):
        risk_scores = self.report.get('risk_scores', {})
        if not risk_scores:
            ax.text(0.5, 0.5, "No entities found", ha='center', va='center')
            return

        top_entities = sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)[:10]
        entities, scores = zip(*top_entities)
        colors = [self.colors['CRITICAL'] if s >= 80 else
                  self.colors['HIGH'] if s >= 60 else
                  self.colors['MEDIUM'] if s >= 40 else
                  self.colors['LOW'] for s in scores]

        bars = ax.bar(entities, scores, color=colors, alpha=0.7)
        ax.set_title('Top 10 Entities by Risk Score')
        ax.set_xlabel('Entities')
        ax.set_ylabel('Risk Score')
        ax.tick_params(axis='x', rotation=45)
        ax.grid(True, alpha=0.3)

        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height,
                    f'{int(height)}', ha='center', va='bottom')

    def _plot_remediation_priority(self, ax):
        findings = self.report.get('findings', {})
        if not findings:
            ax.text(0.5, 0.5, "No findings for remediation", ha='center', va='center')
            return

        priority_counts = {
            'CRITICAL': len(findings.get('excessive_trust', [])) +
                        len(findings.get('cross_account_risks', [])),
            'HIGH': len(findings.get('over_privileged_roles', [])),
            'MEDIUM': len(findings.get('risky_permissions', [])),
            'LOW': len(findings.get('unused_roles', []))
        }

        priorities = list(priority_counts.keys())
        counts = list(priority_counts.values())
        colors = [self.colors[p] for p in priorities]

        bars = ax.bar(priorities, counts, color=colors, alpha=0.7)
        ax.set_title('Remediation Priority Matrix')
        ax.set_xlabel('Priority Level')
        ax.set_ylabel('Number of Findings')
        ax.grid(True, alpha=0.3)

        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height,
                    f'{int(height)}', ha='center', va='bottom')


class IAMVisualizer:
    def __init__(self, output_format: str = 'console', output_file: Optional[str] = None):
        self.output_format = output_format
        self.output_file = output_file

    def generate_visualization(self, findings: Dict[str, Any]) -> str:
        # Basic validation per tests
        if not isinstance(findings, dict):
            raise TypeError("findings must be a dict")

        expected_keys = ('high_risk', 'medium_risk', 'low_risk')
        if not any(k in findings for k in expected_keys):
            # If none of the expected keys are present, signal invalid structure
            raise KeyError("Missing required findings keys")

        # Default any missing risk groups to empty lists to be lenient for tests
        findings = {
            'high_risk': findings.get('high_risk', []),
            'medium_risk': findings.get('medium_risk', []),
            'low_risk': findings.get('low_risk', []),
        }

        if self.output_format not in ('console', 'json', 'graphviz'):
            raise ValueError(f"Invalid output format: {self.output_format}")

        if self.output_format == 'console':
            content = self._to_console(findings)
        elif self.output_format == 'json':
            content = self._to_json(findings)
        else:
            content = self._to_graphviz(findings)

        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(content)

        return content

    def _to_console(self, findings: Dict[str, Any]) -> str:
        lines = []
        # Headings
        lines.append("High Risk Findings:")
        if findings['high_risk']:
            for item in findings['high_risk']:
                principal = item.get('principal', '')
                for f in item.get('findings', []) or []:
                    action = f.get('action', '')
                    lines.append(f"- {principal} -> {action}")
        else:
            lines.append("No findings")

        lines.append("")
        lines.append("Medium Risk Findings:")
        if findings['medium_risk']:
            for item in findings['medium_risk']:
                principal = item.get('principal', '')
                for f in item.get('findings', []) or []:
                    action = f.get('action', '')
                    lines.append(f"- {principal} -> {action}")
        else:
            lines.append("No findings")

        lines.append("")
        lines.append("Low Risk Findings:")
        if findings['low_risk']:
            for item in findings['low_risk']:
                principal = item.get('principal', '')
                for f in item.get('findings', []) or []:
                    action = f.get('action', '')
                    lines.append(f"- {principal} -> {action}")
        else:
            lines.append("No findings")

        return "\n".join(lines)

    def _to_json(self, findings: Dict[str, Any]) -> str:
        return json.dumps(findings)

    def _to_graphviz(self, findings: Dict[str, Any]) -> str:
        # Create a simple DOT graph containing principals and actions
        lines = ["digraph IAM {", "  rankdir=LR;"]

        def short_name(principal: str) -> str:
            # Extract readable name if ARN contains '/'
            if not isinstance(principal, str):
                return str(principal)
            if '/' in principal:
                return principal.split('/')[-1]
            return principal

        def add_group(items, color: str):
            for item in items:
                principal = item.get('principal', '')
                p_label = short_name(principal)
                p_node = f'"{p_label}"'
                # declare node
                lines.append(f"  {p_node} [shape=box, color=\"{color}\"]; ")
                for fnd in item.get('findings', []) or []:
                    action = fnd.get('action', '')
                    a_node = f'"{action}"'
                    lines.append(f"  {p_node} -> {a_node};")

        add_group(findings.get('high_risk', []), '#FF6B6B')
        add_group(findings.get('medium_risk', []), '#FFA726')
        add_group(findings.get('low_risk', []), '#C8E6C9')

        lines.append("}")
        return "\n".join(lines)


def generate_visualizations_from_report(report_file: str = 'entitlement_report.json'):
    """Generate all visualizations from a saved report file"""
    with open(report_file, 'r') as f:
        report = json.load(f)

    visualizer = PrivilegeVisualizer(report)
    return visualizer.generate_visualizations("visuals")


if __name__ == '__main__':
    generate_visualizations_from_report()
