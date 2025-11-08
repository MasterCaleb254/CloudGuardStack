#!/usr/bin/env python3
"""
Render simple demo graphs from generated JSON reports.
Creates `reports/iam_risk_scores.png` and `reports/storage_summary.png`.
"""
import json
import os
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
try:
    import plotext as pext
    _HAS_PLOTEXT = True
except Exception:
    _HAS_PLOTEXT = False

ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / 'reports'
REPORTS_DIR.mkdir(exist_ok=True)

def load_json(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️  Missing report: {path}")
        return None


def render_iam_risk_scores(report):
    if not report:
        return None
    scores = report.get('risk_scores', {})
    if not scores:
        print("⚠️  No risk scores in IAM report")
        return None
    names = list(scores.keys())
    vals = [scores[n] for n in names]

    plt.figure(figsize=(8,4))
    bars = plt.bar(names, vals, color='crimson')
    plt.ylabel('Risk Score')
    plt.ylim(0, 100)
    plt.title('IAM Entity Risk Scores')
    plt.xticks(rotation=30, ha='right')
    for bar, val in zip(bars, vals):
        plt.text(bar.get_x() + bar.get_width()/2, val+1, f"{val:.0f}", ha='center')
    out = REPORTS_DIR / 'iam_risk_scores.png'
    plt.tight_layout()
    plt.savefig(out)
    plt.close()
    print(f"✅ IAM graph saved: {out}")
    # Also render to terminal if possible
    if _HAS_PLOTEXT:
        try:
            names_short = [n[:12] for n in names]
            pext.clear_figure()
            pext.bar(names_short, vals, orientation='vertical', width=0.6, color='red')
            pext.title('IAM Entity Risk Scores')
            pext.ylim(0, 100)
            pext.show()
        except Exception as e:
            print(f"⚠️  Terminal IAM render failed: {e}")
    else:
        print("ℹ️  Install 'plotext' to see ASCII charts in terminal: pip install plotext")
    return out


def render_storage_summary(report):
    if not report:
        return None
    summary = report.get('summary', {})
    labels = []
    sizes = []
    if summary.get('total_public_buckets') is not None:
        labels.append('Public Buckets')
        sizes.append(summary.get('total_public_buckets', 0))
    if summary.get('total_sensitive_findings') is not None:
        labels.append('Sensitive Findings')
        sizes.append(summary.get('total_sensitive_findings', 0))
    if summary.get('total_configuration_issues') is not None:
        labels.append('Config Issues')
        sizes.append(summary.get('total_configuration_issues', 0))

    if not sizes or sum(sizes) == 0:
        # fallback: create a small bar chart with counts of findings
        counts = [len(report.get('public_buckets', [])), len(report.get('sensitive_data_findings', [])), len(report.get('insecure_configurations', []))]
        labels = ['Public Buckets','Sensitive Findings','Config Issues']
        sizes = counts

    plt.figure(figsize=(6,4))
    plt.title('Storage Findings Overview')
    colors = ['#ff6b6b', '#ffa94d', '#4cc9f0']
    try:
        plt.pie(sizes, labels=labels, autopct='%1.0f', colors=colors, startangle=140)
        out = REPORTS_DIR / 'storage_summary.png'
        plt.savefig(out)
        plt.close()
        print(f"✅ Storage graph saved: {out}")
        # Terminal rendering
        if _HAS_PLOTEXT:
            try:
                pext.clear_figure()
                pext.bar(labels, sizes, orientation='horizontal', color=['#ff6b6b', '#ffa94d', '#4cc9f0'])
                pext.title('Storage Findings Overview')
                pext.show()
            except Exception as e:
                print(f"⚠️  Terminal storage render failed: {e}")
        else:
            print("ℹ️  Install 'plotext' to see ASCII charts in terminal: pip install plotext")
        return out
    except Exception as e:
        print(f"⚠️  Failed to render storage pie: {e}")
        plt.close()
        return None


if __name__ == '__main__':
    iam_report = load_json(ROOT / 'entitlement_report.json')
    storage_report = load_json(ROOT / 'storage_demo_findings.json')

    iam_img = render_iam_risk_scores(iam_report)
    storage_img = render_storage_summary(storage_report)

    if not iam_img and not storage_img:
        print('⚠️  No graphs generated')
        sys.exit(2)

    # Print filenames to make it easy for the caller to pick them up
    if iam_img:
        print(iam_img)
    if storage_img:
        print(storage_img)

    # Create a simple markdown preview that references the generated images
    try:
        preview_md = REPORTS_DIR / 'demo_preview.md'
        with open(preview_md, 'w') as f:
            f.write('# CloudGuardStack Demo Preview\n\n')
            if iam_img:
                f.write('## IAM Risk Scores\n')
                f.write(f'![]({iam_img.name})\n\n')
            if storage_img:
                f.write('## Storage Findings Overview\n')
                f.write(f'![]({storage_img.name})\n\n')
            f.write('_Generated by scripts/render_demo_graphs.py_\n')
        print(f"✅ Preview markdown created: {preview_md}")
    except Exception as e:
        print(f"⚠️  Failed to create preview markdown: {e}")

    sys.exit(0)
