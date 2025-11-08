# tests/integration/test_storage_reporter_integration.py
import pytest
import os
import json
import boto3
import pandas as pd
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from botocore.stub import Stubber
from datetime import datetime, timedelta
from scanners.storage_auditor.reporter import StorageReporter, ReportFormat

# Sample test data
SAMPLE_FINDINGS = [
    {
        "id": "finding-1",
        "resource_type": "AWS::S3::Bucket",
        "resource_arn": "arn:aws:s3:::test-bucket-1",
        "finding_type": "public_access",
        "severity": "high",
        "title": "Public Access Allowed",
        "description": "Bucket allows public access",
        "details": {
            "public_access": True,
            "block_public_access": False
        },
        "created_at": "2023-01-01T00:00:00Z"
    },
    {
        "id": "finding-2",
        "resource_type": "AWS::S3::Bucket",
        "resource_arn": "arn:aws:s3:::test-bucket-2",
        "finding_type": "unencrypted",
        "severity": "medium",
        "title": "Bucket Not Encrypted",
        "description": "Bucket does not have encryption enabled",
        "details": {
            "encryption": False
        },
        "created_at": "2023-01-02T00:00:00Z"
    }
]

SAMPLE_METRICS = {
    "total_resources": 10,
    "scanned_resources": 8,
    "findings_count": len(SAMPLE_FINDINGS),
    "severity_counts": {
        "high": 1,
        "medium": 1,
        "low": 0,
        "informational": 0
    },
    "resource_type_counts": {
        "AWS::S3::Bucket": 2
    }
}

@pytest.fixture
def reporter(tmp_path):
    """Create a StorageReporter instance with a temporary output directory."""
    return StorageReporter(
        findings=SAMPLE_FINDINGS,
        metrics=SAMPLE_METRICS,
        output_dir=str(tmp_path)
    )

def test_generate_html_report(reporter, tmp_path):
    """Test generating an HTML report."""
    # Generate the report
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="test_report"
    )
    
    # Verify the report was created
    assert os.path.exists(report_path)
    assert report_path.endswith(".html")
    
    # Verify the report content
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Storage Audit Report" in content
        assert "test-bucket-1" in content
        assert "test-bucket-2" in content

def test_generate_pdf_report(reporter, tmp_path):
    """Test generating a PDF report."""
    # Mock the PDF generation
    with patch('weasyprint.HTML') as mock_html:
        # Generate the report
        report_path = reporter.generate_report(
            report_format=ReportFormat.PDF,
            report_name="test_report"
        )
        
        # Verify the report path
        assert report_path.endswith(".pdf")
        
        # Verify PDF generation was called
        mock_html.assert_called_once()

def test_generate_csv_report(reporter, tmp_path):
    """Test generating a CSV report."""
    # Generate the report
    report_path = reporter.generate_report(
        report_format=ReportFormat.CSV,
        report_name="test_report"
    )
    
    # Verify the report was created
    assert os.path.exists(report_path)
    assert report_path.endswith(".csv")
    
    # Verify the CSV content
    df = pd.read_csv(report_path)
    assert len(df) == len(SAMPLE_FINDINGS)
    assert set(df['resource_arn']) == {f"test-bucket-{i+1}" for i in range(2)}

def test_generate_json_report(reporter, tmp_path):
    """Test generating a JSON report."""
    # Generate the report
    report_path = reporter.generate_report(
        report_format=ReportFormat.JSON,
        report_name="test_report"
    )
    
    # Verify the report was created
    assert os.path.exists(report_path)
    assert report_path.endswith(".json")
    
    # Verify the JSON content
    with open(report_path, 'r') as f:
        data = json.load(f)
        assert "findings" in data
        assert "metrics" in data
        assert len(data["findings"]) == len(SAMPLE_FINDINGS)
        assert data["metrics"]["findings_count"] == len(SAMPLE_FINDINGS)

def test_generate_report_with_filters(reporter, tmp_path):
    """Test generating a report with filters."""
    # Generate a filtered report
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="filtered_report",
        severity_filters=["high"]
    )
    
    # Verify the report content
    with open(report_path, 'r') as f:
        content = f.read()
        assert "test-bucket-1" in content  # High severity
        assert "test-bucket-2" not in content  # Medium severity

def test_generate_report_with_custom_template(reporter, tmp_path):
    """Test generating a report with a custom template."""
    # Create a custom template
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    template_file = template_dir / "custom_template.html"
    template_file.write_text("""
    <html>
    <body>
        <h1>Custom Report</h1>
        <div id="findings-count">{{ metrics.findings_count }} findings</div>
    </body>
    </html>
    """)
    
    # Generate the report with custom template
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="custom_report",
        template_path=str(template_file)
    )
    
    # Verify the custom template was used
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Custom Report" in content
        assert f"{len(SAMPLE_FINDINGS)} findings" in content

def test_generate_report_with_custom_styles(reporter, tmp_path):
    """Test generating a report with custom styles."""
    # Create a custom stylesheet
    styles_dir = tmp_path / "styles"
    styles_dir.mkdir()
    styles_file = styles_dir / "custom_styles.css"
    styles_file.write_text("""
    .finding { color: red; }
    .severity-high { font-weight: bold; }
    """)
    
    # Generate the report with custom styles
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="styled_report",
        stylesheet_path=str(styles_file)
    )
    
    # Verify the styles were included
    with open(report_path, 'r') as f:
        content = f.read()
        assert ".finding" in content
        assert ".severity-high" in content

def test_generate_report_with_timeline(reporter, tmp_path):
    """Test generating a report with a timeline of findings."""
    # Generate a report with timeline
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="timeline_report",
        include_timeline=True
    )
    
    # Verify the timeline was included
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Findings Timeline" in content
        assert "2023-01-01" in content
        assert "2023-01-02" in content

def test_generate_report_with_metrics(reporter, tmp_path):
    """Test generating a report with metrics."""
    # Generate a report with metrics
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="metrics_report",
        include_metrics=True
    )
    
    # Verify the metrics were included
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Metrics" in content
        assert str(SAMPLE_METRICS["total_resources"]) in content
        assert str(SAMPLE_METRICS["findings_count"]) in content

def test_generate_report_with_severity_summary(reporter, tmp_path):
    """Test generating a report with a severity summary."""
    # Generate a report with severity summary
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="severity_report",
        include_severity_summary=True
    )
    
    # Verify the severity summary was included
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Severity Summary" in content
        assert "High" in content
        assert "Medium" in content

def test_generate_report_with_resource_type_summary(reporter, tmp_path):
    """Test generating a report with a resource type summary."""
    # Generate a report with resource type summary
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="resource_type_report",
        include_resource_type_summary=True
    )
    
    # Verify the resource type summary was included
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Resource Types" in content
        assert "AWS::S3::Bucket" in content

def test_generate_report_with_recommendations(reporter, tmp_path):
    """Test generating a report with remediation recommendations."""
    # Generate a report with recommendations
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="recommendations_report",
        include_recommendations=True
    )
    
    # Verify the recommendations were included
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Recommendations" in content
        assert "Remediation Steps" in content

def test_generate_report_with_custom_sections(reporter, tmp_path):
    """Test generating a report with custom sections."""
    # Define custom sections
    custom_sections = [
        {
            "title": "Executive Summary",
            "content": "<p>This is a custom executive summary.</p>"
        },
        {
            "title": "Appendix",
            "content": "<p>Additional information goes here.</p>"
        }
    ]
    
    # Generate a report with custom sections
    report_path = reporter.generate_report(
        report_format=ReportFormat.HTML,
        report_name="custom_sections_report",
        custom_sections=custom_sections
    )
    
    # Verify the custom sections were included
    with open(report_path, 'r') as f:
        content = f.read()
        assert "Executive Summary" in content
        assert "Appendix" in content
        assert "custom executive summary" in content.lower()