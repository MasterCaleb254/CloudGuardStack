# tests/integration/test_reports_generator_integration.py
import pytest
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime
from scanners.reports.generator import ReportGenerator
from scanners.reports.templates import HTML_TEMPLATE, PDF_TEMPLATE

# Sample test data
SAMPLE_REPORT_DATA = {
    "metadata": {
        "report_id": "test-report-123",
        "generated_at": "2023-01-01T00:00:00Z",
        "account_id": "123456789012",
        "region": "us-east-1"
    },
    "findings": [
        {
            "id": "finding-1",
            "severity": "high",
            "title": "Public S3 Bucket",
            "description": "S3 bucket is publicly accessible",
            "resource_arn": "arn:aws:s3:::test-bucket",
            "resource_type": "AWS::S3::Bucket",
            "details": {
                "public_access": True,
                "block_public_access": False
            }
        }
    ],
    "summary": {
        "total_findings": 1,
        "severity_counts": {"high": 1, "medium": 0, "low": 0},
        "resource_types": {"AWS::S3::Bucket": 1}
    }
}

@pytest.fixture
def report_generator(tmp_path):
    """Create a ReportGenerator instance with a temporary output directory."""
    return ReportGenerator(output_dir=str(tmp_path))

def test_generate_html_report(report_generator, tmp_path):
    """Test generating an HTML report."""
    # Generate the report
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name="default"
    )
    
    # Verify the output file
    assert os.path.exists(output_file)
    assert output_file.endswith('.html')
    
    # Verify the file contains expected content
    with open(output_file, 'r') as f:
        content = f.read()
        assert "Security Report" in content
        assert "test-bucket" in content
        assert "high" in content.lower()

def test_generate_pdf_report(report_generator, tmp_path):
    """Test generating a PDF report."""
    # Mock the PDF generation
    with patch('weasyprint.HTML') as mock_html:
        # Generate the report
        output_file = report_generator.generate_report(
            report_data=SAMPLE_REPORT_DATA,
            report_format="pdf",
            template_name="default"
        )
        
        # Verify the output file
        assert os.path.exists(output_file)
        assert output_file.endswith('.pdf')
        
        # Verify PDF generation was called
        mock_html.assert_called_once()

def test_custom_template(report_generator, tmp_path):
    """Test generating a report with a custom template."""
    # Create a custom template
    custom_template = tmp_path / "templates" / "custom.html"
    custom_template.parent.mkdir(parents=True, exist_ok=True)
    custom_template.write_text("""
    <html>
    <body>
        <h1>Custom Report</h1>
        <div id="content">{{ report_data.metadata.report_id }}</div>
    </body>
    </html>
    """)
    
    # Generate the report with custom template
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name=str(custom_template)
    )
    
    # Verify the custom template was used
    with open(output_file, 'r') as f:
        content = f.read()
        assert "Custom Report" in content
        assert SAMPLE_REPORT_DATA["metadata"]["report_id"] in content

def test_generate_report_with_filters(report_generator, tmp_path):
    """Test generating a report with severity filters."""
    # Generate report with high severity filter
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name="default",
        filters={"severity": ["high"]}
    )
    
    # Verify the output contains high severity finding
    with open(output_file, 'r') as f:
        content = f.read()
        assert "finding-1" in content
    
    # Generate report with non-matching filter
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name="default",
        filters={"severity": ["low"]}
    )
    
    # Verify the output doesn't contain high severity finding
    with open(output_file, 'r') as f:
        content = f.read()
        assert "finding-1" not in content

def test_generate_report_with_custom_styles(report_generator, tmp_path):
    """Test generating a report with custom CSS styles."""
    # Create a custom styles directory
    styles_dir = tmp_path / "styles"
    styles_dir.mkdir()
    
    # Create a custom CSS file
    custom_css = styles_dir / "custom.css"
    custom_css.write_text("""
    .severity-high { color: red; }
    .severity-medium { color: orange; }
    .severity-low { color: green; }
    """)
    
    # Generate the report with custom styles
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name="default",
        stylesheet_path=str(custom_css)
    )
    
    # Verify the custom styles are included
    with open(output_file, 'r') as f:
        content = f.read()
        assert "severity-high" in content
        assert "color: red" in content

def test_generate_report_with_custom_metadata(report_generator, tmp_path):
    """Test generating a report with custom metadata."""
    # Add custom metadata
    report_data = SAMPLE_REPORT_DATA.copy()
    report_data["metadata"]["custom_field"] = "custom_value"
    
    # Generate the report
    output_file = report_generator.generate_report(
        report_data=report_data,
        report_format="html",
        template_name="default"
    )
    
    # Verify the custom metadata is included
    with open(output_file, 'r') as f:
        content = f.read()
        assert "custom_field" in content
        assert "custom_value" in content

def test_generate_report_with_missing_template(report_generator):
    """Test generating a report with a non-existent template."""
    with pytest.raises(FileNotFoundError):
        report_generator.generate_report(
            report_data=SAMPLE_REPORT_DATA,
            report_format="html",
            template_name="non_existent_template"
        )

def test_generate_report_with_invalid_format(report_generator):
    """Test generating a report with an invalid format."""
    with pytest.raises(ValueError):
        report_generator.generate_report(
            report_data=SAMPLE_REPORT_DATA,
            report_format="invalid_format",
            template_name="default"
        )

def test_generate_report_with_empty_findings(report_generator, tmp_path):
    """Test generating a report with no findings."""
    # Create report data with no findings
    report_data = {
        "metadata": {
            "report_id": "empty-report",
            "generated_at": "2023-01-01T00:00:00Z"
        },
        "findings": [],
        "summary": {
            "total_findings": 0,
            "severity_counts": {},
            "resource_types": {}
        }
    }
    
    # Generate the report
    output_file = report_generator.generate_report(
        report_data=report_data,
        report_format="html",
        template_name="default"
    )
    
    # Verify the output indicates no findings
    with open(output_file, 'r') as f:
        content = f.read()
        assert "No findings" in content or "0 findings" in content

def test_generate_report_with_custom_filters(report_generator, tmp_path):
    """Test generating a report with custom filter functions."""
    # Define a custom filter
    def custom_filter(finding):
        return finding.get("severity") == "high"
    
    # Generate the report with custom filter
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name="default",
        filters=custom_filter
    )
    
    # Verify the output contains only high severity findings
    with open(output_file, 'r') as f:
        content = f.read()
        assert "finding-1" in content
    
    # Test with a filter that excludes all findings
    def exclude_all_filter(finding):
        return False
    
    output_file = report_generator.generate_report(
        report_data=SAMPLE_REPORT_DATA,
        report_format="html",
        template_name="default",
        filters=exclude_all_filter
    )
    
    with open(output_file, 'r') as f:
        content = f.read()
        assert "finding-1" not in content