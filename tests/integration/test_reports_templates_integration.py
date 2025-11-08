# tests/integration/test_reports_templates_integration.py
import pytest
import os
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock
from scanners.reports.templates import (
    ReportTemplates,
    HTML_TEMPLATE,
    PDF_TEMPLATE,
    DEFAULT_STYLES,
    SEVERITY_COLORS,
    format_timestamp,
    format_severity,
    format_resource_type,
    format_finding_details
)

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
def report_templates(tmp_path):
    """Create a ReportTemplates instance with a temporary template directory."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    return ReportTemplates(template_dir=str(templates_dir))

def test_load_default_template(report_templates):
    """Test loading the default template."""
    template = report_templates.get_template("default")
    assert template is not None
    assert "{{ report_data.metadata.report_id }}" in template

def test_load_custom_template(report_templates, tmp_path):
    """Test loading a custom template from file."""
    # Create a custom template
    custom_template = tmp_path / "templates" / "custom.html"
    custom_template.write_text("<h1>Custom Template: {{ report_data.metadata.report_id }}</h1>")
    
    # Load the custom template
    template = report_templates.get_template(str(custom_template))
    assert template is not None
    assert "Custom Template" in template

def test_render_template(report_templates):
    """Test rendering a template with data."""
    rendered = report_templates.render(
        template_name="default",
        report_data=SAMPLE_REPORT_DATA
    )
    assert rendered is not None
    assert SAMPLE_REPORT_DATA["metadata"]["report_id"] in rendered
    assert SAMPLE_REPORT_DATA["findings"][0]["title"] in rendered

def test_format_timestamp():
    """Test timestamp formatting."""
    # Test with ISO format
    timestamp = "2023-01-01T12:34:56Z"
    formatted = format_timestamp(timestamp)
    assert "2023-01-01" in formatted
    assert "12:34:56" in formatted
    
    # Test with datetime object
    dt = datetime(2023, 1, 1, 12, 34, 56)
    formatted = format_timestamp(dt)
    assert "2023-01-01" in formatted
    assert "12:34:56" in formatted

def test_format_severity():
    """Test severity formatting."""
    # Test with valid severity
    assert "High" in format_severity("high")
    assert "Medium" in format_severity("medium")
    assert "Low" in format_severity("low")
    
    # Test with unknown severity
    assert "Unknown" in format_severity("unknown")

def test_format_resource_type():
    """Test resource type formatting."""
    # Test with AWS resource type
    assert "S3 Bucket" in format_resource_type("AWS::S3::Bucket")
    
    # Test with custom resource type
    assert "CustomResource" in format_resource_type("CustomResource")

def test_format_finding_details():
    """Test finding details formatting."""
    details = {
        "key1": "value1",
        "key2": 123,
        "nested": {
            "key3": [1, 2, 3],
            "key4": {"a": "b"}
        }
    }
    
    formatted = format_finding_details(details)
    assert "key1" in formatted
    assert "value1" in formatted
    assert "nested" in formatted
    assert "key3" in formatted

def test_get_styles(report_templates):
    """Test getting default styles."""
    styles = report_templates.get_styles()
    assert "severity-high" in styles
    assert "severity-medium" in styles
    assert "severity-low" in styles

def test_custom_styles(report_templates, tmp_path):
    """Test loading custom styles."""
    # Create a custom styles file
    custom_styles = tmp_path / "custom_styles.css"
    custom_styles.write_text(".custom-style { color: red; }")
    
    # Load custom styles
    styles = report_templates.get_styles(str(custom_styles))
    assert ".custom-style" in styles

def test_template_rendering_with_filters(report_templates):
    """Test template rendering with custom filters."""
    # Create a template that uses custom filters
    template = """
    {{ report_data.findings[0].severity|upper }}
    {{ report_data.metadata.generated_at|format_timestamp }}
    """
    
    # Render the template
    rendered = report_templates._render_template(
        template,
        report_data=SAMPLE_REPORT_DATA
    )
    
    # Verify filters were applied
    assert "HIGH" in rendered
    assert "2023-01-01" in rendered

def test_template_rendering_with_conditional_logic(report_templates):
    """Test template rendering with conditional logic."""
    template = """
    {% if report_data.findings %}
    <ul>
    {% for finding in report_data.findings %}
        <li>{{ finding.title }} ({{ finding.severity|upper }})</li>
    {% endfor %}
    </ul>
    {% else %}
    <p>No findings</p>
    {% endif %}
    """
    
    # Render with findings
    rendered = report_templates._render_template(
        template,
        report_data=SAMPLE_REPORT_DATA
    )
    assert "<ul>" in rendered
    assert "Public S3 Bucket" in rendered
    assert "HIGH" in rendered
    
    # Render without findings
    empty_data = SAMPLE_REPORT_DATA.copy()
    empty_data["findings"] = []
    rendered = report_templates._render_template(template, report_data=empty_data)
    assert "No findings" in rendered

def test_template_rendering_with_custom_functions(report_templates):
    """Test template rendering with custom template functions."""
    # Create a template that uses custom functions
    template = """
    {{ format_severity('high') }}
    {{ format_resource_type('AWS::S3::Bucket') }}
    {{ format_finding_details({'key': 'value'}) }}
    """
    
    # Render the template
    rendered = report_templates._render_template(
        template,
        report_data=SAMPLE_REPORT_DATA
    )
    
    # Verify custom functions were called
    assert "High" in rendered
    assert "S3 Bucket" in rendered
    assert "key" in rendered
    assert "value" in rendered

def test_template_error_handling(report_templates):
    """Test template error handling."""
    # Test with invalid template syntax
    with pytest.raises(Exception):
        report_templates._render_template(
            "{% invalid template syntax %}",
            report_data=SAMPLE_REPORT_DATA
        )
    
    # Test with missing variable
    rendered = report_templates._render_template(
        "{{ non_existent_variable }}",
        report_data=SAMPLE_REPORT_DATA
    )
    assert "" == rendered.strip()

def test_template_inheritance(report_templates, tmp_path):
    """Test template inheritance."""
    # Create a base template
    base_template = tmp_path / "templates" / "base.html"
    base_template.write_text("""
    <html>
    <head><title>{% block title %}Default Title{% endblock %}</title></head>
    <body>{% block content %}{% endblock %}</body>
    </html>
    """)
    
    # Create a child template
    child_template = tmp_path / "templates" / "child.html"
    child_template.write_text("""
    {% extends "base.html" %}
    {% block title %}Child Title{% endblock %}
    {% block content %}<h1>Child Content</h1>{% endblock %}
    """)
    
    # Render the child template
    rendered = report_templates.render("child", report_data=SAMPLE_REPORT_DATA)
    assert "Child Title" in rendered
    assert "Child Content" in rendered
    assert "Default Title" not in rendered