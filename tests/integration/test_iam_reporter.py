# tests/integration/test_iam_reporter.py
import pytest
import json
import csv
from pathlib import Path
from datetime import datetime
from scanners.iam_entitlement.reporter import IAMReporter

@pytest.fixture
def sample_findings():
    """Sample IAM findings for testing."""
    return {
        'excessive_permissions': [
            {
                'id': 'finding-1',
                'severity': 'high',
                'resource_type': 'iam_policy',
                'principal_type': 'iam_role',
                'resource_arn': 'arn:aws:iam::123456789012:role/TestRole',
                'details': {
                    'policy_arn': 'arn:aws:iam::123456789012:policy/TestPolicy',
                    'excessive_permissions': ['s3:DeleteBucket', 'ec2:TerminateInstances'],
                    'used_permissions': ['s3:GetObject', 's3:PutObject']
                }
            }
        ],
        'unused_roles': [
            {
                'id': 'finding-2',
                'severity': 'medium',
                'resource_type': 'iam_role',
                'principal_type': 'iam_role',
                'resource_arn': 'arn:aws:iam::123456789012:role/UnusedRole',
                'details': {
                    'last_used': '2023-01-01T00:00:00Z',
                    'days_since_last_use': 300
                }
            }
        ]
    }

@pytest.fixture
def reporter(tmp_path):
    """Create an IAMReporter instance with a temporary directory."""
    return IAMReporter(output_dir=str(tmp_path))

def test_json_report_creation(reporter, sample_findings, tmp_path):
    """Test JSON report file creation and content."""
    # Generate report
    report_path = reporter.generate_json_report(sample_findings)
    
    # Verify file was created
    assert Path(report_path).exists()
    assert report_path.endswith('.json')
    
    # Verify content
    with open(report_path, 'r') as f:
        content = json.load(f)
        assert 'excessive_permissions' in content
        assert 'unused_roles' in content
        assert len(content['excessive_permissions']) == 1
        assert len(content['unused_roles']) == 1

def test_html_report_creation(reporter, sample_findings, tmp_path):
    """Test HTML report file creation and content."""
    # Create a simple template
    template_dir = tmp_path / 'templates'
    template_dir.mkdir()
    (template_dir / 'iam_entitlement.html').write_text("""
    <html>
    <body>
        {% for type, items in findings.items() %}
        <h2>{{ type }}</h2>
        <ul>
            {% for item in items %}
            <li>{{ item.resource_arn }} - {{ item.severity }}</li>
            {% endfor %}
        </ul>
        {% endfor %}
    </body>
    </html>
    """)
    
    # Create reporter with custom template directory
    reporter = IAMReporter(
        output_dir=str(tmp_path / 'reports'),
        template_dir=str(template_dir)
    )
    
    # Generate report
    report_path = reporter.generate_html_report(sample_findings)
    
    # Verify file was created
    assert Path(report_path).exists()
    assert report_path.endswith('.html')
    
    # Verify content
    with open(report_path, 'r') as f:
        content = f.read()
        assert 'TestRole' in content
        assert 'UnusedRole' in content
        assert 'high' in content
        assert 'medium' in content

def test_csv_report_creation(reporter, sample_findings, tmp_path):
    """Test CSV report file creation and content."""
    # Generate report
    report_path = reporter.generate_csv_report(sample_findings)
    
    # Verify file was created
    assert Path(report_path).exists()
    assert report_path.endswith('.csv')
    
    # Verify content
    with open(report_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]['finding_type'] == 'excessive_permissions'
        assert rows[1]['finding_type'] == 'unused_roles'
        assert 'resource_arn' in rows[0]
        assert 'severity' in rows[0]

def test_report_generation_all_formats(reporter, sample_findings, tmp_path):
    """Test report generation in all supported formats."""
    # Test HTML format
    html_path = reporter.generate_report(sample_findings, 'html')
    assert Path(html_path).exists()
    
    # Test JSON format
    json_path = reporter.generate_report(sample_findings, 'json')
    assert Path(json_path).exists()
    
    # Test CSV format
    csv_path = reporter.generate_report(sample_findings, 'csv')
    assert Path(csv_path).exists()
    
    # Verify all reports were created in the same directory
    assert Path(html_path).parent == Path(json_path).parent
    assert Path(html_path).parent == Path(csv_path).parent

def test_summary_generation(reporter, sample_findings):
    """Test summary generation from findings."""
    summary = reporter.generate_summary(sample_findings)
    
    # Verify summary structure
    assert 'timestamp' in summary
    assert 'total_findings' in summary
    assert 'by_severity' in summary
    assert 'by_resource_type' in summary
    assert 'by_principal_type' in summary
    
    # Verify counts
    assert summary['total_findings'] == 2
    assert summary['by_severity']['high'] == 1
    assert summary['by_severity']['medium'] == 1
    assert summary['by_resource_type']['iam_policy'] == 1
    assert summary['by_resource_type']['iam_role'] == 1
    assert summary['by_principal_type']['iam_role'] == 2

def test_empty_findings_handling(reporter, tmp_path):
    """Test report generation with empty findings."""
    # Test with empty findings
    empty_findings = {}
    
    # Generate reports
    json_path = reporter.generate_json_report(empty_findings)
    csv_path = reporter.generate_csv_report(empty_findings)
    
    # JSON should create an empty object
    with open(json_path, 'r') as f:
        content = json.load(f)
        assert content == {}
    
    # CSV should not create a file for empty findings
    assert not Path(csv_path).exists()

def test_custom_output_directory_creation(reporter, tmp_path):
    """Test that output directory is created if it doesn't exist."""
    custom_dir = tmp_path / 'custom_reports'
    reporter = IAMReporter(output_dir=str(custom_dir))
    
    # Directory should be created on first report generation
    assert not custom_dir.exists()
    reporter.generate_json_report({}, 'test.json')
    assert custom_dir.exists()

def test_error_handling_missing_template(reporter, sample_findings, tmp_path):
    """Test error handling when template is missing."""
    # Create reporter with empty template directory
    empty_dir = tmp_path / 'empty_templates'
    empty_dir.mkdir()
    reporter = IAMReporter(
        output_dir=str(tmp_path),
        template_dir=str(empty_dir)
    )
    
    # Should raise an error when template is missing
    with pytest.raises(Exception):
        reporter.generate_html_report(sample_findings)

def test_large_findings_handling(reporter, tmp_path):
    """Test report generation with a large number of findings."""
    # Generate a large number of findings
    large_findings = {
        'excessive_permissions': [
            {
                'id': f'finding-{i}',
                'severity': 'high',
                'resource_type': 'iam_policy',
                'principal_type': 'iam_role',
                'resource_arn': f'arn:aws:iam::123456789012:role/Role{i}',
                'details': {
                    'policy_arn': f'arn:aws:iam::123456789012:policy/Policy{i}',
                    'excessive_permissions': [f's3:Action{i}'],
                    'used_permissions': [f's3:UsedAction{i}']
                }
            }
            for i in range(1000)  # 1000 findings
        ]
    }
    
    # Test JSON report
    json_path = reporter.generate_json_report(large_findings)
    with open(json_path, 'r') as f:
        content = json.load(f)
        assert len(content['excessive_permissions']) == 1000
    
    # Test CSV report
    csv_path = reporter.generate_csv_report(large_findings)
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1000