# tests/unit/test_storage_reporter.py
import pytest
import json
import csv
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime
from scanners.storage_auditor.reporter import StorageAuditReporter

@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return {
        'public_buckets': [
            {
                'bucket_name': 'test-bucket-1',
                'severity': 'high',
                'resource_type': 's3',
                'issue_type': 'public_access',
                'details': 'Bucket has public read access'
            }
        ],
        'unencrypted_buckets': [
            {
                'bucket_name': 'test-bucket-2',
                'severity': 'medium',
                'resource_type': 's3',
                'issue_type': 'encryption',
                'details': 'Bucket is not encrypted'
            }
        ]
    }

@pytest.fixture
def template_dir(tmp_path):
    """Create a template directory with a test template."""
    template_dir = tmp_path / 'templates'
    template_dir.mkdir()
    (template_dir / 'storage_audit.html').write_text("""
    <html>
    <body>
        {% for type, items in findings.items() %}
        <h2>{{ type }}</h2>
        <ul>
            {% for item in items %}
            <li>{{ item.bucket_name }} - {{ item.severity }}</li>
            {% endfor %}
        </ul>
        {% endfor %}
    </body>
    </html>
    """)
    return template_dir

@pytest.fixture
def reporter(tmp_path, template_dir):
    """Create a StorageAuditReporter instance for testing with template directory."""
    from scanners.storage_auditor.reporter import StorageAuditReporter
    return StorageAuditReporter(
        output_dir=str(tmp_path),
        template_dir=str(template_dir)
    )

def test_initialization(tmp_path):
    """Test StorageAuditReporter initialization."""
    from scanners.storage_auditor.reporter import StorageAuditReporter
    
    # Test with default template directory
    reporter = StorageAuditReporter(output_dir=str(tmp_path))
    assert reporter.output_dir == Path(tmp_path)
    
    # Test with custom template directory
    custom_templates = tmp_path / 'custom_templates'
    custom_templates.mkdir()
    reporter = StorageAuditReporter(
        output_dir=str(tmp_path),
        template_dir=str(custom_templates)
    )
    assert str(custom_templates) in str(reporter.env.loader.searchpath[0])

@patch('scanners.storage_auditor.reporter.datetime')
def test_generate_json_report(mock_datetime, reporter, sample_findings, tmp_path):
    """Test JSON report generation."""
    from scanners.storage_auditor.reporter import StorageAuditReporter
    
    # Mock datetime for consistent testing
    mock_datetime.utcnow.return_value.strftime.return_value = '20230101_120000'
    
    # Test with default name
    report_path = reporter.generate_json_report(sample_findings)
    assert report_path.endswith('storage_audit_20230101_120000.json')
    assert (tmp_path / 'storage_audit_20230101_120000.json').exists()
    
    # Test with custom name
    custom_name = 'custom_report.json'
    report_path = reporter.generate_json_report(sample_findings, report_name=custom_name)
    assert report_path.endswith(custom_name)
    assert (tmp_path / custom_name).exists()
    
    # Verify content
    with open(report_path, 'r') as f:
        content = json.load(f)
        assert 'public_buckets' in content
        assert 'unencrypted_buckets' in content

@patch('scanners.storage_auditor.reporter.datetime')
def test_generate_html_report(mock_datetime, template_dir, reporter, sample_findings, tmp_path):
    """Test HTML report generation."""
    # Set up mock datetime
    mock_datetime.utcnow.return_value.strftime.return_value = '20230101_120000'
    
    reporter = StorageAuditReporter(
        output_dir=str(tmp_path / 'reports'),
        template_dir=str(template_dir)
    )
    
    # Test report generation
    report_path = reporter.generate_html_report(sample_findings)
    assert report_path.endswith('.html')
    assert (tmp_path / 'reports' / 'storage_audit_20230101_120000.html').exists()
    
    # Verify content
    with open(report_path, 'r') as f:
        content = f.read()
        assert 'test-bucket-1' in content
        assert 'test-bucket-2' in content

@patch('scanners.storage_auditor.reporter.datetime')
def test_generate_csv_report(mock_datetime, reporter, sample_findings, tmp_path):
    """Test CSV report generation."""
    # Set up mock datetime
    mock_datetime.utcnow.return_value.strftime.return_value = '20230101_120000'
    report_path = reporter.generate_csv_report(sample_findings)
    assert report_path.endswith('.csv')
    
    # Verify content
    with open(report_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]['bucket_name'] == 'test-bucket-1'
        assert rows[1]['bucket_name'] == 'test-bucket-2'
        assert 'severity' in rows[0]
        assert 'resource_type' in rows[0]
        assert 'issue_type' in rows[0]

@patch('scanners.storage_auditor.reporter.datetime')
def test_generate_report(mock_datetime, reporter, template_dir, sample_findings, tmp_path):
    """Test report generation with different formats."""
    # Set up mock datetime
    mock_datetime.utcnow.return_value.strftime.return_value = '20230101_120000'
    
    # Re-initialize reporter with template directory
    reporter = StorageAuditReporter(
        output_dir=str(tmp_path / 'reports'),
        template_dir=str(template_dir)
    )
    
    # Test HTML format
    html_path = reporter.generate_report(sample_findings, 'html')
    assert html_path.endswith('.html')
    
    # Test JSON format
    json_path = reporter.generate_report(sample_findings, 'json')
    assert json_path.endswith('.json')
    
    # Test CSV format
    csv_path = reporter.generate_report(sample_findings, 'csv')
    assert csv_path.endswith('.csv')
    
    # Test unsupported format
    with pytest.raises(ValueError, match="Unsupported report format: txt"):
        reporter.generate_report(sample_findings, 'txt')

def test_generate_summary(reporter, sample_findings):
    """Test generation of summary information."""
    summary = reporter.generate_summary(sample_findings)
    
    assert 'timestamp' in summary
    assert summary['total_findings'] == 2
    assert summary['by_severity'] == {'high': 1, 'medium': 1}
    assert summary['by_resource_type'] == {'s3': 2}
    assert summary['by_issue_type'] == {'public_access': 1, 'encryption': 1}

def test_empty_findings(reporter, tmp_path):
    """Test report generation with empty findings."""
    # Test with empty findings
    empty_findings = {}
    
    # Should not raise exceptions
    reporter.generate_json_report(empty_findings)
    reporter.generate_csv_report(empty_findings)
    
    # Verify CSV with empty findings
    csv_path = tmp_path / 'empty.csv'
    reporter.generate_csv_report(empty_findings, report_name='empty.csv')
    assert not csv_path.exists() or csv_path.stat().st_size == 0

@patch('builtins.open', new_callable=mock_open)
@patch('json.dump')
def test_file_operations(mock_json_dump, mock_file, reporter, sample_findings):
    """Test file operations during report generation."""
    # Test JSON report file operations
    reporter.generate_json_report(sample_findings, 'test.json')
    mock_file.assert_called_once()
    mock_json_dump.assert_called_once_with(sample_findings, mock_file.return_value.__enter__.return_value, indent=2)

def test_error_handling(reporter, sample_findings, tmp_path):
    """Test error handling during report generation."""
    # Test with invalid template directory
    with pytest.raises(Exception):
        reporter = StorageAuditReporter(
            output_dir=str(tmp_path),
            template_dir='/nonexistent/directory'
        )
        reporter.generate_html_report(sample_findings)
    
    # Test with invalid JSON serialization
    class NonSerializable:
        pass
    
    with pytest.raises(TypeError):
        reporter.generate_json_report({'invalid': NonSerializable()})

def test_custom_output_dir(reporter, tmp_path):
    """Test report generation in custom output directory."""
    custom_dir = tmp_path / 'custom_reports'
    reporter = StorageAuditReporter(output_dir=str(custom_dir))
    
    # Should create the directory if it doesn't exist
    assert not custom_dir.exists()
    reporter.generate_json_report({}, 'test.json')
    assert custom_dir.exists()