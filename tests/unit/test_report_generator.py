# tests/unit/test_report_generator.py
import pytest
import json
import csv
import os
from datetime import datetime
from unittest.mock import patch, mock_open
from scanners.reports.generator import ReportGenerator

@pytest.fixture
def sample_findings():
    return {
        'high': [
            {
                'principal': 'arn:aws:iam::123456789012:role/AdminRole',
                'action': 's3:DeleteBucket',
                'resource': '*',
                'used': False,
                'risk': 'Data loss'
            }
        ],
        'medium': [
            {
                'principal': 'arn:aws:iam::123456789012:user/Developer',
                'action': 'ec2:ModifyInstanceAttribute',
                'resource': 'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
                'used': True,
                'risk': 'Privilege escalation'
            }
        ],
        'low': []
    }

def test_initialization():
    """Test ReportGenerator initialization."""
    # Test default initialization
    generator = ReportGenerator()
    assert generator.output_format == 'console'
    assert generator.output_file is None
    
    # Test with custom format and file
    generator = ReportGenerator(output_format='json', output_file='report.json')
    assert generator.output_format == 'json'
    assert generator.output_file == 'report.json'
    
    # Test unsupported format
    with pytest.raises(ValueError):
        ReportGenerator(output_format='unsupported')

def test_generate_json(sample_findings):
    """Test JSON report generation."""
    generator = ReportGenerator(output_format='json')
    report = generator.generate(sample_findings)
    
    # Parse JSON and verify structure
    data = json.loads(report)
    assert 'metadata' in data
    assert 'findings' in data
    assert len(data['findings']['high']) == 1
    assert len(data['findings']['medium']) == 1
    assert len(data['findings']['low']) == 0
    assert data['findings']['high'][0]['principal'] == 'arn:aws:iam::123456789012:role/AdminRole'

def test_generate_csv(sample_findings):
    """Test CSV report generation."""
    generator = ReportGenerator(output_format='csv')
    report = generator.generate(sample_findings)
    
    # Split into lines and verify structure
    lines = report.strip().split('\n')
    assert lines[0].startswith('# generated_at:')
    assert 'severity,principal,action,resource,used,risk' in lines
    
    # Count data rows (header + 2 findings)
    data_rows = [line for line in lines if not line.startswith('#') and line]
    assert len(data_rows) == 3  # header + 2 findings

def test_generate_html(sample_findings):
    """Test HTML report generation."""
    generator = ReportGenerator(output_format='html')
    report = generator.generate(sample_findings)
    
    # Basic HTML structure checks
    assert '<!DOCTYPE html>' in report
    assert '<title>CloudGuardStack Security Report</title>' in report
    assert 'AdminRole' in report
    assert 'Developer' in report
    assert 'high' in report.lower()
    assert 'medium' in report.lower()

def test_generate_console(sample_findings):
    """Test console report generation."""
    generator = ReportGenerator(output_format='console')
    report = generator.generate(sample_findings)
    
    # Check for expected sections
    assert 'CLOUDGUARDSTACK SECURITY REPORT' in report
    assert 'METADATA:' in report
    assert 'FINDINGS' in report
    assert 'HIGH RISK' in report
    assert 'MEDIUM RISK' in report
    assert 'AdminRole' in report
    assert 'Developer' in report

def test_empty_findings():
    """Test report generation with empty findings."""
    generator = ReportGenerator(output_format='console')
    report = generator.generate({'high': [], 'medium': [], 'low': []})
    
    assert 'FINDINGS (0 total)' in report

def test_save_report(tmp_path):
    """Test saving report to file."""
    test_file = tmp_path / "test_report.txt"
    generator = ReportGenerator(output_file=str(test_file))
    
    with patch('builtins.open', mock_open()) as mock_file:
        generator.save_report("Test report content")
        mock_file.assert_called_once_with(str(test_file), 'w', encoding='utf-8')

def test_save_report_error():
    """Test error handling when saving report."""
    generator = ReportGenerator(output_file='/invalid/path/report.txt')
    
    with patch('builtins.open', side_effect=IOError("Permission denied")):
        with pytest.raises(IOError):
            generator.save_report("Test content")

def test_custom_metadata(sample_findings):
    """Test report generation with custom metadata."""
    metadata = {
        'title': 'Custom Report',
        'account_id': '123456789012',
        'region': 'us-east-1'
    }
    
    # Test JSON format
    generator = ReportGenerator(output_format='json')
    report = generator.generate(sample_findings, report_metadata=metadata)
    data = json.loads(report)
    
    # Check that custom metadata is included
    assert 'title' in data['metadata']
    assert data['metadata']['title'] == 'Custom Report'
    assert 'generated_at' in data['metadata']  # Should be auto-added

def test_special_characters():
    """Test handling of special characters in findings."""
    findings = {
        'high': [{
            'principal': 'user/with/special&chars?',
            'action': 's3:*',
            'resource': 'arn:aws:s3:::bucket/with/special/*',
            'used': True,
            'risk': 'high'
        }]
    }
    
    # Test all formats
    for fmt in ['json', 'csv', 'html', 'console']:
        generator = ReportGenerator(output_format=fmt)
        report = generator.generate(findings)
        assert 'user/with/special&chars?' in report

def test_large_findings_performance(benchmark):
    """Test performance with large number of findings."""
    # Generate large dataset
    large_findings = {
        'high': [{
            'principal': f'role-{i}',
            'action': f's3:Action{i}',
            'resource': '*',
            'used': i % 2 == 0,
            'risk': 'high'
        } for i in range(1000)],
        'medium': [],
        'low': []
    }
    
    generator = ReportGenerator(output_format='json')
    benchmark(generator.generate, large_findings)

def test_error_handling():
    """Test error handling in report generation."""
    generator = ReportGenerator()
    
    # Test invalid findings format
    with pytest.raises((TypeError, AttributeError)):
        generator.generate(None)
    
    with pytest.raises((TypeError, AttributeError)):
        generator.generate("invalid findings")
    
    # Test with empty findings
    with pytest.raises(ValueError):
        generator.generate({})

def test_html_escaping():
    """Test that HTML special characters are properly escaped."""
    findings = {
        'high': [{
            'principal': 'user<script>alert("xss")</script>',
            'action': 's3:*',
            'resource': 'arn:aws:s3:::bucket/with/<tag>',
            'used': True,
            'risk': 'XSS <injection>'
        }]
    }
    
    generator = ReportGenerator(output_format='html')
    report = generator.generate(findings)
    
    # Check that special characters are properly escaped
    assert '&lt;script&gt;' in report
    assert '&lt;tag&gt;' in report
    assert '&lt;injection&gt;' in report
    assert '<script>' not in report

def test_csv_quoting():
    """Test proper CSV quoting and escaping."""
    findings = {
        'high': [{
            'principal': 'user,with,commas',
            'action': 's3:Action"WithQuotes"',
            'resource': 'arn:aws:s3:::bucket/with/commas,and"quotes"',
            'used': True,
            'risk': 'high,risk'
        }]
    }
    
    generator = ReportGenerator(output_format='csv')
    report = generator.generate(findings)
    
    # Check that the CSV is properly formatted
    lines = [line for line in report.split('\n') if line and not line.startswith('#')]
    assert len(lines) == 2  # header + data row
    
    # Parse the CSV
    reader = csv.DictReader(lines)
    row = next(reader)
    
    assert row['principal'] == 'user,with,commas'
    assert row['action'] == 's3:Action"WithQuotes"'
    assert row['resource'] == 'arn:aws:s3:::bucket/with/commas,and"quotes"'
    assert row['risk'] == 'high,risk'