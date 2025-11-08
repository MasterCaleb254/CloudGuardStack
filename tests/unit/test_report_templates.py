# tests/unit/test_report_templates.py
import pytest
import os
import json
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock
from scanners.reports.templates import ReportTemplates

@pytest.fixture
def mock_template_dir(tmp_path):
    """Create a temporary directory with test templates."""
    templates = {
        'test_template.j2': 'Test Template\nFindings: {{ findings|tojson }}',
        'html_report.j2': '<html><body>{{ findings|tojson }}</body></html>',
        'text_report.j2': 'Text Report\n{{ findings|tojson }}'
    }
    
    template_dir = tmp_path / 'templates'
    template_dir.mkdir()
    
    for name, content in templates.items():
        (template_dir / name).write_text(content)
    
    return str(template_dir)

@pytest.fixture
def sample_findings():
    return {
        'high': [{'id': '1', 'title': 'Critical Issue'}],
        'medium': [{'id': '2', 'title': 'Moderate Issue'}],
        'low': []
    }

def test_initialization_default_templates():
    """Test initialization with default template directory."""
    with patch('scanners.reports.templates.os.path') as mock_path:
        mock_path.join.side_effect = lambda *args: '/'.join(args)
        mock_path.dirname.return_value = '/base'
        templates = ReportTemplates()
        
    assert templates.template_dir == '/base/templates/reports'
    assert isinstance(templates.env.loader.searchpath[0], str)

def test_initialization_custom_dir(mock_template_dir):
    """Test initialization with custom template directory."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    assert templates.template_dir == mock_template_dir
    assert 'test_template' in templates.templates

def test_load_templates(mock_template_dir):
    """Test loading of templates from directory."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    assert len(templates.templates) == 3
    assert 'test_template' in templates.templates
    assert 'html_report' in templates.templates
    assert 'text_report' in templates.templates

def test_get_template(mock_template_dir):
    """Test getting a template by name."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    template = templates.get_template('test_template')
    assert template is not None
    assert template.name == 'test_template.j2'

def test_get_template_not_found(mock_template_dir):
    """Test getting a non-existent template."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    with pytest.raises(ValueError, match="Template 'missing' not found"):
        templates.get_template('missing')

def test_render_template(mock_template_dir, sample_findings):
    """Test rendering a template with context."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    result = templates.render_template(
        'test_template',
        {'findings': sample_findings}
    )
    
    assert 'Test Template' in result
    assert '"high"' in result
    assert 'Critical Issue' in result

def test_generate_report(mock_template_dir, sample_findings, tmp_path):
    """Test generating a report with metadata."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    output_file = tmp_path / 'report.html'
    
    with patch.object(templates, 'save_report') as mock_save:
        result = templates.generate_report(
            findings=sample_findings,
            template_name='html_report',
            output_format='html',
            output_file=str(output_file),
            title='Test Report'
        )
    
    assert '<html>' in result
    assert 'Test Report' in result
    mock_save.assert_called_once()

def test_save_report(tmp_path):
    """Test saving a report to a file."""
    content = "Test report content"
    file_path = tmp_path / 'reports' / 'test_report.txt'
    
    # Test successful save
    ReportTemplates.save_report(content, str(file_path))
    assert file_path.exists()
    assert file_path.read_text() == content
    
    # Test directory creation
    assert file_path.parent.exists()
    
    # Test error handling
    with patch('builtins.open', side_effect=OSError("Permission denied")):
        with pytest.raises(IOError, match="Failed to save report"):
            ReportTemplates.save_report(content, '/invalid/path/report.txt')

def test_list_available_templates(mock_template_dir):
    """Test listing available templates."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    available = templates.list_available_templates()
    
    assert len(available) == 3
    assert 'test_template' in available
    assert 'html_report' in available
    assert 'text_report' in available

def test_template_autoescape(mock_template_dir):
    """Test that autoescaping works for HTML templates."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    # Create a template with potentially unsafe content
    unsafe_content = {
        'title': '<script>alert("xss")</script>',
        'content': 'Safe <b>content</b>'
    }
    
    # Test with HTML template (should escape)
    result = templates.render_template('html_report', {'findings': unsafe_content})
    assert '&lt;script&gt;' in result
    assert '&lt;b&gt;content&lt;/b&gt;' in result
    
    # Test with text template (should not escape)
    result = templates.render_template('text_report', {'findings': unsafe_content})
    assert '<script>' in result
    assert '<b>content</b>' in result

def test_template_filters(mock_template_dir):
    """Test that template filters are available."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    # Create a test template that uses filters
    test_content = {
        'list': [1, 2, 3],
        'data': {'key': 'value'}
    }
    
    # Test with a template that uses tojson filter
    result = templates.render_template('test_template', {'findings': test_content})
    assert '"list": [1, 2, 3]' in result
    assert '"key": "value"' in result

def test_generate_report_no_output_file(mock_template_dir, sample_findings):
    """Test generating a report without saving to file."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    with patch.object(templates, 'save_report') as mock_save:
        result = templates.generate_report(
            findings=sample_findings,
            template_name='text_report',
            output_format='txt'
        )
    
    assert 'Text Report' in result
    mock_save.assert_not_called()

def test_template_with_custom_context(mock_template_dir):
    """Test template rendering with custom context variables."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    # Create a test template that uses custom variables
    test_template = mock_template_dir + '/custom_vars.j2'
    with open(test_template, 'w') as f:
        f.write('User: {{ user }}\nRole: {{ role }}')
    
    # Reload templates to include the new one
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    result = templates.render_template(
        'custom_vars',
        {'user': 'testuser'},
        role='admin'
    )
    
    assert 'User: testuser' in result
    assert 'Role: admin' in result

def test_template_inheritance(mock_template_dir):
    """Test template inheritance and includes."""
    # Create base template
    base_template = mock_template_dir + '/base.j2'
    with open(base_template, 'w') as f:
        f.write("""{% block header %}Header{% endblock %}
{% block content %}{% endblock %}
{% block footer %}Footer{% endblock %}""")

    # Create child template
    child_template = mock_template_dir + '/child.j2'
    with open(child_template, 'w') as f:
        f.write("""{% extends "base.j2" %}
{% block content %}Child Content{% endblock %}""")
    
    templates = ReportTemplates(template_dir=mock_template_dir)
    result = templates.render_template('child', {})
    
    assert 'Header' in result
    assert 'Child Content' in result
    assert 'Footer' in result

def test_template_error_handling(mock_template_dir):
    """Test error handling during template rendering."""
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    # Create a template with syntax error
    bad_template = mock_template_dir + '/bad.j2'
    with open(bad_template, 'w') as f:
        f.write('{% if missing_var %}This will fail{% endif %}')
    
    # Reload templates
    templates = ReportTemplates(template_dir=mock_template_dir)
    
    with pytest.raises(Exception) as excinfo:
        templates.render_template('bad', {})
    assert 'missing_var' in str(excinfo.value)