# tests/unit/test_iam_visualizer.py
import pytest
import json
from unittest.mock import patch, mock_open
from scanners.iam_entitlement.visualizer import IAMVisualizer

@pytest.fixture
def sample_findings():
    return {
        'high_risk': [
            {
                'principal': 'arn:aws:iam::123456789012:role/AdminRole',
                'findings': [
                    {
                        'action': 's3:DeleteBucket',
                        'resource': '*',
                        'used': False,
                        'risk': 'high'
                    }
                ]
            }
        ],
        'medium_risk': [],
        'low_risk': []
    }

def test_initialization():
    """Test visualizer initialization with different formats."""
    # Test default initialization
    viz = IAMVisualizer()
    assert viz.output_format == 'console'
    assert viz.output_file is None
    
    # Test with custom format and file
    viz = IAMVisualizer(output_format='graphviz', output_file='output.dot')
    assert viz.output_format == 'graphviz'
    assert viz.output_file == 'output.dot'

def test_generate_graphviz(sample_findings):
    """Test Graphviz output generation."""
    viz = IAMVisualizer(output_format='graphviz')
    dot_output = viz.generate_visualization(sample_findings)
    
    # Basic Graphviz structure checks
    assert 'digraph' in dot_output
    assert 'AdminRole' in dot_output
    assert 's3:DeleteBucket' in dot_output
    assert '->' in dot_output  # Should contain edges

def test_generate_json(sample_findings):
    """Test JSON output generation."""
    viz = IAMVisualizer(output_format='json')
    json_output = viz.generate_visualization(sample_findings)
    
    # Verify valid JSON
    data = json.loads(json_output)
    assert 'high_risk' in data
    assert len(data['high_risk']) == 1
    assert data['high_risk'][0]['principal'] == 'arn:aws:iam::123456789012:role/AdminRole'

def test_generate_console_output(sample_findings):
    """Test console output generation."""
    viz = IAMVisualizer(output_format='console')
    console_output = viz.generate_visualization(sample_findings)
    
    # Check for expected output in console
    assert 'High Risk Findings' in console_output
    assert 'AdminRole' in console_output
    assert 's3:DeleteBucket' in console_output

@patch('builtins.open', new_callable=mock_open)
def test_save_visualization(mock_file, sample_findings, tmp_path):
    """Test saving visualization to a file."""
    test_file = tmp_path / "test_output.dot"
    viz = IAMVisualizer(output_format='graphviz', output_file=str(test_file))
    viz.generate_visualization(sample_findings)
    
    # Verify file was opened for writing
    mock_file.assert_called_once_with(str(test_file), 'w')
    
    # Get the content that would be written to the file
    written_content = ''.join(call[0][0] for call in mock_file().write.call_args_list)
    assert 'digraph' in written_content
    assert 'AdminRole' in written_content

def test_empty_findings():
    """Test visualization with empty findings."""
    viz = IAMVisualizer()
    for fmt in ['console', 'json', 'graphviz']:
        viz.output_format = fmt
        output = viz.generate_visualization({'high_risk': [], 'medium_risk': [], 'low_risk': []})
        if fmt == 'json':
            data = json.loads(output)
            assert len(data['high_risk']) == 0
        else:
            assert 'No findings' in output or 'digraph' in output

def test_invalid_format(sample_findings):
    """Test handling of invalid output format."""
    viz = IAMVisualizer(output_format='invalid_format')
    with pytest.raises(ValueError):
        viz.generate_visualization(sample_findings)

def test_visualization_with_complex_findings():
    """Test visualization with complex findings structure."""
    complex_findings = {
        'high_risk': [
            {
                'principal': 'arn:aws:iam::123456789012:role/AdminRole',
                'findings': [
                    {
                        'action': 's3:*',
                        'resource': '*',
                        'used': True,
                        'risk': 'high',
                        'context': {'source': 'inline_policy'}
                    }
                ],
                'trust_relationship': {
                    'Principal': {'Service': 'ec2.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }
            }
        ],
        'medium_risk': [],
        'low_risk': [
            {
                'principal': 'arn:aws:iam::123456789012:user/ReadOnlyUser',
                'findings': [
                    {
                        'action': 's3:Get*',
                        'resource': 'arn:aws:s3:::secure-bucket/*',
                        'used': True,
                        'risk': 'low'
                    }
                ]
            }
        ]
    }
    
    # Test all formats
    for fmt in ['console', 'json', 'graphviz']:
        viz = IAMVisualizer(output_format=fmt)
        output = viz.generate_visualization(complex_findings)
        
        if fmt == 'json':
            data = json.loads(output)
            assert len(data['high_risk']) == 1
            assert len(data['low_risk']) == 1
        elif fmt == 'graphviz':
            assert 'digraph' in output
            assert 'AdminRole' in output
            assert 'ReadOnlyUser' in output
        else:  # console
            assert 'High Risk' in output
            assert 'Low Risk' in output
            assert 'AdminRole' in output
            assert 'ReadOnlyUser' in output


# Add these to the same test file

def test_special_characters_in_output():
    """Test handling of special characters in visualization."""
    findings = {
        'high_risk': [{
            'principal': 'role/with/special&chars?',
            'findings': [{
                'action': 's3:*',
                'resource': 'arn:aws:s3:::bucket/with/special/*',
                'used': True
            }]
        }]
    }
    
    viz = IAMVisualizer()
    for fmt in ['console', 'json', 'graphviz']:
        viz.output_format = fmt
        output = viz.generate_visualization(findings)
        assert 'role/with/special&chars?' in output

def test_large_findings_performance(benchmark, sample_findings):
    """Test performance with large findings sets."""
    # Create a large set of findings
    large_findings = {
        'high_risk': [
            {
                'principal': f'role-{i}',
                'findings': [
                    {
                        'action': f's3:Action{i}',
                        'resource': '*',
                        'used': i % 2 == 0,
                        'risk': 'high'
                    }
                    for _ in range(10)  # 10 findings per role
                ]
            }
            for i in range(100)  # 100 high risk roles
        ],
        'medium_risk': [],
        'low_risk': []
    }
    
    viz = IAMVisualizer(output_format='graphviz')
    benchmark(viz.generate_visualization, large_findings)

def test_error_handling():
    """Test error handling in visualization generation."""
    viz = IAMVisualizer()
    
    # Test with invalid findings format
    with pytest.raises((TypeError, KeyError)):
        viz.generate_visualization(None)
    
    with pytest.raises(KeyError):
        viz.generate_visualization({'invalid': 'data'})
    
    # Test with invalid output file
    viz = IAMVisualizer(output_file='/invalid/path/output.dot')
    with patch('builtins.open', side_effect=IOError("Permission denied")):
        with pytest.raises(IOError):
            viz.generate_visualization({'high_risk': [], 'medium_risk': [], 'low_risk': []})
