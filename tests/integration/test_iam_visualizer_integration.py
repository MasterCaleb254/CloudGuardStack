# tests/integration/test_iam_visualizer_integration.py
import pytest
import os
import json
import networkx as nx
from pathlib import Path
from unittest.mock import patch, MagicMock
from scanners.iam_entitlement.visualizer import IAMVisualizer

# Sample test data
SAMPLE_FINDINGS = {
    "findings": [
        {
            "id": "finding-1",
            "severity": "high",
            "resource_arn": "arn:aws:iam::123456789012:role/TestRole",
            "resource_type": "AWS::IAM::Role",
            "finding_type": "excessive_permissions",
            "details": {
                "policy_arn": "arn:aws:iam::123456789012:policy/TestPolicy",
                "actions": ["s3:*", "ec2:*"],
                "resources": ["*"]
            }
        }
    ],
    "summary": {
        "total_findings": 1,
        "severity_counts": {"high": 1, "medium": 0, "low": 0},
        "resource_type_counts": {"AWS::IAM::Role": 1}
    }
}

@pytest.fixture
def visualizer(tmp_path):
    """Create an IAMVisualizer instance with a temporary output directory."""
    return IAMVisualizer(output_dir=str(tmp_path))

def test_generate_visualization(visualizer, tmp_path):
    """Test generating a visualization from findings."""
    # Test generating visualization
    output_file = visualizer.generate_visualization(SAMPLE_FINDINGS)
    
    # Verify output file was created
    assert os.path.exists(output_file)
    assert output_file.endswith('.html')
    
    # Verify the file contains expected content
    with open(output_file, 'r') as f:
        content = f.read()
        assert 'IAM Entitlements Visualization' in content
        assert 'TestRole' in content

def test_generate_interactive_graph(visualizer):
    """Test generating an interactive graph from findings."""
    # Generate the graph
    graph = visualizer._generate_interactive_graph(SAMPLE_FINDINGS)
    
    # Verify the graph structure
    assert isinstance(graph, nx.DiGraph)
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0
    
    # Verify the graph contains expected nodes
    node_labels = [data.get('label', '') for _, data in graph.nodes(data=True)]
    assert any('TestRole' in label for label in node_labels)

def test_save_visualization(visualizer, tmp_path):
    """Test saving the visualization to a file."""
    # Create a sample graph
    graph = nx.DiGraph()
    graph.add_node("test_node", label="Test Node", type="test")
    
    # Test saving the visualization
    output_file = str(tmp_path / "test_visualization.html")
    visualizer._save_visualization(graph, output_file)
    
    # Verify the file was created
    assert os.path.exists(output_file)
    
    # Verify the file contains expected content
    with open(output_file, 'r') as f:
        content = f.read()
        assert 'Test Node' in content
        assert 'vis-network.min.css' in content

def test_generate_visualization_with_empty_findings(visualizer):
    """Test visualization with empty findings."""
    empty_findings = {"findings": [], "summary": {"total_findings": 0}}
    
    # Should not raise an exception
    output_file = visualizer.generate_visualization(empty_findings)
    
    # Should still create a file
    assert os.path.exists(output_file)
    with open(output_file, 'r') as f:
        content = f.read()
        assert 'No IAM entities found' in content

def test_generate_visualization_with_large_dataset(visualizer):
    """Test visualization with a large dataset."""
    # Create a large dataset
    large_findings = {
        "findings": [
            {
                "id": f"finding-{i}",
                "severity": "high",
                "resource_arn": f"arn:aws:iam::123456789012:role/Role{i}",
                "resource_type": "AWS::IAM::Role",
                "finding_type": "excessive_permissions",
                "details": {
                    "policy_arn": f"arn:aws:iam::123456789012:policy/Policy{i}",
                    "actions": [f"s3:Action{i}"],
                    "resources": [f"arn:aws:s3:::bucket-{i}/*"]
                }
            } for i in range(100)  # 100 findings
        ],
        "summary": {
            "total_findings": 100,
            "severity_counts": {"high": 100, "medium": 0, "low": 0},
            "resource_type_counts": {"AWS::IAM::Role": 100}
        }
    }
    
    # Test generating visualization
    output_file = visualizer.generate_visualization(large_findings)
    assert os.path.exists(output_file)
    
    # Verify the file size is reasonable
    assert os.path.getsize(output_file) > 10000  # At least 10KB

def test_custom_output_directory(visualizer, tmp_path):
    """Test visualization with custom output directory."""
    custom_dir = tmp_path / "custom_output"
    visualizer.output_dir = str(custom_dir)
    
    # Generate visualization
    output_file = visualizer.generate_visualization(SAMPLE_FINDINGS)
    
    # Verify the file was created in the custom directory
    assert str(custom_dir) in output_file
    assert os.path.exists(output_file)

def test_visualization_content(visualizer):
    """Test the content of the generated visualization."""
    # Generate the visualization
    output_file = visualizer.generate_visualization(SAMPLE_FINDINGS)
    
    # Verify the file contains expected content
    with open(output_file, 'r') as f:
        content = f.read()
        
        # Check for required JavaScript libraries
        assert 'vis-network.min.js' in content
        assert 'd3.v7.min.js' in content
        
        # Check for the graph container
        assert '<div id="network"' in content
        
        # Check for the findings data
        assert 'TestRole' in content
        assert 'excessive_permissions' in content

def test_graph_generation(visualizer):
    """Test the graph generation logic."""
    # Generate the graph
    graph = visualizer._generate_interactive_graph(SAMPLE_FINDINGS)
    
    # Verify the graph structure
    assert len(graph.nodes) >= 2  # At least the role and policy nodes
    assert len(graph.edges) >= 1  # At least one edge
    
    # Verify node properties
    for node_id, node_data in graph.nodes(data=True):
        assert 'label' in node_data
        assert 'type' in node_data
        assert 'color' in node_data
        
        # Verify node types
        if node_data['type'] == 'role':
            assert 'TestRole' in node_data['label']
        elif node_data['type'] == 'policy':
            assert 'TestPolicy' in node_data['label']

def test_error_handling(visualizer, caplog):
    """Test error handling in the visualizer."""
    # Test with invalid findings
    invalid_findings = {"invalid": "data"}
    output_file = visualizer.generate_visualization(invalid_findings)
    
    # Should still return a file path
    assert output_file is not None
    assert "Error generating visualization" in caplog.text

def test_visualization_with_different_severities(visualizer):
    """Test visualization with findings of different severities."""
    findings = {
        "findings": [
            {
                "id": "high-severity",
                "severity": "high",
                "resource_arn": "arn:aws:iam::123456789012:role/HighRiskRole",
                "resource_type": "AWS::IAM::Role",
                "finding_type": "excessive_permissions"
            },
            {
                "id": "medium-severity",
                "severity": "medium",
                "resource_arn": "arn:aws:iam::123456789012:role/MediumRiskRole",
                "resource_type": "AWS::IAM::Role",
                "finding_type": "unused_permissions"
            },
            {
                "id": "low-severity",
                "severity": "low",
                "resource_arn": "arn:aws:iam::123456789012:role/LowRiskRole",
                "resource_type": "AWS::IAM::Role",
                "finding_type": "info"
            }
        ],
        "summary": {
            "total_findings": 3,
            "severity_counts": {"high": 1, "medium": 1, "low": 1},
            "resource_type_counts": {"AWS::IAM::Role": 3}
        }
    }
    
    # Generate visualization
    output_file = visualizer.generate_visualization(findings)
    assert os.path.exists(output_file)
    
    # Verify all severities are represented
    with open(output_file, 'r') as f:
        content = f.read()
        assert 'HighRiskRole' in content
        assert 'MediumRiskRole' in content
        assert 'LowRiskRole' in content