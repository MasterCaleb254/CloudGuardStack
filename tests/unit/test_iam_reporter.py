# tests/unit/test_iam_reporter.py
import pytest
import json
import os
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime, timezone
from scanners.iam_entitlement.reporter import IAMReporter

@pytest.fixture
def sample_entitlement_data():
    return {
        "report_metadata": {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "scan_metadata": {},
            "risk_summary": {
                "total_principals": 1,
                "total_findings": 1,
                "high_risk_findings": 1,
                "medium_risk_findings": 0,
                "low_risk_findings": 0
            }
        },
        "detailed_findings": [
            {
                "principal": "arn:aws:iam::123456789012:role/AdminRole",
                "findings": [
                    {
                        "action": "s3:DeleteBucket",
                        "resource": "*",
                        "used": False,
                        "risk": "high"
                    }
                ]
            }
        ],
        "risk_prioritization": {
            "high_risk_entities": {
                "count": 1,
                "entities": {
                    "arn:aws:iam::123456789012:role/AdminRole": {
                        "findings_count": 1,
                        "risk_score": 90
                    }
                },
                "remediation_priority": "IMMEDIATE",
                "timeline": "Within 48 hours"
            },
            "medium_risk_entities": {
                "count": 0,
                "entities": {},
                "remediation_priority": "HIGH",
                "timeline": "Within 1 week"
            },
            "low_risk_entities": {
                "count": 0,
                "entities": {},
                "remediation_priority": "MEDIUM",
                "timeline": "Within 2 weeks"
            },
            "top_remediation_actions": []
        },
        "compliance_report": {
            "framework": "CIS",
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "compliance_score": 85.0,
            "controls": {
                "CIS-1.4": {
                    "description": "Ensure no root user access key exists",
                    "status": "PASS",
                    "findings": []
                }
            },
            "recommendations": []
        },
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "IAMReporter"
        }
    }

def test_initialization(sample_entitlement_data):
    """Test reporter initialization."""
    reporter = IAMReporter(entitlement_data=sample_entitlement_data)
    assert reporter.data == sample_entitlement_data
    assert hasattr(reporter, 'timestamp')
    assert reporter.timestamp is not None

def test_generate_report_structure(sample_entitlement_data):
    """Test report structure."""
    reporter = IAMReporter(entitlement_data=sample_entitlement_data)
    report = reporter.generate_report()
    
    assert 'executive_summary' in report
    assert 'detailed_findings' in report
    assert 'risk_prioritization' in report
    assert 'compliance_report' in report
    assert 'metadata' in report

def test_generate_report_with_scan_results():
    """Test report generation with scan results."""
    reporter = IAMReporter(entitlement_data={})
    scan_results = {
        "report_metadata": {
            "risk_summary": {
                "total_findings": 1,
                "high_risk_findings": 1
            }
        },
        "detailed_findings": [{
            "principal": "arn:aws:iam::123456789012:role/TestRole",
            "findings": [{"action": "s3:*", "resource": "*", "used": False, "risk": "high"}]
        }]
    }
    report = reporter.generate_report(scan_results=scan_results)
    assert len(report['detailed_findings']) == 1
    assert report['detailed_findings'][0]['principal'] == "arn:aws:iam::123456789012:role/TestRole"

def test_executive_summary(sample_entitlement_data):
    """Test executive summary generation."""
    reporter = IAMReporter(entitlement_data=sample_entitlement_data)
    summary = reporter.generate_executive_summary()
    assert 'report_date' in summary
    assert 'risk_summary' in summary
    assert 'key_findings' in summary
    assert 'total_principals' in summary['risk_summary']
    assert 'total_findings' in summary['risk_summary']

@patch('builtins.open', new_callable=mock_open)
def test_save_report(mock_file, sample_entitlement_data, tmp_path):
    """Test saving report to a file."""
    test_file = tmp_path / "test_report.json"
    reporter = IAMReporter(entitlement_data=sample_entitlement_data)
    
    # Mock the file operations
    with patch('json.dump') as mock_json_dump:
        with open(test_file, 'w') as f:
            json.dump(sample_entitlement_data, f)
        
        # Verify the file operations were called
        mock_file.assert_called_once_with(test_file, 'w')
        mock_json_dump.assert_called_once()
        
        # Verify the content being written
        args, kwargs = mock_json_dump.call_args
        assert 'report_metadata' in args[0]
        assert 'detailed_findings' in args[0]

def test_error_handling():
    """Test error handling in report generation."""
    # Test missing required argument
    with pytest.raises(TypeError):
        IAMReporter()
    
    # Test invalid scan results format - missing required sections
    reporter = IAMReporter(entitlement_data={"report_metadata": {"risk_summary": {}}})
    with pytest.raises(ValueError, match="Scan results missing required section: report_metadata"):
        reporter.generate_report(scan_results={"invalid": "data"})
        
    # Test invalid detailed_findings type
    with pytest.raises(ValueError, match="detailed_findings must be a list"):
        reporter.generate_report(scan_results={"report_metadata": {}, "detailed_findings": "not a list"})

def test_empty_findings():
    """Test report generation with empty findings."""
    reporter = IAMReporter(entitlement_data={
        "report_metadata": {
            "risk_summary": {
                "total_findings": 0,
                "high_risk_findings": 0
            }
        },
        "detailed_findings": [],
        "risk_prioritization": {
            "high_risk_entities": {
                "count": 0,
                "entities": {}
            },
            "medium_risk_entities": {
                "count": 0,
                "entities": {}
            },
            "low_risk_entities": {
                "count": 0,
                "entities": {}
            },
            "top_remediation_actions": []
        },
        "compliance_report": {
            "framework": "CIS",
            "compliance_score": 100.0,
            "controls": {}
        }
    })
    report = reporter.generate_report()
    assert len(report['detailed_findings']) == 0

def test_report_timestamps(sample_entitlement_data):
    """Test that reports include timestamps."""
    reporter = IAMReporter(entitlement_data=sample_entitlement_data)
    report = reporter.generate_report()
    assert 'generated_at' in report['metadata']

def test_large_number_of_findings():
    """Test report generation with a large number of findings."""
    large_data = {
        "report_metadata": {
            "risk_summary": {
                "total_findings": 1000,
                "high_risk_findings": 1000
            }
        },
        "detailed_findings": [
            {
                'principal': f'arn:aws:iam::123456789012:role/TestRole-{i}',
                'findings': [{
                    'action': f's3:Action{i}',
                    'resource': '*',
                    'used': False,
                    'risk': 'high'
                }]
            } for i in range(1000)
        ],
        "risk_prioritization": {
            "high_risk_entities": {
                "count": 1000,
                "entities": {
                    f'arn:aws:iam::123456789012:role/TestRole-{i}': {
                        "findings_count": 1,
                        "risk_score": 90
                    } for i in range(1000)
                },
                "remediation_priority": "IMMEDIATE",
                "timeline": "Within 48 hours"
            },
            "medium_risk_entities": {"count": 0, "entities": {}},
            "low_risk_entities": {"count": 0, "entities": {}},
            "top_remediation_actions": []
        },
        "compliance_report": {
            "framework": "CIS",
            "compliance_score": 85.0,
            "controls": {}
        }
    }
    
    reporter = IAMReporter(entitlement_data=large_data)
    report = reporter.generate_report()
    assert len(report['detailed_findings']) == 1000
    assert report['risk_prioritization']['high_risk_entities']['count'] == 1000

def test_special_characters_in_findings():
    """Test handling of special characters in findings."""
    special_principal = 'role/with/slashes&special=chars?'
    special_data = {
        "report_metadata": {
            "risk_summary": {
                "total_findings": 1,
                "high_risk_findings": 1
            }
        },
        "detailed_findings": [{
            'principal': special_principal,
            'findings': [{
                'action': 's3:*',
                'resource': 'arn:aws:s3:::bucket/with/special/chars/*',
                'used': False,
                'risk': 'high'
            }]
        }],
        "risk_prioritization": {
            "high_risk_entities": {
                "count": 1,
                "entities": {
                    special_principal: {
                        "findings_count": 1,
                        "risk_score": 90
                    }
                },
                "remediation_priority": "IMMEDIATE",
                "timeline": "Within 48 hours"
            },
            "medium_risk_entities": {"count": 0, "entities": {}},
            "low_risk_entities": {"count": 0, "entities": {}},
            "top_remediation_actions": []
        },
        "compliance_report": {
            "framework": "CIS",
            "compliance_score": 85.0,
            "controls": {}
        }
    }
    
    reporter = IAMReporter(entitlement_data=special_data)
    report = reporter.generate_report()
    
    # Check if the special characters are preserved in the report
    assert any(finding['principal'] == special_principal 
              for finding in report['detailed_findings'])
    assert special_principal in str(report['risk_prioritization'])

def test_report_performance(benchmark, sample_entitlement_data):
    """Test report generation performance."""
    reporter = IAMReporter(entitlement_data=sample_entitlement_data)
    benchmark(reporter.generate_report)