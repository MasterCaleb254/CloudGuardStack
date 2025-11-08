# tests/unit/test_apply_remediation_plan.py
import pytest
from unittest.mock import patch, MagicMock
from scanners.storage_auditor.remediation import apply_remediation_plan

def test_apply_remediation_plan_success():
    """Test successful application of a remediation plan."""
    mock_remediator = MagicMock()
    mock_remediator.remediate_public_s3_bucket.return_value = {'success': True}
    
    plan = {
        'phases': {
            'immediate': {
                'actions': [{
                    'action': 'remediate_public_bucket',
                    'resource': 'test-bucket',
                    'description': 'Test action'
                }]
            }
        }
    }
    
    with patch('scanners.storage_auditor.remediation.StorageRemediation', 
              return_value=mock_remediator):
        results = apply_remediation_plan(plan)
        
    assert results['total_actions'] == 1
    assert results['completed_actions'] == 1
    assert results['failed_actions'] == 0

def test_apply_remediation_plan_failure():
    """Test handling of failed remediation actions."""
    mock_remediator = MagicMock()
    mock_remediator.remediate_public_s3_bucket.return_value = {
        'success': False,
        'error': 'Test error'
    }
    
    plan = {
        'phases': {
            'immediate': {
                'actions': [{
                    'action': 'remediate_public_bucket',
                    'resource': 'test-bucket',
                    'description': 'Test action'
                }]
            }
        }
    }
    
    with patch('scanners.storage_auditor.remediation.StorageRemediation', 
              return_value=mock_remediator):
        results = apply_remediation_plan(plan)
        
    assert results['total_actions'] == 1
    assert results['completed_actions'] == 1
    assert results['failed_actions'] == 1
    assert 'Test error' in str(results['action_results'])