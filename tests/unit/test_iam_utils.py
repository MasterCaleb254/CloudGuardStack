# tests/unit/test_iam_utils.py
import pytest
from datetime import datetime, timedelta
from scanners.iam_entitlement.utils import IAMUtils
from scanners.iam_entitlement.utils import (
    normalize_action,
    is_high_risk_action,
    get_actions_from_statement,
    expand_action_wildcards,
    get_principal_type,
    is_risky_principal,
    get_used_actions
)

# Test data
SAMPLE_EVENTS = [
    {
        'eventTime': (datetime.utcnow() - timedelta(days=1)).isoformat(),
        'eventSource': 's3.amazonaws.com',
        'eventName': 'GetObject',
        'sourceIPAddress': '192.0.2.1',
        'userIdentity': {
            'type': 'IAMUser',
            'principalId': 'test-user',
            'arn': 'arn:aws:iam::123456789012:user/test-user'
        }
    }
]

def test_normalize_action():
    """Test action name normalization."""
    assert normalize_action('s3:GetObject') == 's3:getobject'
    assert normalize_action('S3:PutObject') == 's3:putobject'
    assert normalize_action('ec2:Describe*') == 'ec2:describe*'
    assert normalize_action('*') == '*'

def test_is_high_risk_action():
    """Test high-risk action detection."""
    assert is_high_risk_action('iam:CreateUser') is True
    assert is_high_risk_action('s3:GetObject') is False
    assert is_high_risk_action('ec2:TerminateInstances') is True
    assert is_high_risk_action('lambda:UpdateFunctionCode') is True

def test_get_actions_from_statement():
    """Test action extraction from policy statements."""
    # Test single action
    statement = {'Effect': 'Allow', 'Action': 's3:GetObject'}
    assert get_actions_from_statement(statement) == ['s3:GetObject']
    
    # Test array of actions
    statement = {'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:PutObject']}
    assert set(get_actions_from_statement(statement)) == {'s3:GetObject', 's3:PutObject'}
    
    # Test NotAction
    statement = {'Effect': 'Allow', 'NotAction': 's3:Delete*'}
    assert get_actions_from_statement(statement) == ['s3:Delete*']
    
    # Test empty statement
    assert get_actions_from_statement({}) == []

def test_expand_action_wildcards():
    """Test wildcard expansion in action names."""
    actions = ['s3:Get*', 'ec2:Describe*']
    service_prefix = 's3'
    assert expand_action_wildcards(actions, service_prefix) == ['s3:Get*']
    
    # Test with multiple matches
    actions = ['s3:*', 'ec2:*']
    assert set(expand_action_wildcards(actions, 's3')) == {'s3:*'}

def test_get_principal_type():
    """Test principal type detection."""
    assert get_principal_type('arn:aws:iam::123456789012:user/test') == 'AWS'
    assert get_principal_type({'Service': 'ec2.amazonaws.com'}) == 'Service'
    assert get_principal_type('*') == 'Wildcard'
    assert get_principal_type({'AWS': '123456789012'}) == 'AWS'
    assert get_principal_type({'Federated': 'cognito-identity.amazonaws.com'}) == 'Federated'

def test_is_risky_principal():
    """Test risky principal detection."""
    assert is_risky_principal('*') is True
    assert is_risky_principal('arn:aws:iam::*:root') is True
    assert is_risky_principal('arn:aws:iam::123456789012:role/Admin') is False
    assert is_risky_principal({'AWS': '*'}) is True
    assert is_risky_principal({'Service': 'ec2.amazonaws.com'}) is False

def test_get_used_actions():
    """Test extraction of used actions from CloudTrail events."""
    events = SAMPLE_EVENTS
    used_actions = get_used_actions(events)
    
    assert len(used_actions) == 1
    assert 's3:GetObject' in used_actions
    assert all(isinstance(action, str) for action in used_actions)

# Additional test cases for edge cases
def test_empty_events():
    """Test with empty events list."""
    assert get_used_actions([]) == set()

def test_malformed_events():
    """Test with malformed event data."""
    events = [{'invalid': 'data'}, None, 123]
    assert get_used_actions(events) == set()

def test_normalize_edge_cases():
    """Test edge cases in action name normalization."""
    assert normalize_action('') == ''
    assert normalize_action(None) is None
    assert normalize_action(123) == '123'
    assert normalize_action('S3:List*') == 's3:list*'

def test_is_high_risk_edge_cases():
    """Test edge cases in high-risk action detection."""
    assert is_high_risk_action('') is False
    assert is_high_risk_action(None) is False
    assert is_high_risk_action(123) is False

def test_get_actions_edge_cases():
    """Test edge cases in action extraction."""
    assert get_actions_from_statement(None) == []
    assert get_actions_from_statement({'Effect': 'Deny'}) == []
    assert get_actions_from_statement({'Action': None}) == []

def test_principal_type_edge_cases():
    """Test edge cases in principal type detection."""
    assert get_principal_type('') == 'Unknown'
    assert get_principal_type(None) == 'Unknown'
    assert get_principal_type(123) == 'Unknown'
    assert get_principal_type({}) == 'Unknown'
    assert get_principal_type({'Unknown': 'value'}) == 'Unknown'

def test_risky_principal_edge_cases():
    """Test edge cases in risky principal detection."""
    assert is_risky_principal('') is False
    assert is_risky_principal(None) is False
    assert is_risky_principal(123) is False
    assert is_risky_principal({}) is False
    assert is_risky_principal({'Invalid': '*'}) is False

def test_expand_wildcards_edge_cases():
    """Test edge cases in wildcard expansion."""
    assert expand_action_wildcards([], 's3') == []
    assert expand_action_wildcards(None, 's3') == []
    assert expand_action_wildcards(['*'], '') == ['*']
    assert expand_action_wildcards(['invalid'], 's3') == []