# tests/unit/test_iam_remediation_generator.py
import pytest
import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from scanners.iam_entitlement.remediation_generator import RemediationGenerator, matches_action_pattern

@pytest.fixture
def generator():
    with patch('boto3.Session') as mock_session:
        mock_iam = MagicMock()
        mock_orgs = MagicMock()
        mock_session.return_value.client.side_effect = [mock_iam, mock_orgs]
        gen = RemediationGenerator()
        gen.iam = mock_iam
        gen.organizations = mock_orgs
        return gen

def test_matches_action_pattern():
    assert matches_action_pattern("s3:*", "s3:GetObject") is True
    assert matches_action_pattern("s3:Get*", "s3:GetObject") is True
    assert matches_action_pattern("s3:GetObject", "s3:GetObject") is True
    assert matches_action_pattern("s3:Put*", "s3:GetObject") is False
    assert matches_action_pattern("ec2:*", "s3:GetObject") is False

def test_generate_least_privilege_policy_basic(generator):
    current_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "ec2:*"],
                "Resource": "*"
            }
        ]
    }
    used_actions = ["s3:GetObject", "s3:ListBucket"]
    result = generator.generate_least_privilege_policy(current_policy, used_actions)

    assert result['Version'] == '2012-10-17'
    assert len(result['Statement']) == 1
    actions = result['Statement'][0]['Action']
    assert isinstance(actions, list)
    assert set(actions) == set(used_actions)
    assert result['Statement'][0]['Resource'] == '*'

def test_create_remediation_plan(generator):
    findings = [
        {
            'principal': 'test-role',
            'entity_arn': 'arn:aws:iam::123456789012:role/test-role',
            'entity_name': 'test-role',
            'entity_type': 'AWS::IAM::Role',
            'finding_type': 'over_privileged',
            'findings': [
                {'action': 's3:GetObject', 'resource': 'arn:aws:s3:::test-bucket/*', 'used': True},
                {'action': 's3:ListBucket', 'resource': 'arn:aws:s3:::test-bucket', 'used': True}
            ]
        }
    ]
    plan = generator.create_remediation_plan(findings)

    assert len(plan['remediations']) == 1
    assert plan['remediations'][0]['entity_name'] == 'test-role'
    assert len(plan['remediations'][0]['actions']) == 1
    assert plan['remediations'][0]['actions'][0]['type'] == 'update_policy'

def test_apply_remediation_plan_dry_run(generator):
    plan = {
        'remediations': [
            {
                'principal': 'test-role',
                'entity_arn': 'arn:aws:iam::123456789012:role/test-role',
                'entity_name': 'test-role',
                'policy_name': 'test-policy',
                'actions': [{'type': 'update_policy', 'status': 'pending'}]
            }
        ]
    }

    generator.iam.get_role_policy.return_value = {
        'PolicyDocument': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
    }

    results = generator.apply_remediation_plan(plan, dry_run=True)

    assert len(results) == 1
    assert results[0]['status'] == 'success'
    generator.iam.put_role_policy.assert_not_called()

def test_apply_remediation_plan_actual(generator):
    plan = {
        'remediations': [
            {
                'principal': 'test-role',
                'entity_arn': 'arn:aws:iam::123456789012:role/test-role',
                'entity_name': 'test-role',
                'policy_name': 'test-policy',
                'actions': [
                    {
                        'type': 'update_policy',
                        'status': 'pending',
                        'current_policy': {
                            'Version': '2012-10-17',
                            'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'}]
                        },
                        'used_actions': ['s3:GetObject', 's3:ListBucket']
                    }
                ]
            }
        ]
    }

    generator.iam.get_role_policy.return_value = {
        'PolicyDocument': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]}'
    }

    results = generator.apply_remediation_plan(plan, dry_run=False)

    assert len(results) == 1
    assert results[0]['status'] == 'success'

    generator.iam.put_role_policy.assert_called_once()
    args, kwargs = generator.iam.put_role_policy.call_args
    assert kwargs['RoleName'] == 'test-role'
    assert kwargs['PolicyName'] == 'test-policy'

    policy_doc = json.loads(kwargs['PolicyDocument'])
    assert policy_doc['Version'] == '2012-10-17'
    assert len(policy_doc['Statement']) == 1
    assert policy_doc['Statement'][0]['Effect'] == 'Allow'
    assert set(policy_doc['Statement'][0]['Action']) == {'s3:GetObject', 's3:ListBucket'}
    assert policy_doc['Statement'][0]['Resource'] == '*'

def test_error_handling(generator):
    with pytest.raises(ValueError):
        generator.generate_least_privilege_policy("invalid", [])

    generator.iam.put_role_policy.side_effect = Exception("API Error")
    plan = {
        'remediations': [{
            'principal': 'test-role',
            'entity_arn': 'arn:aws:iam::123456789012:role/test-role',
            'entity_name': 'test-role',
            'policy_name': 'test-policy',
            'actions': [{
                'type': 'update_policy',
                'current_policy': {
                    'Version': '2012-10-17',
                    'Statement': [{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*'}]
                },
                'used_actions': ['s3:GetObject'],
                'status': 'pending'
            }],
            'resources': []
        }]
    }

    results = generator.apply_remediation_plan(plan, dry_run=False)
    assert results[0]['status'] == 'error'
    assert 'API Error' in results[0]['error']

    with patch('builtins.print') as mock_print:
        results = generator.apply_remediation_plan(plan, dry_run=False)
    assert results[0]['status'] == 'error'
    assert 'API Error' in results[0]['message']

def test_edge_cases(generator):
    plan = generator.create_remediation_plan([])
    assert 'remediations' in plan
    assert len(plan['remediations']) == 0
    assert 'timestamp' in plan
    datetime.fromisoformat(plan['timestamp'])  # Validate timestamp format

    result = generator.generate_least_privilege_policy(
        {'Version': '2012-10-17', 'Statement': []},
        ['s3:GetObject']
    )
    assert result['Version'] == '2012-10-17'
    assert result['Statement'] == []

    current_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
            {"Effect": "Deny", "Action": ["s3:DeleteBucket"], "Resource": "*"}
        ]
    }
    result = generator.generate_least_privilege_policy(current_policy, [])
    assert len(result['Statement']) == 1
    assert result['Statement'][0]['Effect'] == 'Deny'
    assert result['Statement'][0]['Action'] == ['s3:DeleteBucket']

def test_complex_policy_processing(generator):
    complex_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "ec2:*", "iam:*"],
                "Resource": "*",
                "Condition": {
                    "IpAddress": {"aws:SourceIp": ["192.0.2.0/24"]}
                }
            },
            {
                "Effect": "Deny",
                "Action": "s3:DeleteBucket",
                "Resource": "*"
            }
        ]
    }

    used_actions = ["s3:GetObject", "s3:ListBucket"]
    result = generator.generate_least_privilege_policy(complex_policy, used_actions)

    assert len(result['Statement']) == 2
    assert result['Statement'][0]['Effect'] == 'Allow'
    actions = result['Statement'][0]['Action']
    if isinstance(actions, str):
        actions = [actions]
    assert set(actions) == set(used_actions)
    assert 'Condition' in result['Statement'][0]
    assert result['Statement'][1]['Effect'] == 'Deny'
    assert result['Statement'][1]['Action'] == 's3:DeleteBucket'