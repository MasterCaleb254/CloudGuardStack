from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check
from checkov.kubernetes.checks.resource.k8s.KubeClientConfig import KubeClientConfig

# AWS Custom Policies
class S3PublicAccessBlockCheck(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 buckets have public access block enabled"
        id = "CUSTOM_AWS_S3_001"
        supported_resources = ['aws_s3_bucket_public_access_block']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        required_blocks = ['block_public_acls', 'block_public_policy', 
                          'ignore_public_acls', 'restrict_public_buckets']
        
        for block in required_blocks:
            if conf.get(block) != [True]:
                return CheckResult.FAILED
        return CheckResult.PASSED

# Azure Custom Policies
class AzureNSGRuleSSHAccessRestricted(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SSH access is restricted from the internet"
        id = "CUSTOM_AZURE_NSG_001"
        supported_resources = ['azurerm_network_security_rule']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (conf.get('direction', [None])[0] == 'Inbound' and
            conf.get('access', [None])[0] == 'Allow' and
            conf.get('protocol', [None])[0] in ['Tcp', '*'] and
            '22' in conf.get('destination_port_range', [''])[0].split(',')):
            if conf.get('source_address_prefix', [None])[0] in ['*', '0.0.0.0/0', 'Internet']:
                return CheckResult.FAILED
        return CheckResult.PASSED

# GCP Custom Policies
class GCPComputeFirewallSSHRestricted(BaseResourceCheck):
    def __init__(self):
        name = "Ensure SSH access is restricted from the internet"
        id = "CUSTOM_GCP_COMPUTE_001"
        supported_resources = ['google_compute_firewall']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (conf.get('direction', [None])[0] == 'INGRESS' and
            '22' in conf.get('allow', [{}])[0].get('ports', [''])[0].split(',')):
            if '0.0.0.0/0' in conf.get('source_ranges', [[]])[0]:
                return CheckResult.FAILED
        return CheckResult.PASSED

# Kubernetes Custom Policies
class K8sDefaultServiceAccountCheck(BaseK8Check):
    def __init__(self):
        name = "Prevent pods from using default service account"
        id = "CUSTOM_K8S_001"
        supported_kind = ['containers', 'initContainers']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf, entity_type):
        if conf.get('name') == 'default' and not conf.get('serviceAccountName'):
            return CheckResult.FAILED
        return CheckResult.PASSED

# Register the checks
def get_checks(provider=None):
    checks = []
    
    if provider in ['aws', None]:
        checks.append(S3PublicAccessBlockCheck())
    
    if provider in ['azure', None]:
        checks.append(AzureNSGRuleSSHAccessRestricted())
    
    if provider in ['gcp', None]:
        checks.append(GCPComputeFirewallSSHRestricted())
    
    if provider in ['kubernetes', None]:
        checks.append(K8sDefaultServiceAccountCheck())
    
    return checks