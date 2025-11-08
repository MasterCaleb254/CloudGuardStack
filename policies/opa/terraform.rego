package terraform

# Enforce tagging
deny[msg] {
    resource := input.resource_changes[_]
    not resource.change.after.tags
    msg := sprintf("Resource is missing required tags: %s", [resource.address])
}

# Prevent public IPs on instances
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    resource.change.after.associate_public_ip_address == true
    msg := sprintf("EC2 instance should not have a public IP: %s", [resource.address])
}

# Enforce secure SSH access
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"
    resource.change.after.from_port == 22
    resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
    msg = "SSH access should not be open to the world (0.0.0.0/0)"
}

# Require logging for CloudTrail
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.after.enable_log_file_validation != true
    msg = "CloudTrail must have log file validation enabled"
}