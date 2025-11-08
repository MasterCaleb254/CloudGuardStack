package kubernetes

# Deny privileged containers
deny[msg] {
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Privileged container is not allowed: %v", [container.name])
}

# Require resource limits
deny[msg] {
    container := input.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container is missing resource limits: %v", [container.name])
}

# Prevent root user
deny[msg] {
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf("Container must not run as root (UID 0): %v", [container.name])
}

# Require read-only root filesystem
deny[msg] {
    container := input.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("Container must have read-only root filesystem: %v", [container.name])
}

# Prevent hostPath volumes
deny[msg] {
    volume := input.spec.volumes[_]
    volume.hostPath
    msg := sprintf("HostPath volumes are not allowed: %v", [volume.name])
}