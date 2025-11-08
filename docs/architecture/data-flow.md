# CloudGuardStack Data Flow

## Overview
This document outlines the data flow within CloudGuardStack, detailing how information moves between components and security controls are enforced.

```mermaid
sequenceDiagram
    participant User
    participant CI as CI/CD Pipeline
    participant Scanner as IAM Scanner
    participant Auditor as Storage Auditor
    participant DB as Findings DB
    participant Policy as Policy Engine
    participant Remediate as Remediation
    
    User->>+CI: Triggers deployment/scan
    CI->>+Scanner: Initiate IAM scan
    CI->>+Auditor: Initiate storage audit
    
    Scanner->>Scanner: Collect IAM data
    Auditor->>Auditor: Collect storage configs
    
    Scanner->>+DB: Store IAM findings
    Auditor->>+DB: Store storage findings
    
    Policy->>+DB: Query findings
    DB-->>-Policy: Return results
    
    Policy->>Policy: Evaluate against policies
    
    alt Requires remediation
        Policy->>+Remediate: Trigger fix
        Remediate->>Remediate: Apply fixes
        Remediate-->>-Policy: Confirm resolution
    else Manual review needed
        Policy->>User: Create ticket
    end
    
    CI-->>-User: Report status
```
## Data Flow Details

### 1. Scan Initialization
- **Trigger**: Code push, schedule, or manual trigger
- **Authentication**: Cloud provider credentials via secure secrets
- **Scope Definition**: Target accounts, regions, resource types

### 2. Data Collection

#### IAM Data Collection
```mermaid
flowchart LR
    A[Cloud Provider APIs] --> B[IAM Scanner]
    B --> C[Permission Matrix]
    C --> D[Entitlement Analysis]
    D --> E[Risk Scoring]
```
#### Storage Data Collection
```mermaid
flowchart LR
    A[Cloud Storage APIs] --> B[Storage Auditor]
    B --> C[Access Analysis]
    C --> D[Public Expose Check]
    D --> E[Compliance Check]