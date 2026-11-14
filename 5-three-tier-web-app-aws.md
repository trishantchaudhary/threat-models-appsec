# Threat Model 5: 3-Tier Web App on AWS

## 1. System Description
CloudFront + WAF at the edge, ALB in a public subnet, app servers (EC2/ECS) in a private subnet, RDS in an isolated data subnet. S3 for files, Secrets Manager for credentials, CloudTrail for audit logs. Admins connect through SSM Session Manager.

## 2. Assets
- Customer data in RDS and S3
- IAM roles, access keys, secrets
- Application availability
- The AWS account itself

## 3. DFD with Trust Boundaries

```mermaid
flowchart LR
  subgraph TB1["TRUST BOUNDARY 1: Internet (untrusted)"]
    U["Internet Users"]
    ADM["Admin"]
  end
  subgraph TB2["TRUST BOUNDARY 2: AWS Account (trusted)"]
    CF(("P1 CloudFront + WAF"))
    IAM(("P4 IAM / STS"))
    S3[("D2 S3 Bucket")]
    SM[("D3 Secrets Manager")]
    CT[("D4 CloudTrail + Logs")]
    subgraph TB3["TRUST BOUNDARY 3: VPC"]
      subgraph PUB["Public Subnet"]
        ALB(("P2 ALB"))
      end
      subgraph APP["Private Subnet: App Tier"]
        EC2(("P3 App Servers EC2 / ECS"))
      end
      subgraph DATA["Private Subnet: Data Tier"]
        RDS[("D1 RDS Database")]
      end
    end
  end
  U -->|"1. HTTPS"| CF
  CF -->|"2. forward"| ALB
  ALB -->|"3. forward"| EC2
  EC2 -->|"4. SQL"| RDS
  EC2 -->|"5. read / write files"| S3
  EC2 -->|"6. get secrets"| SM
  EC2 -->|"7. assume role via IMDS"| IAM
  ADM -->|"8. SSM Session Manager + MFA"| EC2
  EC2 -->|"9. audit and app logs"| CT

  classDef ext fill:#eeeeee,stroke:#555,color:#000
  classDef proc fill:#cfe8ff,stroke:#1f5f9f,color:#000
  classDef store fill:#fff2b3,stroke:#9a7d0a,color:#000
  class U,ADM ext
  class CF,IAM,ALB,EC2 proc
  class S3,SM,CT,RDS store
  style TB1 fill:#fff5f5,stroke:#d62728,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB2 fill:#f2f8ff,stroke:#1f77b4,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style TB3 fill:#f3fbf5,stroke:#2e8b57,stroke-width:2px,stroke-dasharray:6 4,color:#000
  style PUB fill:#fff9ee,stroke:#e08a00,stroke-dasharray:4 3,color:#000
  style APP fill:#f9fff9,stroke:#2e8b57,stroke-dasharray:4 3,color:#000
  style DATA fill:#f9fff9,stroke:#2e8b57,stroke-dasharray:4 3,color:#000
```

## 4. STRIDE per Element

| Element | Type | S | T | R | I | D | E | Threat |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| Internet Users | External | ✔ | | ✔ | | | | Bots, scanners, anonymous attackers |
| Admin | External | ✔ | | ✔ | | | | No MFA, phished admin, leaked access keys |
| P1 CloudFront + WAF | Process | | ✔ | | | ✔ | | WAF bypass, DDoS, cache poisoning |
| P2 ALB | Process | | ✔ | | ✔ | ✔ | | Weak TLS config, direct-to-origin bypass of WAF |
| P3 App Servers | Process | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | App vuln, SSRF to IMDSv1, vulnerable AMI / image, open SG |
| P4 IAM / STS | Process | ✔ | ✔ | ✔ | | | ✔ | Over-permissive role (`*:*`), iam:PassRole abuse, long-lived keys |
| D1 RDS | Store | | ✔ | ✔ | ✔ | ✔ | | Public snapshot, DB reachable from internet, unencrypted |
| D2 S3 Bucket | Store | | ✔ | | ✔ | ✔ | | Public bucket, no versioning, ransomware delete |
| D3 Secrets Manager | Store | | | | ✔ | | | Secrets read by over-broad role, secrets in env / user-data |
| D4 CloudTrail + Logs | Store | | ✔ | ✔ | | | | Logging disabled, logs deletable, no integrity validation |
| Flow 4 (SQL) | Flow | | ✔ | | ✔ | | | Flat network, no TLS to DB |
| Flow 8 (admin access) | Flow | ✔ | | ✔ | | | | Open SSH 22 to 0.0.0.0/0, shared bastion keys |

## 5. Attack Tree: Steal Customer Data / Take Over Account

```mermaid
flowchart TD
  G["GOAL: Steal data or take over AWS account"]:::goal
  G --> A["Exploit the app"]
  G --> B["Use leaked credentials"]
  G --> C["Find misconfiguration"]
  G --> D["Take over admin"]
  G --> E["Hide / destroy evidence"]
  A --> A1["Find SSRF or RCE in app"]
  A1 --> A2["Query IMDSv1 for role creds"]
  A2 --> A3["Use role to read S3 and RDS"]
  B --> B1["Access keys in GitHub"]
  B --> B2["Secrets in env vars / user-data"]
  C --> C1["Public S3 bucket"]
  C --> C2["Open SG: SSH or DB to internet"]
  C --> C3["Public RDS snapshot"]
  D --> D1["Phish admin, no MFA"]
  D --> D2["Over-permissive IAM escalation"]
  E --> E1["Disable CloudTrail"]
  E --> E2["Delete backups"]
  classDef goal fill:#d62728,color:#fff,stroke:#8b0000
```
*Branches are OR. The A1 to A3 chain is sequential: each step needs the one before.*

## 6. Mitigations

| Threat | Mitigation |
|---|---|
| Over-permissive IAM | Least privilege, one role per service, permission boundaries, IAM Access Analyzer, no long-lived keys |
| SSRF to IMDS | Enforce IMDSv2 (hop limit 1), fix SSRF in the app, restrict egress |
| Public S3 / snapshots | S3 Block Public Access at account level, bucket policies, SSE-KMS, Macie |
| Open security groups | SG rules by source SG, no inbound SSH (use SSM), DB only from app SG |
| Secrets in code / env | Secrets Manager / Parameter Store, secret scanning in CI, rotation |
| Admin takeover | MFA on root and all humans, SSO, SCPs, locked-away break-glass account |
| No logging | CloudTrail in all regions with log validation, GuardDuty, Config rules, alerts |
| Flat network | Per-tier subnets and SGs, VPC endpoints, no internet route for data tier |
| Vulnerable app / image | WAF managed rules, patch pipeline, ECR image scanning, SAST/DAST |
| Ransomware / deletion | Automated backups, cross-account copy, S3 Object Lock, restore drills |
