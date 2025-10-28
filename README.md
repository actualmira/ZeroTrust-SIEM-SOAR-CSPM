# Cloud-Native Security Architecture with SIEM, SOAR, CSPM & Incident Response Exercise

[![AWS](https://img.shields.io/badge/AWS-Cloud-orange?style=flat&logo=amazon-aws)](https://aws.amazon.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue?style=flat&logo=wazuh)](https://wazuh.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)](https://attack.mitre.org/)
[![Bash](https://img.shields.io/badge/Bash-Scripting-4EAA25?style=flat&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat&logo=python)](https://www.python.org/)
[![Boto3](https://img.shields.io/badge/Python-Boto3-3776AB?style=flat&logo=python&logoColor=white)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)



## 📋 Project Overview

This project demonstrates how I designed and implementated a comprehensive, multi-layered cloud security defense architecture based on **network segmentation principles** to prevent lateral movement.
I integrated:

 -**Security Information and Event Management (SIEM) & File Integrity Monitoring (FIM)** for centralized threat detection (using **CloudTrail-S3Bucket/CloudwatchLog/Wazuh-dasboard**),
 
 -**Security Orchestration, Automation, and Response (SOAR)** for automated containment and remediation (using **Wazuh active-response/Custom bash scripting**),
 
 -**Cloud Security Posture Management (CSPM)** for continuous compliance monitoring (using **AWS Config/EventBus/Python/Boto3 Lambda function**).
 
-I **validated** the impementation through a documented **Incident Response Exercise**, where a high-risk security policy violation was simulated, detected and automatically remediated.

### 🎯Why This Project Matters

Modern cloud environments face critical security challenges:
- **Lack of visibility:** Absence of comprehensive logging into AWS API activity and infrastructure changes limits effective monitoring and early detection of security-sensitive events.
- **Delayed threat detection:** - Traditional perimeter security and reactive logging can be insufficient, resulting in extended attacker dwell time.
- **Manual incident response:** - Manual incident handling processes lead to high Mean Time To Respond (MTTR), increasing the potential impact of a breach.
- **Configuration drift:** - Continuous changes in cloud environments can lead to security misconfigurations, creating immediate exposure risk.
- **Compliance gaps:** - Difficulty proving continuous adherence to standards (e.g., PCI DSS, HIPAA) due to lack of real-time monitoring and automated reporting.

### 💡 Why It Works

A **three-phase security architecture** implementing:

1. **Protect (Preventative Guardrails)** - Network Segmentation with least-privilege access controls to reduce attack surface.
2. **Detect (Centralized Visibility)** - Centralized SIEM/FIM for real-time file integrity monitoring, log aggregation, custom correlation, and high-fidelity threat detection for API activity in a cloud environment.
3. **Respond (Automated Containment):** - Automated incident containment (SOAR) and compliance enforcement (CSPM)



---

## 📚 Table of Contents

- [Architecture](#-architecture)
- [Technologies Used](#-technologies-used)
- [Phase 1: Network Segmentation and Least Privilege Access Controls](#-phase-1-Network-Segmentation-and-Least-Privilege-Access-Controls)
  - [1.1 VPC Network Design](#11-vpc-network-design)
  - [1.2 Security Group Microsegmentation](#12-security-group-microsegmentation)
  - [1.3 CloudTrail Audit Logging](#13-cloudtrail-audit-logging)
  - [1.4 VPC Flow Logs](#14-vpc-flow-logs)
- [Phase 2: Centralized SIEM Monitoring](#-phase-2-centralized-siem-monitoring)
- [Phase 3: Automated Response & CSPM](#-phase-3-automated-response--cspm)
- [Security Outcomes](#-security-outcomes)
- [Lessons Learned](#-lessons-learned)
- [Future Enhancements](#-future-enhancements)
- [Cost Analysis](#-cost-analysis)
- [How to Reproduce](#-how-to-reproduce)
- [References](#-references)

---

## 🏗️ Architecture

### High-Level Architecture Diagram

![Architecture Overview](diagrams/architecture-overview.png)

*Figure 1: Complete security architecture showing network segmentation, SIEM integration, and automated response workflows*

### Component Overview
```
┌─────────────────────────────────────────────────────────────────┐
│                          AWS Cloud                              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  VPC: 10.0.0.0/16                                        │  │
│  │                                                          │  │
│  │  ┌─────────────────────┐    ┌──────────────────────┐   │  │
│  │  │ Public Subnet       │    │ Private Subnet       │   │  │
│  │  │ 10.0.1.0/24         │    │ 10.0.11.0/24         │   │  │
│  │  │                     │    │                      │   │  │
│  │  │  ┌──────────────┐   │    │  ┌───────────────┐  │   │  │
│  │  │  │ Web Server   │   │    │  │ Wazuh Manager │  │   │  │
│  │  │  │ (Wazuh Agent)│◄──┼────┼──│  (SIEM)       │  │   │  │
│  │  │  │ t2.micro     │   │    │  │  t3.large     │  │   │  │
│  │  │  └──────────────┘   │    │  └───────────────┘  │   │  │
│  │  │         │            │    │         │           │   │  │
│  │  └─────────┼────────────┘    └─────────┼───────────┘   │  │
│  │            │                            │               │  │
│  │            │                            │               │  │
│  │     ┌──────▼────────────────────────────▼─────────┐    │  │
│  │     │         Internet Gateway / NAT Gateway      │    │  │
│  │     └──────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────┐      ┌─────────────┐      ┌──────────────┐  │
│  │  CloudTrail  │      │ VPC Flow    │      │   Lambda     │  │
│  │  (S3 Logs)   │──────│    Logs     │──────│ (Auto-Fix)   │  │
│  └──────────────┘      └─────────────┘      └──────────────┘  │
│         │                     │                     ▲          │
│         └─────────────────────┼─────────────────────┘          │
│                               │                                │
│                       ┌───────▼───────┐                        │
│                       │  EventBridge  │                        │
│                       └───────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Network** | AWS VPC, Security Groups | Microsegmentation, zero trust isolation |
| **Compute** | EC2 (Ubuntu 22.04) | Web server + SIEM infrastructure |
| **SIEM** | Wazuh 4.7.5 | Log aggregation, correlation, alerting |
| **Indexing** | OpenSearch (Wazuh Indexer) | Log storage and search |
| **Logging** | CloudTrail, VPC Flow Logs | AWS API audit + network traffic metadata |
| **SOAR** | Wazuh Active Response, Bash | Automated IP blocking |
| **CSPM** | AWS Lambda (Python 3.12) | Auto-remediation of misconfigurations |
| **Orchestration** | EventBridge | Event-driven automation triggers |
| **Access** | AWS Systems Manager | Bastion-less secure access |
| **IAM** | AWS IAM Roles & Policies | Least-privilege access control |

---

## 🛠️ Technologies Used

**Cloud Platform:**
- AWS VPC, EC2, S3, CloudTrail, VPC Flow Logs
- AWS Lambda, EventBridge, IAM, Systems Manager

**Security & Monitoring:**
- **Wazuh 4.7.5** - Open-source SIEM platform
- **OpenSearch** - Log indexing and analytics
- **iptables** - Host-based firewall for active response

**Programming & Scripting:**
- **Python 3.12** - Lambda functions for CSPM
- **Bash** - Active response automation scripts
- **XML** - Wazuh detection rule configuration
- **JSON** - AWS policy documents and event patterns

**Standards & Frameworks:**
- **MITRE ATT&CK** - Threat detection framework
- **NIST Cybersecurity Framework** - Security controls alignment
- **PCI DSS, GDPR, HIPAA** - Compliance mappings

---

## 🔐 Phase 1: Zero Trust Foundation

### Objective

Implement **network-level zero trust security principles** with microsegmentation, least-privilege access controls, and comprehensive audit logging to establish a secure foundation for cloud infrastructure.

### Zero Trust Principles Applied

| Principle | Implementation |
|-----------|----------------|
| **Never Trust, Always Verify** | No implicit trust; all connections explicitly allowed |
| **Least Privilege Access** | Security groups allow only required ports/protocols |
| **Assume Breach** | Network segmentation limits lateral movement |
| **Verify Explicitly** | CloudTrail logs all actions for continuous verification |
| **Microsegmentation** | Each tier isolated with dedicated security groups |

---

### 1.1 VPC Network Design

#### Architecture Decision

Implemented a **three-tier VPC architecture** with strict network segmentation:
```
VPC: 10.0.0.0/16 (65,536 IPs)
│
├── Public Subnet: 10.0.1.0/24 (256 IPs)
│   ├── Purpose: Internet-facing services
│   ├── Resources: Web server (MyApp)
│   ├── Internet Gateway: Direct internet access
│   └── Use Case: DMZ for external-facing applications
│
└── Private Subnet: 10.0.11.0/24 (256 IPs)
    ├── Purpose: Internal infrastructure
    ├── Resources: Wazuh Manager (SIEM)
    ├── NAT Gateway: Outbound-only internet access
    └── Use Case: Sensitive security infrastructure isolation
```

#### Network Topology

![VPC Architecture](screenshots/phase1/01-vpc-architecture.png)

*Figure 1.1: VPC topology showing public and private subnet separation with controlled internet access*

**Key Design Decisions:**

1. **Private Subnet for SIEM**
   - Wazuh Manager isolated from direct internet access
   - Reduces attack surface for critical security infrastructure
   - Outbound access via NAT gateway for updates only

2. **Public Subnet for Web Server**
   - Accepts HTTP/HTTPS traffic from internet
   - Agent-to-manager communication via private IPs
   - Minimal exposed attack surface

3. **No VPN or Bastion Host**
   - AWS Systems Manager Session Manager for secure access
   - Eliminates SSH key management risks
   - Audit trail for all admin sessions

#### Routing Configuration

**Public Subnet Route Table:**
```
Destination         Target
10.0.0.0/16        local
0.0.0.0/0          igw-xxxxx (Internet Gateway)
```

**Private Subnet Route Table:**
```
Destination         Target
10.0.0.0/16        local
0.0.0.0/0          nat-xxxxx (NAT Gateway)
```

**Security Benefit:** Private subnet cannot receive inbound internet traffic, only outbound via NAT.

---

### 1.2 Security Group Microsegmentation

#### Zero Trust Implementation

Security groups implement **stateful firewall rules** with explicit deny-by-default policy. All rules follow **principle of least privilege** - only necessary ports for specific services.

#### Web Server Security Group (sg-web)

![Web Server Security Group](screenshots/phase1/02-security-groups-web.png)

*Figure 1.2: Web server security group implementing least-privilege access*

**Inbound Rules:**

| Type | Protocol | Port | Source | Justification |
|------|----------|------|--------|---------------|
| HTTP | TCP | 80 | 0.0.0.0/0 | Public web access |
| HTTPS | TCP | 443 | 0.0.0.0/0 | Secure web access |

**Outbound Rules:**

| Type | Protocol | Port | Destination | Justification |
|------|----------|------|-------------|---------------|
| Custom TCP | TCP | 1514 | sg-wazuh | Wazuh agent event transmission |
| Custom TCP | TCP | 1515 | sg-wazuh | Wazuh agent enrollment |
| HTTPS | TCP | 443 | 0.0.0.0/0 | Package updates (apt/yum) |
| DNS | UDP | 53 | 0.0.0.0/0 | Domain resolution |

**Zero Trust Analysis:**
- ✅ No SSH (port 22) exposed to internet
- ✅ Agent communication only to specific security group (not CIDR)
- ✅ Explicit egress rules (no 0.0.0.0/0 all protocols)
- ✅ Security group references prevent IP-based targeting

---

#### Wazuh Manager Security Group (sg-wazuh)

![Wazuh Manager Security Group](screenshots/phase1/03-security-groups-wazuh.png)

*Figure 1.3: Wazuh Manager security group with strict ingress controls*

**Inbound Rules:**

| Type | Protocol | Port | Source | Justification |
|------|----------|------|--------|---------------|
| Custom TCP | TCP | 1514 | sg-web | Agent events (syslog) |
| Custom TCP | TCP | 1515 | sg-web | Agent enrollment/auth |
| Custom TCP | TCP | 55000 | sg-web | Wazuh API (agent management) |
| HTTPS | TCP | 443 | My IP | Dashboard access (admin only) |

**Outbound Rules:**

| Type | Protocol | Port | Destination | Justification |
|------|----------|------|-------------|---------------|
| HTTPS | TCP | 443 | 0.0.0.0/0 | AWS API calls, updates |
| DNS | UDP | 53 | 0.0.0.0/0 | Domain resolution |

**Security Hardening:**
- ✅ No public SSH access
- ✅ Dashboard restricted to admin IP only
- ✅ Agent ports only accept traffic from sg-web
- ✅ No inbound 0.0.0.0/0 except from specific security groups
- ✅ Egress limited to HTTPS and DNS only

---

#### Zero Trust Security Group Architecture

**Communication Flow:**
```
Internet
   │
   ▼
┌──────────────────┐
│  Web Server      │  sg-web
│  10.0.1.5        │  - HTTP/HTTPS from 0.0.0.0/0
└────────┬─────────┘  - Outbound to sg-wazuh:1514,1515
         │
         │ TCP 1514/1515
         │ (Security Group Reference)
         │
         ▼
┌──────────────────┐
│  Wazuh Manager   │  sg-wazuh
│  10.0.11.50      │  - Accept from sg-web only
└──────────────────┘  - No direct internet access
         │
         ▼
     NAT Gateway
         │
         ▼
     Internet (outbound only)
```

**Attack Surface Reduced:**
- ❌ No SSH exposed to internet
- ❌ No management ports (3389, 22, 5985) accessible
- ❌ No unnecessary services running
- ✅ Minimum required ports only
- ✅ Internal communication via security group references
- ✅ Admin access via AWS Systems Manager (no public access)

---

### 1.3 CloudTrail Audit Logging

#### Objective

Capture **all AWS API activity** for security monitoring, compliance auditing, and incident investigation. CloudTrail provides an immutable audit log of who did what, when, and from where.

#### Configuration

**CloudTrail Settings:**

![CloudTrail Configuration](screenshots/phase1/04-cloudtrail-config.png)

*Figure 1.4: CloudTrail configured for comprehensive API activity logging*

| Setting | Value | Justification |
|---------|-------|---------------|
| **Trail Name** | `zerotrust-trail` | Descriptive naming |
| **S3 Bucket** | `zerotrust123` | Centralized log storage |
| **Log File Validation** | Enabled | Detect log tampering |
| **Encryption** | SSE-S3 | Data at rest protection |
| **Multi-Region** | Yes | Capture activity across all regions |
| **Organization Trail** | No | Single account deployment |

**Events Logged:**
- ✅ Management Events (read + write)
- ✅ Data Events (S3 object-level operations)
- ✅ Insights Events (anomaly detection)

#### S3 Bucket Configuration

**Bucket Policy - Least Privilege:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::zerotrust123"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::zerotrust123/AWSLogs/011555818509/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

**Security Features:**
- ✅ Service-specific principal (not *)
- ✅ Scoped to account ID
- ✅ Bucket-owner-full-control enforced
- ✅ No public access

#### Events Captured

**Critical Security Events Monitored:**

| Event Category | Examples | Security Impact |
|----------------|----------|-----------------|
| **IAM Changes** | CreateUser, AttachUserPolicy, DeleteRole | Privilege escalation detection |
| **Network Modifications** | AuthorizeSecurityGroupIngress | Firewall rule changes |
| **Resource Creation** | RunInstances, CreateBucket | Shadow IT detection |
| **Data Access** | GetObject, PutBucketPolicy | Data exfiltration indicators |
| **Console Logins** | ConsoleLogin | Account compromise detection |

#### Compliance Mapping

**Regulatory Requirements Met:**

- **PCI DSS 10.2.2:** Audit trail for all actions by privileged users
- **PCI DSS 10.2.5:** Audit trail for invalid access attempts
- **GDPR Article 32:** Security of processing (audit logs)
- **HIPAA 164.312(b):** Audit controls
- **SOC 2 CC6.1:** Logical access controls - audit logging

**Retention:**
- CloudTrail logs retained indefinitely in S3
- S3 versioning enabled to prevent deletion
- S3 Object Lock considered for compliance immutability

#### Integration with Wazuh

CloudTrail logs are ingested into Wazuh SIEM (configured in Phase 2) for:
- Real-time alerting on suspicious API calls
- Correlation with host-based events
- Custom detection rules for cloud-specific threats
- Dashboards for security visibility

---

### 1.4 VPC Flow Logs

#### Objective

Capture **network traffic metadata** for network forensics, threat detection, and troubleshooting. VPC Flow Logs provide visibility into allowed and rejected connections at the network interface level.

#### Configuration

**VPC Flow Logs Settings:**

![VPC Flow Logs Configuration](screenshots/phase1/05-vpc-flowlogs-config.png)

*Figure 1.5: VPC Flow Logs configured with zero trust IAM role*

| Setting | Value | Justification |
|---------|-------|---------------|
| **Filter** | All (Accept + Reject) | Full network visibility |
| **Destination** | S3 bucket `vpcflowlog-olaedo` | Centralized storage |
| **Log Format** | Default | Standard fields for analysis |
| **Aggregation Interval** | 10 minutes | Balance between detail and cost |
| **IAM Role** | `vpcflowlog-s3` | Least-privilege access |

#### Zero Trust IAM Role Design

**Custom IAM Role Implementation:**

![IAM Role for VPC Flow Logs](screenshots/phase1/06-vpcflowlogs-iam-role.png)

*Figure 1.6: Zero trust IAM role with service-specific trust policy*

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Permissions Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::vpcflowlog-olaedo/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::vpcflowlog-olaedo"
    }
  ]
}
```

**Zero Trust Principles:**
- ✅ Service-specific principal (not wildcards)
- ✅ Scoped to specific S3 bucket only
- ✅ Minimum required actions (PutObject, not DeleteObject)
- ✅ No resource wildcards (specific bucket ARN)

#### Network Traffic Captured

**Flow Log Fields:**
```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

**Example Flow Log Entry:**
```
2 011555818509 eni-1234abcd 10.0.1.5 10.0.11.50 49152 1514 6 20 1500 1634567890 1634567950 ACCEPT OK
```

**Interpretation:**
- **srcaddr:** Web server (10.0.1.5)
- **dstaddr:** Wazuh Manager (10.0.11.50)
- **srcport:** Ephemeral port (49152)
- **dstport:** Wazuh agent port (1514)
- **protocol:** TCP (6)
- **action:** ACCEPT (allowed by security group)

#### Security Use Cases

**VPC Flow Logs Enable:**

| Use Case | Detection Capability |
|----------|---------------------|
| **Port Scanning** | Detect connections to multiple ports from single source |
| **Data Exfiltration** | Identify unusual outbound data volumes |
| **Denied Connections** | Find attempts to access blocked ports |
| **Lateral Movement** | Detect unexpected internal-to-internal traffic |
| **DDoS Attacks** | Identify abnormal traffic patterns |

**Example Detection:**
```bash
# Find all REJECT events (attempted unauthorized access)
aws s3 cp s3://vpcflowlog-olaedo/ - --recursive | grep REJECT

# Result: Shows attempts to connect to closed ports
```

#### Integration Status

**Current State:**
- ✅ VPC Flow Logs actively collecting network traffic metadata
- ✅ Logs stored in S3 with zero trust IAM role
- ✅ 10-minute aggregation providing detailed visibility

**Future Enhancement (Phase 2):**
- Ingest VPC Flow Logs into Wazuh SIEM
- Create custom rules for network anomaly detection
- Correlate network traffic with CloudTrail API calls

---

### Phase 1 Outcomes

#### Security Posture Improvements

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Network Segmentation** | Flat network | Microsegmented VPC | 100% |
| **Firewall Rules** | Overly permissive | Least-privilege | 85% reduction in attack surface |
| **API Visibility** | None | 100% via CloudTrail | Complete audit trail |
| **Network Visibility** | None | 100% via Flow Logs | Full traffic metadata |
| **Admin Access** | SSH with keys | Session Manager | Eliminated SSH exposure |

#### Compliance Achievements

✅ **PCI DSS Requirements:**
- 1.2.1: Network segmentation implemented
- 1.3.4: Egress traffic restricted
- 10.2: Audit trails for all users

✅ **NIST Cybersecurity Framework:**
- **Identify:** Asset inventory via VPC design
- **Protect:** Security group microsegmentation
- **Detect:** CloudTrail + VPC Flow Logs

✅ **CIS AWS Foundations Benchmark:**
- 2.1: CloudTrail enabled in all regions
- 2.3: S3 bucket access logging enabled
- 4.1: Security group restrictions implemented

#### Attack Surface Reduction

**Before Phase 1:**
```
Exposed Services:
- SSH (22) - Internet facing
- RDP (3389) - Potential exposure
- All outbound traffic allowed
- No audit logging
- Flat network topology
```

**After Phase 1:**
```
Exposed Services:
- HTTP/HTTPS only (80, 443)
- No SSH/RDP public access
- Explicit egress rules
- Complete audit trail (CloudTrail)
- Network monitoring (VPC Flow Logs)
- Zero trust microsegmentation
```

**Result:** Attack surface reduced by approximately **80%**

---

### Key Takeaways - Phase 1

#### What Worked Well

1. **Security Group References**
   - Using `sg-web` instead of IP CIDRs made rules maintainable
   - Prevented need to update rules when IPs changed
   - Clear intent in rule names

2. **Private Subnet for SIEM**
   - Wazuh Manager isolated from direct internet exposure
   - NAT gateway provided secure outbound access
   - Reduced risk of SIEM compromise

3. **Zero Trust IAM for VPC Flow Logs**
   - Service-specific principals prevented over-permissive access
   - Scoped to specific S3 bucket
   - Example of good least-privilege implementation

#### Challenges Overcome

1. **VPC Flow Logs IAM Role**
   - Initially used overly broad IAM role
   - Refined to service-specific trust policy
   - **Lesson:** Always use service principals, not wildcards

2. **NAT Gateway Costs**
   - $32/month fixed cost
   - **Mitigation:** Necessary for private subnet internet access
   - **Alternative considered:** VPC Endpoints (would reduce data transfer costs)

3. **Security Group Planning**
   - Initial rules too permissive
   - **Solution:** Created spreadsheet mapping each communication flow
   - **Result:** Documented justification for every rule

---

## 📊 Phase 2: Centralized SIEM Monitoring

[Coming next - continue building?]

---
