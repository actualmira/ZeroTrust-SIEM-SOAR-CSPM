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

- [Technology Stack](#-technology-stack)
- [Phase 1: Network Segmentation and Least Privilege Access Controls](#-phase-1-network-segmentation-and-least-privilege-access-controls)
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

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Network** | AWS VPC, Security Groups | Microsegmentation, network isolation |
| **Compute** | EC2 (Ubuntu 22.04) | Web server, database, SIEM infrastructure |
| **SIEM** | Wazuh 4.7.5 | Log aggregation, correlation, alerting |
| **FIM** | Wazuh FIM | File integrity monitoring |
| **Visualization** | Wazuh Dashboard | Security monitoring and incident analysis |
| **Indexing** | OpenSearch (Wazuh Indexer) | Log storage and search |
| **Logging** | CloudTrail, VPC Flow Logs | AWS API audit + network traffic metadata |
| **SOAR** | Wazuh Active Response, Bash | Automated IP blocking |
| **CSPM** | AWS Lambda (Python 3.12/Boto3) | Auto-remediation of misconfigurations |
| **Orchestration** | EventBridge | Event-driven automation triggers |
| **Access** | AWS Systems Manager Session Manager | Bastion-less secure access |
| **IAM** | AWS IAM Roles & Policies | Least-privilege access control |
| **Firewall** | iptables | Host-based firewall for active response |
| **Cloud Services** | S3, CloudTrail, VPC Flow Logs | Storage, audit logging, network monitoring |
| **Languages** | Python 3.12, Bash, XML, JSON | Lambda functions, automation, rule configs |
| **Frameworks** | MITRE ATT&CK, NIST CSF | Threat detection, security controls |
| **Compliance** | PCI DSS, GDPR, HIPAA | Compliance mappings and controls |

---

## 🔐 Phase 1: Network Segmentation and Least Privilege Access Controls

### Objective

To build a secure network architecture with proper separation of concerns, implementing security best practices for AWS environments. Aimed to reduce attack surface through strategic subnet placement, least-privilege security groups, and identity-based access controls.


### Security Architecture Principles

| Principle | Implementation |
|-----------|----------------|
| **Minimal Attack Surface** | Eliminated SSH exposure via Session Manager, No port 22 open anywhere. IAM role-based access through Systems Manager. Sessions logged to CloudTrail. No SSH keys to rotate or secure |
| **Least Privilege Access** | Security groups allow only required ports/protocols |
| **Assume Breach** | Network segmentation limits lateral movement |
| **Verify Explicitly** | CloudTrail logs all actions for continuous verification |
| **Microsegmentation** | Each tier isolated with dedicated security groups |

---

### 1.1 VPC Network Design

#### Architecture Decision

I created a VPC with four subnets across two availability zones, strategically separating public-facing infrastructure from the database tier.
```
- VPC CIDR: 10.0.0.0/16
- Public Subnet 1 (us-east-1a): 10.0.0.0/20 (Web Server + Wazuh Manager)
- Public Subnet 2 (us-east-1b): 10.0.16.0/20 (Multi-AZ failover capability)
- Private Subnet 1 (us-east-1a): 10.0.128.0/20 (Database - Primary)
- Private Subnet 2 (us-east-1b): 10.0.144.0/20 (Database - Standby/Read Replica)
```
![VPC Architecture](screenshots/phase1/01-vpc-architecture.png)
*Figure 1.1: VPC topology showing public and private subnet separation with controlled internet access*

#### Subnet Strategy

**Co-locating Web Server and Wazuh Manager:**
I placed both the web server and Wazuh Manager in the same public subnet (10.0.0.0/20) with restricted security groups.

**Why public subnets for both:**
1. **Web Server** - Obviously needs to accept HTTP/HTTPS from the internet
2. **Wazuh Manager** - Needs to be accessible by the web server agent, and I need dashboard access as the administrator.

In a **production environment**, they should be in a private subnet without a direct internet access but  via NAT Gateway for updates or via **VPN, AWS Private Link or load balancer in a public subnet** for inbound traffic but for a demonstration environment, putting them in a public subnet with strict security group rules was a reasonable trade-off and
avoids the cost of a NAT Gateway or Application Load Balancer.

**The trade-off:**
If someone compromises the web server, they're already in the same network segment as the Wazuh Manager. Security groups still protect it by providing instance-level isolation (only specific ports open, dashboard restricted to my IP), but there's less network-level isolation.

**Multi-AZ Architecture:**
I deployed across two availability zones (us-east-1a and us-east-1b) to demonstrate high availability concepts, even though I'm only running single instances in this demo.

**Why two AZs:**
- **Database failover capability** - RDS can automatically fail over to the standby subnet if us-east-1a fails
- **Future scaling** - If I wanted to add a second web server for load balancing, I'd put it in the 1b public subnet
- **Best practice demonstration** - Shows I understand production architecture.

**Private Subnets (Database Tier):**
The database lives in the private subnets with no direct internet access:
- Primary instance in 10.0.128.0/20 (us-east-1a)
- Standby/read replica capability in 10.0.144.0/20 (us-east-1b)
- In production environment, both subnets route through NAT Gateway or VPC Endpoint for outbound connections (package updates, OS patches)
- Zero inbound routes from Internet Gateway.

**Security benefit:**
The database is network-isolated from the internet. Even if someone compromised both the web server and Wazuh Manager, they'd still need to:
1. Bypass the security group rules (only port 3306 from sg-web allowed)
2. Authenticate to the database itself
3. Navigate the fact that there's no route from the database back to the internet for data exfiltration (would need to proxy through the web server).

This is **defense in depth** - multiple layers have to fail before data is compromised.

### 1.2 Security Group Configuration

Security groups act as stateful firewalls controlling traffic at the instance level. I configured three security groups with very specific rules following the principle of least privilege.

#### Web Server Security Group
![Web Server Security Group](screenshots/phase1/02-security-groups-web.png)

**Inbound Rules:**

| Type | Protocol | Port | Source | Justification |
|------|----------|------|--------|---------------|
| HTTP | TCP | 80 | 0.0.0.0/0 | Public website access |
| HTTPS | TCP | 443 | 0.0.0.0/0 | Secure public website access |

**Outbound Rules:**

| Type | Protocol | Port | Destination | Justification |
|------|----------|------|-------------|---------------|
| HTTP | TCP | 80 | 0.0.0.0/0 | Package repositories |
| HTTPS | TCP | 443 | 0.0.0.0/0 | Package updates, HTTPS traffic |
| Custom TCP | TCP | 1514 | sg-wazuh | Wazuh agent event forwarding |
| Custom TCP | TCP | 1515 | sg-wazuh | Wazuh agent enrollment |
| Custom TCP | TCP | 55000 | sg-wazuh | Wazuh API communication |
| MySQL | TCP | 3306 | sg-database | Database queries |

**Key Design Decisions:**

Notice the outbound rules to Wazuh and the database use **security group references** (sg-wazuh, sg-database) instead of IP addresses. This is important because:
- If instance IPs change, rules still work
- Clear intent - "web server talks to Wazuh or Database only on specific ports"
- Reduces attack surface
- Easier to audit and maintain

**SSH notably absent:**
There's no SSH (port 22) rule. Instead, I use AWS Systems Manager Session Manager (configured via IAM role) for administrative access. This eliminates the need to expose SSH and manage SSH keys, which are common attack vectors.

#### Wazuh Manager Security Group

![Wazuh Manager Security Group](screenshots/phase1/03-security-groups-wazuh.png)

**Inbound Rules:**

| Type | Protocol | Port | Source | Justification |
|------|----------|------|--------|---------------|
| Custom TCP | TCP | 1514 | sg-web | Agent log events |
| Custom TCP | TCP | 1515 | sg-web | Agent registration |
| Custom TCP | TCP | 55000 | sg-web | Wazuh API (agent management) |
| HTTPS | TCP | 443 | My IP (41.x.x.x/32) | Wazuh dashboard access |

**Outbound Rules:**

| Type | Protocol | Port | Destination | Justification |
|------|----------|------|-------------|---------------|
| HTTPS | TCP | 443 | 0.0.0.0/0 | AWS API calls, package updates |
| HTTP | TCP | 80 | 0.0.0.0/0 | Domain name resolution |

**Critical security controls:**

1. **Agent ports (1514, 1515, 55000) only accept connections from sg-web**
   - Even though Wazuh Manager is in a public subnet, these ports can't be reached from the internet
   - Only the web server can connect
   - If I had multiple agents in production, I'd allow their security groups too

2. **Dashboard access (443) restricted to my IP address**
   - I'm the only one who can access the Wazuh web interface
   - This prevents unauthorized access to the SIEM
   - **In production**, this would be:
     - Multiple admin IPs (SOC team)
     - VPN endpoint (all admins route through VPN)
     - AWS PrivateLink (no public access at all)
     - Or behind a bastion host in private subnet

**Why I allowed my specific IP:**
The Wazuh dashboard contains sensitive security information - alerts, logs, configuration. Allowing access from only my IP (41.x.x.x/32) means even if someone knew the Wazuh Manager's public IP, they couldn't reach the dashboard. This is a compromise for a demo environment; production would use VPN or PrivateLink to avoid public exposure entirely.

**No SSH here either:**

Same as the web server - using Systems Manager Session Manager via IAM role for administrative access.

#### Database Security Group

![Database Security Group](screenshots/phase1/04-security-groups-database.png)

**Inbound Rules:**

| Type | Protocol | Port | Source | Justification |
|------|----------|------|--------|---------------|
| MySQL | TCP | 3306 | sg-web | Database queries from web application |

**Outbound Rules:**

| Type | Protocol | Port | Destination | Justification |
|------|----------|------|-------------|---------------|
| All traffic | All | All | 0.0.0.0/0 | Response traffic (stateful) |


**Most restrictive security group:**
The database accepts connections ONLY from the web server security group. Nothing else can reach port 3306.

**In a production environment:**

This rule would be more complex:
```
Inbound:
- MySQL (3306) from sg-web
- MySQL (3306) from sg-wazuh (if Wazuh agents query DB for inventory)
- MySQL (3306) from NAT Gateway IP (for automated backups)
- Systems Manager Session Manager via IAM role for administrative access.

```
For this demo, only the web server needs database access, so that's all I allowed.

**Why the database is in private subnet:**

Even with security group protection, defense in depth means adding network-level isolation. The database:
- Has no public IP address
- Cannot be reached from the internet (no IGW route)
- Must be accessed through instances that ARE in public subnets

This creates layers of security. An attacker would need to:
1. Compromise the web server
2. Bypass security group rules
3. Then reach the database

### 1.3 Identity and Access Management (IAM)

Instead of managing SSH keys and opening port 22, I used AWS IAM roles and Systems Manager Session Manager for secure instance access.

#### Web Server IAM Role

**Attached Policies:**
- `AmazonSSMManagedInstanceCore` - Enables Session Manager access
![WEB-IM ROE](screenshots/phase1/04-security-groups-database.png)

**Why this approach:**

Traditional SSH access requires:
- Managing SSH key pairs
- Opening port 22 (common attack vector)
- No audit trail of what commands were run
- Risk of compromised or leaked keys

Session Manager provides:
- No SSH keys to manage
- No port 22 exposure
- All sessions logged to CloudTrail
- Can restrict access through IAM policies
- Can record session commands for compliance

**Access workflow:**
```
Admin → AWS Console → Systems Manager → Session Manager → Web Server
                            ↓
                      CloudTrail Log
```

Every session is logged: who connected, when, and (optionally) what commands they ran.

#### Wazuh Manager IAM Role

**Attached Policies:**
1. `AmazonS3ReadOnlyAccess` - Read CloudTrail logs from S3
2. `AmazonSSMManagedInstanceCore` - Session Manager access
3. `CloudWatchLogsReadOnlyAccess` - Read CloudWatch logs

![Wazuh Manager IAM Role](screenshots/phase1/05-iam-role-wazuh.png)

**Why these permissions:**

**1. AmazonS3ReadOnlyAccess:**

The Wazuh Manager needs to read CloudTrail logs from the S3 bucket (`zerotrust123`) to ingest AWS API activity into the SIEM. The `aws-s3` module in Wazuh polls this bucket every 10 minutes for new logs.

Read-only is sufficient - Wazuh only needs to `GetObject` and `ListBucket`, not write or delete.

**2. CloudWatchLogsReadOnlyAccess:**

For VPC Flow Logs integration which I configured to go to CloudWatchLogs. 

**3. AmazonSSMManagedInstanceCore:**

Session Manager access for administrative tasks (checking logs, restarting services, troubleshooting).

**Least privilege consideration:**

In production, I'd use a custom IAM policy instead of AWS managed policy for S3Bucket Read Access:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::zerotrust123",
        "arn:aws:s3:::zerotrust123/*"
      ]
    }
  ]
}
```
This is more restrictive than `AmazonS3ReadOnlyAccess` which allows reading from ALL S3 buckets in the account. For a demo, the managed policy is fine, but production should be scoped to specific resources.

---

### 1.4 CloudTrail Audit Logging

#### Why CloudTrail

AWS doesn't log API activity by default. Without CloudTrail, if someone:
- Modified a security group
- Created an EC2 instance
- Changed an IAM policy
- Accessed an S3 bucket

...there would be no record of it. CloudTrail provides an audit trail of every API call made in the AWS account and it's immutable.

**What CloudTrail captures:**

For every API call:
- **Who** - IAM user or role that made the call
- **What** - The specific action (RunInstances, DeleteBucket, etc.)
- **When** - Timestamp
- **Where** - Source IP address and AWS region
- **How** - Whether it succeeded or failed
- **Why** - Request parameters (what was changed)

#### Configuration

![CloudTrail Configuration](screenshots/phase1/06-cloudtrail-config.png)

| Setting | Value | Why |
|---------|-------|-----|
| **Trail Name** | zerotrust-trail | Descriptive naming |
| **S3 Bucket** | zerotrust123 | Centralized log storage |
| **Log File Validation** | Enabled | Detect log tampering |
| **Multi-Region** | Yes | Capture activity across all AWS regions |
| **Management Events** | All (read + write) | Complete visibility |

**S3 bucket for logs:**

CloudTrail writes logs to S3 bucket `zerotrust123`. I configured the bucket with:
- Server-side encryption (SSE-S3)
- Versioning enabled (can't overwrite logs)
- Block public access (logs should never be public)

**Bucket policy - least privilege:**

Only CloudTrail service can write to this bucket:
```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "AWSCloudTrailAclCheck20150319-b3f0c3ca-3e2c-46a2-bb6f-84b9816fe146",
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "s3:GetBucketAcl",
			"Resource": "arn:aws:s3:::zerotrust123",
			"Condition": {
				"StringEquals": {
					"AWS:SourceArn": "arn:aws:cloudtrail:us-east-1:011555818509:trail/ZeroTrust-Trail"
				}
			}
		},
		{
			"Sid": "AWSCloudTrailWrite20150319-db5b4ad8-3321-49ba-b688-ee03fb63efe1",
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "s3:PutObject",
			"Resource": "arn:aws:s3:::zerotrust123/AWSLogs/011555818509/*",
			"Condition": {
				"StringEquals": {
					"AWS:SourceArn": "arn:aws:cloudtrail:us-east-1:011555818509:trail/ZeroTrust-Trail",
					"s3:x-amz-acl": "bucket-owner-full-control"
				}
			}
		}
	]
}
```
#### Integration with Wazuh

CloudTrail logs are ingested into Wazuh SIEM (configured in Phase 2) for real-time monitoring. This enables:
- Alerts on suspicious API calls (privilege escalation, security group changes)
- Correlation with host-based events
- Investigation of security incidents
- Compliance reporting

#### Events Captured

**Example CloudTrail events logged:**
![CloudTrail Configuration](screenshots/phase1/06-cloudtrail-config.png)

---

### 1.5 VPC Flow Logs

#### Purpose

VPC Flow Logs capture metadata about network traffic - not the packet contents, but information about connections:
- Which IPs are talking to each other
- What ports they're using
- Whether the connection was allowed or denied
- How much data was transferred

This is useful for:
- Detecting port scanning
- Identifying data exfiltration
- Troubleshooting connectivity issues
- Network forensics during incidents

#### Configuration

![VPC Flow Logs](screenshots/phase1/07-vpc-flowlogs.png)

| Setting | Value | Why |
|---------|-------|-----|
| **Filter** | All (Accept + Reject) | See both allowed and blocked traffic |
| **Destination** | Cloudwatch Log | Long-term storage |
| **Aggregation** | 10 minutes | Balance between detail and cost |

**IAM Role for VPC Flow Logs:**

This follows least privilege - only the VPC Flow Logs service can

#### Security Posture Achieved

**Attack surface reduction:**

| Before | After | Improvement |
|--------|-------|-------------|
| SSH exposed to internet | No SSH exposure (Session Manager) | Eliminated common attack vector |
| No API activity logging | CloudTrail enabled | Complete audit trail |
| No network visibility | VPC Flow Logs collecting | Network forensics capability |
| Overly permissive SGs | Least-privilege rules | Reduced blast radius |
| No database isolation | Private subnet isolation | Defense in depth |

**What this architecture accomplishes:**
- Separates public-facing and sensitive infrastructure
- Reduces attack surface through security group least privilege
- Eliminates SSH key management risks
- Provides foundation for SIEM monitoring (Phase 2)
- Creates audit trail for compliance and incident response

**Where it falls short of enterprise production:**
- Wazuh Manager should be in private subnet or behind VPN
- Should use AWS PrivateLink to eliminate public internet traffic for AWS API calls
- IAM policies could be more granular
- Missing DDoS protection (AWS Shield Advanced)
- Single points of failure (no high availability)

These trade-offs are appropriate for a demonstration environment. The architecture shows I understand the principles and can articulate what production would require.

---

