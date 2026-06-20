# Azure Cloud Security Assessment

## Overview

This project documents a security assessment of a deliberately misconfigured Azure environment. I built a vulnerable environment, such as public storage, exposed network ports, over-privileged access, and incomplete logging, then used Microsoft Defender for Cloud and Azure Policy to detect, remediate, and prevent those misconfigurations. The assessment was evaluated against the CIS Microsoft Azure Foundations Benchmark v2.0.

The goal wasn't just to do simple fixes after the fact. After remediating each finding manually, I built two custom Azure Policy guardrails that block the same misconfigurations from being created again, and a CLI script that automates detection and remediation across a resource group.

## Lab Architecture

```
Azure Subscription
|
|— Resource Group — SecLab
|   |
|   |— Storage Account — seclabdata (public blob access, no HTTPS enforcement)
|   |   |— Container — important-data (anonymous read, fake sensitive files)
|   |
|   |— Virtual Machine — VM-lab1 (Ubuntu 22.04)
|   |   |— NSG — VM-lab1-nsg (SSH/RDP open to 0.0.0.0/0)
|   |
|   |— Activity Log Diagnostic Setting (partial export, Administrative only)
|
|— RBAC — duplicate Owner role assignments at subscription scope
|
|— Microsoft Defender for Cloud (Foundational CSPM)
|— Azure Policy
    |— deny-public-blob-access (Deny)
    |— deny-open-management-ports (Deny)
```

## Lab Environment

- Cloud Provider: Microsoft Azure
- Services Used: Storage Accounts, Virtual Machines, Network Security Groups, Azure Policy, Microsoft Defender for Cloud, Azure CLI
- Compliance Framework: CIS Microsoft Azure Foundations Benchmark v2.0

## Project Structure

- [Storage Account Misconfiguration](#storage-account-misconfiguration)
- [Network Security Group Misconfiguration](#network-security-group-misconfiguration)
- [Identity and Access Management](#identity-and-access-management)
- [Activity Logging](#activity-logging)
- [Preventive Policy Enforcement](#preventive-policy-enforcement)
- [Remediation Automation](#remediation-automation)
- [Results](#results)
- [Lessons Learned](#lessons-learned)

---

## Storage Account Misconfiguration

The storage account `seclabdata` was provisioned with public blob access enabled and secure transfer (HTTPS enforcement) disabled. A container was set to allow anonymous read access at the blob level, and fake sensitive files — a credentials file and a CSV of employee records — were uploaded to demonstrate what real-world exposure looks like, not just a flagged setting in isolation.

This combination means anyone with the container URL could read these files without any authentication, and traffic to the storage account wasn't guaranteed to be encrypted in transit.

![public access enabled](evidence/before-storage-public-access-enabled.png)
![public container contents](evidence/before-public-container-files.png)

Defender for Cloud flagged this under its public access recommendation, mapped to CIS control 3.7:

![defender finding detail](evidence/defender-detail-storage-public-access.png)

**Remediation:** Disabled blob anonymous access and enabled secure transfer through the storage account's Configuration blade.

![public access disabled](evidence/after-storage-public-access-disabled.png)
![secure transfer enabled](evidence/after-storage-secure-transfer-enabled.png)

CIS Control: 3.7, 3.1 | Severity: High

---

## Network Security Group Misconfiguration

The NSG attached to `VM-lab1` had inbound rules allowing SSH (22) and RDP (3389) from any source (0.0.0.0/0). This is one of the most common real-world findings in cloud environments — exposed management ports are a direct target for credential brute-forcing and automated exploit scanning, and they don't require any further misconfiguration to be actively dangerous the moment the VM is reachable.

![open ports](evidence/before-nsg-open-ssh-rdp.png)

Defender for Cloud flagged this as an open management port finding:

![defender finding detail](evidence/defender-detail-open-management-ports.png)

**Remediation:** Removed both rules from the NSG, leaving only the default secure rules (intra-VNet traffic and Azure Load Balancer health probes).

![ports closed](evidence/after-nsg-rules-removed.png)

CIS Control: 6.2, 6.3 | Severity: High

---

## Identity and Access Management

The subscription had two separate Owner role assignments tied to the same account at subscription scope — one created as a standard Owner assignment, the other configured with a "highly privileged" delegation condition. Standing privileged access at this scope violates least-privilege principles: every account holding Owner has full control over every resource and every other identity's permissions in the subscription, with no time-bound or approval-based limitation.

![duplicate owner](evidence/before-rbac-duplicate-owner.png)

**Remediation:** Removed the duplicate assignment, leaving a single Owner role.

![single owner](evidence/after-rbac-single-owner.png)

CIS Control: 1.1 | Severity: Medium

**Scope limitation:** Service principal credential review was not performed for this assessment. App Registration creation is restricted at the tenant level under the Azure for Students subscription type, which sits inside UTD's institutional Azure AD tenant rather than a standalone tenant. In a production environment, this control would cover credential rotation policy and detection of long-lived or unused service principal secrets.

---

## Activity Logging

The subscription's Activity Log diagnostic setting was configured to export only the "Administrative" category to storage, leaving Security, Policy, ServiceHealth, and Alert events unexported. The CIS benchmark requires full-category logging — a partial export creates a blind spot where security-relevant events (like policy changes or triggered alerts) aren't retained anywhere queryable.

![partial logging](evidence/before-incomplete-diagnostic-logging.png)

CIS Control: 5.1.1 | Severity: Medium

---

## Preventive Policy Enforcement

Manually remediating a finding fixes the resource that already exists — it doesn't stop the same misconfiguration from being created again tomorrow. To address that, I authored two custom Azure Policy definitions with Deny effect:

- **`deny-public-blob-access`** — blocks any storage account from being created or updated with public blob access enabled
- **`deny-open-management-ports`** — blocks any NSG rule allowing inbound SSH (22) or RDP (3389) from an unrestricted source

Both policies were tested by deliberately attempting to violate them via Azure CLI rather than just assuming they'd work. Both attempts were rejected by Azure with `RequestDisallowedByPolicy`.

![storage policy test](evidence/after-policy-deny-storage-test.png)
![ports policy test](evidence/after-policy-deny-ports-test.png)

Policy definitions: [`/policies`](./policies)

---

## Remediation Automation

To move past one-off manual fixes, I wrote a Bash/Azure CLI script (`remediate.sh`) that scans a resource group for the exact misconfiguration patterns identified in this assessment and remediates them automatically — disabling public storage access, enforcing secure transfer, and removing open NSG management-port rules. Over-privileged role assignments are flagged for manual review rather than auto-removed, since RBAC changes carry enough risk that they shouldn't be handled by an unattended script.

To validate the script independently of the Deny policy, I temporarily disabled the storage policy, re-introduced the public access misconfiguration via CLI, and ran the script against the resource group. It detected and corrected the finding without manual intervention.

![script output](evidence/after-remediation-script-output.png)

---

## Results

| Metric | Before | After |
|---|---|---|
| Secure Score | 4% | [X]% |
| High/Critical findings | [X] | [X] |
| Findings remediated | — | [X] of [X] |
| Preventive policies deployed and tested | 0 | 2 |

![baseline score](evidence/before-securescore-baseline-4percent.png)
![final score](evidence/after-securescore-final.png)

---

## Lessons Learned

Most of the findings in this assessment came from Azure's permissive defaults rather than an obviously bad decision — public blob access and unrestricted NSG rules can both be left in place during initial resource creation without any warning at the time. That pushed me toward building the Deny policies instead of stopping at manual remediation: a fix only protects the resource that already exists, while a preventive control protects every resource created after it.

Testing the remediation script also surfaced something I didn't plan for. When I tried to re-trigger the storage misconfiguration with the Deny policy still active, Azure blocked my own test command — the policy was already enforcing the exact condition the script was built to catch. I had to temporarily disable the policy to actually exercise the script. In hindsight, that's a real example of defense-in-depth: the preventive control closed the gap before the detective/corrective layer was ever needed, which is the order you'd want those controls to work in a production environment.

The clearest gap in this assessment was scope, not technique — Azure for Students restricts tenant-level operations like App Registration creation, so the service principal credential finding couldn't be assessed. I documented that limitation directly rather than working around it, which is closer to how a real engagement handles access constraints than pretending the gap doesn't exist.
