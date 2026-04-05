> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Cloud, #Azure, #Networking
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Enumeration](#enumeration)
4. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
5. [Lessons Learned](#lessons%20learned)
6. [References](#References)

---
## Introduction

**Objective:**
Enumerate Azure Network Security Groups (NSGs) to identify a suspicious inbound rule that exposes a sensitive port to the public internet.

**Description:**
Using Azure CLI, enumerate resource groups, list all NSGs, and review their security rules to find a misconfigured rule that allows unrestricted inbound access to a sensitive service port from the entire internet (`0.0.0.0/0`).

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #AzureCLI

---
## Enumeration

### List Resource Groups
```bash
az group list -o table
```

**Findings:**
- `theneighborhood-rg1` — eastus
- `theneighborhood-rg2` — westus

### List Network Security Groups
```bash
az network nsg list -o table
```

**Findings:**
- `nsg-web-eastus` — theneighborhood-rg1
- `nsg-db-eastus` — theneighborhood-rg1
- `nsg-dev-eastus` — theneighborhood-rg2
- `nsg-mgmt-eastus` — theneighborhood-rg2
- `nsg-production-eastus` — theneighborhood-rg1

### Inspect NSG Rules
Review each NSG for suspicious rules. The production NSG stands out:

```bash
az network nsg show --name nsg-production-eastus --resource-group theneighborhood-rg1
```

**Finding:** `Allow-RDP-From-Internet` — allows port `3389/tcp` inbound from `0.0.0.0/0` (any source). This is a critical misconfiguration — RDP exposed to the public internet.

### Confirm the Suspicious Rule
```bash
az network nsg rule show --name Allow-RDP-From-Internet --nsg-name nsg-production-eastus --resource-group theneighborhood-rg1
```

```json
{
  "name": "Allow-RDP-From-Internet",
  "properties": {
    "access": "Allow",
    "destinationPortRange": "3389",
    "direction": "Inbound",
    "priority": 120,
    "protocol": "Tcp",
    "sourceAddressPrefix": "0.0.0.0/0"
  }
}
```

---
## Post-Exploitation/Flag

### Capturing the Flag
The suspicious rule is the flag:

> [!success] Flag
> NSG rule `Allow-RDP-From-Internet` on `nsg-production-eastus` — RDP (port 3389) exposed to `0.0.0.0/0`

---
## Lessons Learned

- **RDP should never be open to `0.0.0.0/0`**: Exposing port 3389 to the entire internet invites brute-force and credential-stuffing attacks. RDP should be locked to specific IPs, routed through Azure Bastion, or protected by a VPN.
- **NSG audit as a routine security check**: Reviewing all NSG rules across all resource groups is a standard cloud security assessment step. Look for `sourceAddressPrefix: "*"` or `"0.0.0.0/0"` on sensitive ports (22, 3389, 1433, 3306, etc.).
- **`az network nsg list` + `az network nsg show`**: These two commands are the fastest path to a full NSG audit. Combine with `-o table` and JMESPath `--query` filters to speed up review.
- **Priority ordering matters**: NSG rules are evaluated in priority order (lower number = higher priority). A permissive rule at priority 120 beats a deny-all at priority 4096.

---
## References
- [Azure NSG overview – Microsoft Docs](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [Azure Bastion – Microsoft Docs](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview)
- [CIS Azure Benchmark – NSG controls](https://www.cisecurity.org/benchmark/azure)
- [MITRE ATT&CK T1021.001 – Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
