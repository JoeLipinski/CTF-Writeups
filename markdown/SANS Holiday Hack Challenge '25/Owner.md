> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Cloud, #Azure, #Enumeration
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
Enumerate Azure subscriptions and role assignments to identify which user holds an Owner-level permission through a chain of nested group memberships.

**Description:**
The challenge provides access to an Azure CLI session with multiple subscriptions. The goal is to trace Owner role assignments through nested Azure AD groups to identify the individual who has effective Owner access.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #AzureCLI

---
## Enumeration

### List All Subscriptions
```bash
az account list --query "[].name"
```

**Findings:**
- `theneighborhood-sub`
- `theneighborhood-sub-2`
- `theneighborhood-sub-3`
- `theneighborhood-sub-4`

Filter to only enabled subscriptions with IDs:
```bash
az account list --query "[?state=='Enabled'].{Name:name, ID:id}"
```

### Enumerate Owner Role Assignments Per Subscription
```bash
az role assignment list --scope "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64" --query "[?roleDefinitionName=='Owner']"
```

Subscription 1 has only a `PIM-Owners` group — confirmed PIM-enabled with no active activations. Safe.

Checking subscription 3 (`065cc24a-...`):
```bash
az role assignment list --scope "/subscriptions/065cc24a-077e-40b9-b666-2f4dd9f3a617" --query "[?roleDefinitionName=='Owner']"
```

**Finding:** An additional group `IT Admins` (ID: `6b982f2f-...`) has Owner on this subscription — not PIM-gated.

### Resolve Nested Group Membership
```bash
az ad group member list --group 6b982f2f-78a0-44a8-b915-79240b2b4796
```

Returns a nested group: `Subscription Admins` (ID: `631ebd3f-...`). Resolve further:

```bash
az ad group member list --group 631ebd3f-39f9-4492-a780-aef2aec8c94e
```

**Findings:**
- **`Firewall Frank`** (`frank.firewall@theneighborhood.onmicrosoft.com`) — HOA IT Administrator

---
## Post-Exploitation/Flag

### Capturing the Flag
The user with effective Owner access via nested group membership is:

> [!success] Flag
> `frank.firewall@theneighborhood.onmicrosoft.com`

---
## Lessons Learned

- **Nested group membership is a common privilege escalation path**: Azure RBAC evaluates transitive group membership. A user in a nested group inherits roles assigned to any parent group, which can be easy to overlook in audits.
- **PIM does not protect non-PIM assignments**: Only the `PIM-Owners` group had PIM controls. The `IT Admins` → `Subscription Admins` chain had standing (always-on) Owner access with no approval required.
- **JMESPath queries with `--query`**: The `az` CLI's `--query` flag supports JMESPath expressions, making it easy to filter large JSON responses directly in the shell.
- **Enumerate all subscriptions**: Checking only the default subscription misses assignments on other subscriptions in the same tenant.

---
## References
- [Azure RBAC overview – Microsoft Docs](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)
- [Azure PIM – Microsoft Docs](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
- [JMESPath query syntax – Azure CLI](https://learn.microsoft.com/en-us/cli/azure/query-azure-cli)
- [MITRE ATT&CK T1069.003 – Cloud Groups](https://attack.mitre.org/techniques/T1069/003/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
