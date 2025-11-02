> **Platform Name**: Huntress CTF 2025
> **Category**: #Malware, #Deofuscation, #PHP
> **Date**: 10-11-2025
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Static Analysis](#static%20analysis)
4. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
5. [Lessons Learned](#lessons%20learned)
6. [References](#References)

---
## Introduction

**Description:**
"Oh great, another phishing kit. This has some functionality to even send stolen data over email! Can you track down the email address they send things to?"

---
## Setup

- **Operating System:** MacOS
- **Tools Used:** #VSCode , #browser 

---
## Static Analysis

### Initial Scanning
Perform and explain any initial scans to discover open ports and services.

```bash
# Example: Nmap Scan
nmap -sC -sV -oN initial_scan.txt [Target IP]
```

**Findings:**
- **`Port Number`**: `Service/Version`

---
## Enumeration

### Web Enumeration (if applicable)
Detail steps for exploring web interfaces, directories, or vulnerabilities.

```bash
# Example: Directory brute-forcing
gobuster dir -u http://[Target IP] -w /path/to/wordlist
```

**Interesting Discoveries:**
- **Discovery**: Description

---
## Exploitation

### Vulnerability Identification
Explain the vulnerabilities found and how they can be exploited.

**Exploitation Steps:**
1. Describe the process
2. Add commands or tools used

```bash
# Example: Exploiting a known vulnerability
python exploit.py -t [Target IP]
```

---
## Privilege Escalation

### Enumerating for Privilege Escalation
Detail how privilege escalation was achieved. Mention any tools or manual checks used.

```bash
# Example: Checking for sudo permissions
sudo -l
```

**Steps to Escalate Privileges:**
1. Describe the process
2. Add commands or tools used

---
## Post-Exploitation/Flag
### Capturing the Flag
Mention the location and method used to capture the flag(s).
```bash
# Example: Reading the flag
cat /root/flag.txt
```

> [!success] Flag
> `Enter the Flag Here`

---
## Lessons Learned
Reflect on what you learned during the challenge or walkthrough. Highlight new tools, techniques, or approaches.

---
## References
- Links to any tools, scripts, or write-ups referenced
- Any additional resources or documentation

---
**Disclaimer** 
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.