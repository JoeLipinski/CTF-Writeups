> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Reconnaissance, #Networking
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Reconnaissance](#reconnaissance)
4. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
5. [Lessons Learned](#lessons%20learned)
6. [References](#References)

---
## Introduction

**Objective:**
Learn to use `nmap` for host and port discovery, including targeted scans, full-range port scans, range-based host scans, and service version detection.

**Description:**
A guided introductory challenge walking through core `nmap` techniques: default scans, full-port scans, host range scans, and service version fingerprinting. A secondary service is also discovered and connected to via `nc`.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #Nmap, #Netcat

---
## Reconnaissance

### Default Port Scan
```bash
nmap 127.0.12.25
```

**Findings:**
- **`8080/tcp`**: `http-proxy` — open

### Full Port Scan
```bash
nmap -p- 127.0.12.25
```

**Findings:**
- **`24601/tcp`**: `unknown` — open (was not found in default top-1000 scan)

### Host Range Scan
```bash
nmap 127.0.12.20-28
```

**Findings:**
- **`127.0.12.23`**: Port `8080/tcp` open — additional host in range with an exposed service

### Service Version Detection
```bash
nmap 127.0.12.25 -sV -p 8080
```

**Findings:**
- **`8080/tcp`**: `SimpleHTTPServer 0.6 (Python 3.10.12)`

---
## Post-Exploitation/Flag

### Capturing the Flag
Connect to the full-scan-discovered port `24601` using `nc`:

```bash
nc 127.0.12.25 24601
```

```
Welcome to the WarDriver 9000!
```

> [!success] Flag
> Service discovered on port `24601` — "Welcome to the WarDriver 9000!"

---
## Lessons Learned

- **Default nmap scans only cover the top 1000 ports**: Port `24601` was invisible in the default scan. Always follow up with `-p-` on interesting hosts to avoid missing non-standard services.
- **`-sV` for service fingerprinting**: Adding `-sV` to a targeted scan reveals the application and version behind a port, which is essential for identifying known vulnerabilities.
- **Host range scanning**: `nmap` accepts CIDR notation and dash-ranges for scanning subnets, enabling discovery of live hosts beyond the initial target.
- **`nc` for quick service interaction**: After discovering an open port, `nc` is the fastest way to send raw input and see what a service responds with before committing to a full exploitation path.

---
## References
- [Nmap reference guide](https://nmap.org/book/man.html)
- [Netcat man page](https://linux.die.net/man/1/nc)
- [MITRE ATT&CK T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
