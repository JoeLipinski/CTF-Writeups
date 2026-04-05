> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Web, #Networking
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
6. [Lessons Learned](#lessons%20learned)
7. [References](#References)

---
## Introduction

**Objective:**
Complete a visual networking challenge by inspecting and manipulating browser-level HTTP request properties, including User-Agent strings.

**Description:**
The challenge involves a web-based interface that requires knowledge of browser fingerprinting and HTTP headers. Screenshots guide the process of identifying the correct User-Agent string to satisfy the challenge's conditions.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #Browser, #BurpSuite

---
## Enumeration

### Reviewing the Challenge Interface
The challenge presents a series of visual prompts captured in screenshots:

- `SansHoliday25VisualNetworking1.png` — Initial challenge view
- `SansHoliday25VisualNetworking2.png` — Intermediate step
- `SansHoliday25VisualNetworking3.png` — User-Agent requirement revealed

### Identifying the Required User-Agent
The challenge requires submitting a request with a specific, up-to-date Chrome User-Agent string. The reference used was:

```
https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome
```

---
## Exploitation

### Crafting the Request
Using the current Chrome User-Agent string from the reference above, the request was crafted and submitted to satisfy the challenge condition. The remaining steps are captured in:

- `SansHoliday25VisualNetworking4.png`
- `SansHoliday25VisualNetworking5.png`

---
## Post-Exploitation/Flag

### Capturing the Flag
The flag was obtained after submitting the request with the correct User-Agent string.

---
## Lessons Learned

- **User-Agent strings are trivially spoofable**: Web applications that gate access based on User-Agent checks provide no real security — any client can send an arbitrary string.
- **Browser fingerprinting**: Sites can attempt to fingerprint clients via User-Agent, Accept headers, and other HTTP metadata. Understanding what these headers contain is useful for both offensive and defensive work.
- **`whatismybrowser.com`**: A quick reference for finding current, valid User-Agent strings when you need to impersonate a specific browser version.

---
## References
- [What is My Browser – Latest Chrome User-Agent](https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome)
- [MDN – User-Agent header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)
- [MITRE ATT&CK T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
