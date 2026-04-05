> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Linux, #Networking
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
Identify which port the `santa_tracker` process is currently listening on after gnomes changed it from the expected port 8080, then connect to verify the service is running.

**Description:**
The neighborhood's Santa-tracking service was tampered with by mischievous gnomes. The service was originally configured on port 8080 but has been moved to an unknown port. The `ss` tool is used to identify the new port, and `curl` is used to verify the service.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #ss, #curl

---
## Enumeration

### Discovering the Listening Port
Use `ss` to list all listening TCP ports and identify the `santa_tracker` process.

```bash
ss -tnlp
```

**Findings:**
```
State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
LISTEN  0       5             0.0.0.0:12321       0.0.0.0:*
```

- **Port `12321`**: The `santa_tracker` process has been moved here from port 8080.

---
## Post-Exploitation/Flag

### Capturing the Flag
Connect to the discovered port to verify the service and retrieve the tracking data.

```bash
curl 127.0.0.1:12321
```

The service responds with a JSON payload confirming Santa's current location, speed, altitude, and delivery stats.

> [!success] Flag
> Port `12321` — Santa tracker successfully connected

---
## Lessons Learned

- **`ss -tlnp` over `netstat`**: `ss` is the modern replacement for `netstat` on Linux systems. The `-t` (TCP), `-l` (listening), `-n` (numeric), `-p` (process) flags together give a complete picture of which processes are bound to which ports.
- **Port changes as a persistence/evasion tactic**: Moving a service off its expected port can delay detection. Enumerating all listening ports rather than checking only expected ones is an important habit.
- **`curl` for quick service verification**: A simple `curl` to a discovered port is a fast way to confirm what service is running and get an initial response without needing a full browser.

---
## References
- [Linux `ss` man page](https://man7.org/linux/man-pages/man8/ss.8.html)
- [ss vs netstat – Red Hat](https://www.redhat.com/en/blog/ss-vs-netstat)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
