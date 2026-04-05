> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Forensics, #Steganography
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
Analyze a floppy disk image from a retro system to recover a hidden message encoded in Base64.

**Description:**
Mark Divito provides a `floppy.img` file connected to an old QuickBASIC environment. The challenge involves careful handling of the image file — mounting it on macOS corrupted the data — and ultimately recovering a Base64-encoded string hidden within the image using `strings`.

---
## Setup

- **Operating System:** Kali / macOS
- **Tools Used:** #strings, #base64, #pcjs

---
## Enumeration

### Initial Examination
After downloading `floppy.img`, an initial attempt to mount it on macOS revealed several `.exe` files and QuickBASIC-related files — nothing immediately useful.

A second approach used the browser-based PC emulator at `https://www.pcjs.org/software/pcx86/sys/windows/3.10/` to run the image in a proper DOS/Windows 3.1 environment.

### Running `strings`
```bash
strings floppy.img
```

**Important note:** Mounting the image on macOS modified the file, removing some strings. The image must be analyzed on Linux or inspected directly with `strings` without mounting to preserve data integrity.

**Interesting Discoveries:**
- A Base64-encoded string near the title card area of the image

---
## Exploitation

### Decoding the Base64 String
The Base64 string found in the image was decoded:

```bash
echo "<base64_string>" | base64 -d
```

---
## Post-Exploitation/Flag

### Capturing the Flag
Decoding the Base64 string reveals the hidden message:

> [!success] Flag
> `merry christmas to all and to all a good night`

---
## Lessons Learned

- **macOS filesystem mounting can alter disk images**: macOS may write hidden files (`.DS_Store`, spotlight indexes, etc.) or modify existing data when mounting foreign filesystem images. Always analyze disk images on Linux or use read-only mount flags (`-o ro`) to preserve forensic integrity.
- **`strings` is a first-pass forensic tool**: Running `strings` on a binary or disk image quickly surfaces human-readable data that might otherwise require deeper analysis.
- **Base64 near title cards**: Retro challenges often embed secrets in the data regions of disk images. Looking near known fixed-location data (title screens, headers) is a good heuristic.
- **Browser-based emulators for retro forensics**: `pcjs.org` provides a convenient way to run old DOS and Windows environments without setting up a full VM.

---
## References
- [PCjs Machines – pcjs.org](https://www.pcjs.org/)
- [Linux `strings` man page](https://linux.die.net/man/1/strings)
- [Base64 encoding – Wikipedia](https://en.wikipedia.org/wiki/Base64)
- [MITRE ATT&CK T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
