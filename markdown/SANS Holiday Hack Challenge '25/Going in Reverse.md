> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #ReverseEngineering, #Cryptography
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
Reverse engineer a Commodore 64 BASIC program to decode an XOR-encrypted flag string.

**Description:**
Kevin directs you to a "Just a Basic Program" item containing a short C64 BASIC script. The script XORs each character of an encrypted flag string with the value `7`. Decoding the flag requires understanding the XOR operation and applying it in reverse using a tool like CyberChef.

---
## Setup
- **Operating System:** Kali
- **Tools Used:** #CyberChef

---
## Enumeration

### Analyzing the BASIC Script
The relevant lines from the program:

```basic
20 ENC_PASS$ = "D13URKBT"
30 ENC_FLAG$ = "DSA|auhts*wkfi=dhjwubtthut+dhhkfis+hnkz"
70 IF CHR$(ASC(MID$(PASS$,I,1)) XOR 7) <> MID$(ENC_PASS$,I,1) THEN GOTO 90
85 FLAG$ = "" : FOR I = 1 TO LEN(ENC_FLAG$) : FLAG$ = FLAG$ + CHR$(ASC(MID$(ENC_FLAG$,I,1)) XOR 7) : NEXT I : PRINT FLAG$
```

**Key observations:**
- The password check XORs each input character with `7` and compares it to `ENC_PASS$`
- The flag decryption loop (line 85) iterates over `ENC_FLAG$`, XORs each character's ASCII value with `7`, and prints the result
- The encryption/decryption are symmetric — XOR with `7` again to decrypt

---
## Exploitation

### Decoding with CyberChef
The decryption logic restructured:

```
For each character in ENC_FLAG$:
    output_char = ASCII(char) XOR 7
```

In CyberChef:
1. Input: `DSA|auhts*wkfi=dhjwubtthut+dhhkfis+hnkz`
2. Operation: **XOR** with key `7`, scheme: **Decimal**

The output reveals two potential flags — the comment in the source shows an older encrypted string, and the current `ENC_FLAG$` decodes to the active flag.

---
## Post-Exploitation/Flag

### Capturing the Flag
CyberChef XOR decode produces:

```
CTF{frost-plan:compressors,coolant,oil}
```

> [!success] Flag
> `CTF{frost-plan:compressors,coolant,oil}`

---
## Lessons Learned

- **XOR is a symmetric cipher**: XORing with the same key twice returns the original value. Any single-key XOR cipher is trivially reversible once the key is known.
- **Reading BASIC for reverse engineering**: Classic BASIC programs expose their logic completely — there's no compilation or obfuscation. Line numbers, `FOR`/`NEXT` loops, and `CHR$`/`ASC` functions map directly to character-level operations.
- **CyberChef for quick crypto operations**: The XOR recipe in CyberChef handles character-level XOR decoding without writing any code, making it the fastest tool for simple cipher reversals.
- **Comments in source reveal old values**: The `' old "DSA|qnisf..."` comment preserved the previous flag string — a good reminder that comments and version history can leak information.

---
## References
- [CyberChef – gchq.github.io](https://gchq.github.io/CyberChef/)
- [XOR cipher – Wikipedia](https://en.wikipedia.org/wiki/XOR_cipher)
- [Commodore 64 BASIC reference](https://www.c64-wiki.com/wiki/BASIC)
- [MITRE ATT&CK T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
