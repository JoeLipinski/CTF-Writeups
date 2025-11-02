> **Platform Name**: CTF Challenge
> **Category**: #Forensics #Cryptography #Memory
> **Difficulty**: Hard
> **Date**: October 14, 2025
> **Author**: Joe Lipinski

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

**Objective:**
Analyze a Windows memory dump to extract encryption keys and decrypt an encrypted flag file. This challenge combines memory forensics, cryptographic analysis, and reverse engineering skills.

**Description:**
The challenge provides three files:
- `memdump.dmp` - A Windows 10 memory dump (captured 2025-09-28 04:42:02 UTC)
- `flag.enc` - An encrypted file containing the flag (208 bytes)
- `memory_strings.txt` - Pre-extracted strings from the memory dump

The goal is to find the decryption key hidden in the memory dump and decrypt the flag file.

---
## Setup

- **Operating System:** macOS (any Unix-like system with Python 3)
- **Tools Used:** 
  - #Volatility3 (memory forensics framework)
  - #Python3 with PyCryptodome library
  - #OpenSSL (cryptographic operations)
  - Standard Unix utilities: `strings`, `grep`, `hexdump`
- **Files Provided:**
  - `memdump.dmp` (Windows memory dump)
  - `flag.enc` (encrypted flag file)
  - `memory_strings.txt` (1.7M lines)

```bash
# Install required Python libraries
pip install pycryptodome

# Verify Volatility3 is available (if using)
vol --version
```

---
## Reconnaissance

### Initial File Analysis

First, examine the provided files to understand what we're working with:

```bash
# Check file sizes and types
ls -lh
file memdump.dmp flag.enc

# Examine the encrypted flag file
hexdump -C flag.enc | head -20
```

**Key Observations:**
- `flag.enc` is 208 bytes of binary data
- Starts with bytes: `47 03 54 30 61 ad 8b 4f...`
- No obvious file signature or header

### Memory Dump Analysis (Optional - Using Volatility3)

If you have Volatility3 available, you can analyze the memory dump:

```bash
# Identify the OS profile
vol -f memdump.dmp windows.info

# List running processes
vol -f memdump.dmp windows.pslist
```

**Findings:**
- **Windows 10 Build 26100**
- **BackupHelper.exe** (PID 2132) - Suspicious encryption-related process
- **PowerShell** (PID 5920) - Likely ran the BackupHelper program

---
## Enumeration

### Step 1: Search Memory Strings for Encryption Clues

The provided `memory_strings.txt` file contains all strings extracted from the memory dump. Search for encryption-related keywords:

```bash
# Look for encryption-related strings
grep -i "encrypt\|decrypt\|key\|aes\|rsa" memory_strings.txt | head -50

# Search for file references
grep -i "flag\|backup\|helper" memory_strings.txt | head -30
```

**Key Discoveries:**
1. References to `BackupHelper.exe` and `BackupHelper.cs`
2. Mentions of `DECRYPT_PRIVATE_KEY.zip`
3. Log messages: "BackupHelper started: 2025-09-28T04:41:52.5463814Z"
4. Evidence of AES-CTR encryption: `;varoutput=aes.ctr.decrypt`

### Step 2: Extract ZIP Archive from Memory

The memory strings revealed a ZIP file containing decryption keys. Search for the ZIP file signature in the memory dump:

```bash
# Dump the BackupHelper process memory (if using Volatility)
vol -f memdump.dmp windows.memmap --pid 2132 --dump

# Search for ZIP signature in the dumped memory
grep -abo "PK" pid.2132.dmp | head -20
```

Create a Python script to extract the ZIP file:

```python
#!/usr/bin/env python3

# Read the process memory dump
with open('pid.2132.dmp', 'rb') as f:
    data = f.read()

# Find ZIP file signature (PK)
pk_offset = data.find(b'PK\x03\x04')
print(f"Found ZIP at offset: 0x{pk_offset:08x}")

# ZIP files end with "PK\x05\x06" (end of central directory)
end_offset = data.find(b'PK\x05\x06', pk_offset)
if end_offset != -1:
    # Include the end-of-central-directory record (22 bytes minimum)
    end_offset += 22
    
    zip_data = data[pk_offset:end_offset]
    
    with open('DECRYPT_PRIVATE_KEY.zip', 'wb') as out:
        out.write(zip_data)
    
    print(f"Extracted {len(zip_data)} bytes to DECRYPT_PRIVATE_KEY.zip")
```

**Results:**
- ZIP file found at offset `0x00004000`
- Extracted 1938 bytes to `DECRYPT_PRIVATE_KEY.zip`
- ZIP is password-protected

### Step 3: Find ZIP Password

Search the memory strings for the ZIP password:

```bash
# The ZIP password is likely stored in memory near the ZIP file reference
grep -B 5 -A 5 "DECRYPT_PRIVATE_KEY" memory_strings.txt

# Search for password patterns (alphanumeric strings)
grep -E '^[a-zA-Z0-9]{16}$' memory_strings.txt | head -20
```

**Password Found:** `ePDaACdOCwaMiYDG`

```bash
# Extract ZIP contents
unzip -P ePDaACdOCwaMiYDG DECRYPT_PRIVATE_KEY.zip
```

**ZIP Contents:**
- `private.pem` - RSA private key (1708 bytes)
- `key.enc` - RSA-encrypted symmetric key material (256 bytes)

---

## Exploitation

### Step 1: Decrypt the RSA-Encrypted Key

The `key.enc` file contains symmetric key material encrypted with RSA. Try decrypting it:

```bash
# First attempt: PKCS1 padding (WRONG - but commonly tried first)
openssl pkeyutl -decrypt -inkey private.pem -in key.enc \
    -out key_pkcs1.bin -pkeyopt rsa_padding_mode:pkcs1

hexdump -C key_pkcs1.bin
# Result: 44 bytes (32-byte key + 12-byte nonce)
# This is INCORRECT - 12 bytes is unusual for standard AES modes
```

**Critical Insight:** The 44-byte result (32+12) is a red flag. Standard AES modes use:
- **CBC:** 16-byte IV
- **GCM:** 12-byte nonce + 16-byte tag
- **CTR:** 8 or 16-byte nonce

The correct approach uses **RSA-OAEP padding**:

```bash
# Correct decryption: OAEP padding
openssl pkeyutl -decrypt -inkey private.pem -in key.enc \
    -out key_oaep.bin -pkeyopt rsa_padding_mode:oaep

hexdump -C key_oaep.bin
```

**Results:**
- **48 bytes** decrypted successfully
- Format: 32-byte AES-256 key + 16-byte IV
- Key: `289ea58a38549d5faf7a97a6dd19cdf2ddc0496a8a64f99a77c643529c94b804`
- IV: `2c6a55b0a89141056517687a977305d6`

### Step 2: Decrypt the Flag File

Now that we have the correct key material (32-byte key + 16-byte IV), decrypt the flag:

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES

# Read the OAEP-decrypted key material
with open('key_oaep.bin', 'rb') as f:
    data = f.read()

key = data[:32]  # 32 bytes for AES-256
iv = data[32:]   # 16 bytes for CBC mode

print(f"Key (32 bytes): {key.hex()}")
print(f"IV (16 bytes): {iv.hex()}")

# Read the encrypted flag
with open('flag.enc', 'rb') as f:
    encrypted_data = f.read()

# Decrypt using AES-256-CBC
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
decrypted = cipher.decrypt(encrypted_data)

# Remove PKCS7 padding
pad_len = decrypted[-1]
if pad_len <= 16 and pad_len > 0:
    unpadded = decrypted[:-pad_len]
    result = unpadded.decode('utf-8')
    print("\n" + "="*70)
    print("SUCCESS!")
    print("="*70)
    print(result)
```

**Alternative: Using OpenSSL**

```bash
# Extract key and IV to separate files
dd if=key_oaep.bin of=aes_key.bin bs=1 count=32
dd if=key_oaep.bin of=aes_iv.bin bs=1 skip=32 count=16

# Decrypt using OpenSSL
openssl enc -d -aes-256-cbc -in flag.enc -out flag.txt \
    -K $(xxd -p -c 32 aes_key.bin) \
    -iv $(xxd -p -c 16 aes_iv.bin)

cat flag.txt
```

---
## Post-Exploitation/Flag

### Capturing the Flag

Running the decryption script successfully reveals:

```
=== CONFIDENTIAL RECOVERY ===
Note: This file contains the recovered data for decryption.
-----------------------------
FLAG:
flag{fa838fa9823e5d612b25001740faca31}
-----------------------------
```

> [!success] Flag
> `flag{fa838fa9823e5d612b25001740faca31}`

---
## Lessons Learned

### Key Takeaways

1. **RSA Padding Matters**
   - Always try both PKCS1 and OAEP padding when decrypting RSA-encrypted data
   - OAEP is more secure and increasingly common in modern implementations
   - Different padding schemes produce different plaintext lengths
   - A 44-byte result from PKCS1 was a clue that the padding was wrong

2. **Memory Forensics Workflow**
   - Start with `strings` extraction - it's fast and often sufficient
   - Look for process-specific artifacts (log files, config data)
   - Suspicious process names like "BackupHelper" warrant deeper investigation
   - Process memory dumps (`windows.memmap`) contain more detail than full dumps

3. **Cryptographic Analysis**
   - Don't assume the encryption scheme - verify with evidence
   - Standard key/IV sizes are hints: 
     - 32 bytes = AES-256 key
     - 16 bytes = CBC IV
     - 12 bytes = GCM nonce
   - Test multiple modes systematically when uncertain

4. **Binary File Extraction from Memory**
   - Use file signatures (magic bytes) to locate embedded files
   - For ZIP files: `PK\x03\x04` (start) and `PK\x05\x06` (end)
   - Account for full file structure including headers and footers

5. **Password Discovery**
   - Passwords are often stored in plaintext in memory
   - Search near related artifacts (file names, log messages)
   - Try pattern matching for common formats (16-char alphanumeric, etc.)

### Common Pitfalls (That We Encountered)

1. **False Leads**
   - Initial "cryptography.fernet" strings led to wasted effort testing Fernet
   - Malware signatures in memory can be misleading
   - Always verify encryption type with multiple sources of evidence

2. **Incorrect Padding Assumptions**
   - PKCS1 gave 44 bytes which seemed plausible but was wrong
   - The unusual 12-byte "nonce" should have been a red flag earlier
   - Test both PKCS1 and OAEP before attempting decryption

3. **Overcomplicating the Solution**
   - Tried complex CTR counter configurations unnecessarily
   - The solution was simpler: correct RSA padding + standard CBC mode

### Tools and Techniques for Future CTFs

**Essential Tools:**
```bash
# Memory forensics
volatility3
strings + grep

# Cryptography
openssl
python3 + PyCryptodome

# Binary analysis
hexdump / xxd
file
binwalk (for finding embedded files)
```

**Python Libraries:**
```python
# Essential for CTF crypto challenges
from Crypto.Cipher import AES, DES, DES3  # Symmetric encryption
from Crypto.PublicKey import RSA           # Asymmetric keys
from Crypto.Util.Padding import pad, unpad # Padding helpers
from Crypto.Hash import SHA256, MD5        # Hashing
import base64                               # Encoding
```

**Systematic Approach to Unknown Encryption:**

1. **Identify the scheme:**
   - File sizes (ciphertext = plaintext + padding/overhead)
   - Key/IV lengths in memory
   - Library imports or function names

2. **Test RSA padding modes:**
   ```bash
   # Try both
   openssl pkeyutl ... -pkeyopt rsa_padding_mode:pkcs1
   openssl pkeyutl ... -pkeyopt rsa_padding_mode:oaep
   ```

3. **Test AES modes systematically:**
   - CBC (most common, needs IV)
   - GCM (authenticated, needs nonce + tag)
   - CTR (streaming, needs nonce/counter)
   - ECB (insecure, no IV needed)

4. **Handle padding:**
   - PKCS7 is standard (Python: `unpad(data, AES.block_size)`)
   - Last byte indicates padding length
   - Manual removal: `data[:-data[-1]]`

### Quick Reference Commands

```bash
# Extract strings from memory dump
strings -a -t d memdump.dmp > memory_strings.txt

# Search for patterns
grep -abo "pattern" file.bin          # Binary search with offset
grep -E '^.{16}$' strings.txt         # Regex for exact length

# Dump process memory (Volatility3)
vol -f dump.dmp windows.memmap --pid PID --dump

# RSA decryption (try both paddings)
openssl pkeyutl -decrypt -inkey priv.pem -in enc.bin \
    -pkeyopt rsa_padding_mode:oaep -out dec.bin

# AES-CBC decryption
openssl enc -d -aes-256-cbc -in enc.bin -out dec.txt \
    -K $(xxd -p key.bin) -iv $(xxd -p iv.bin)

# Examine binary files
hexdump -C file.bin | head -20        # Hex viewer
xxd file.bin | head -20                # Alternative hex viewer
file file.bin                          # Identify file type
```

---
## References

### Tools
- **Volatility3**: https://github.com/volatilityfoundation/volatility3
  - Memory forensics framework for extracting digital artifacts
- **PyCryptodome**: https://pycryptodome.readthedocs.io/
  - Python cryptography library
- **OpenSSL**: https://www.openssl.org/docs/
  - Cryptographic toolkit
### Techniques
- **RSA Padding Schemes**: 
  - PKCS#1 v1.5: https://datatracker.ietf.org/doc/html/rfc2313
  - OAEP: https://datatracker.ietf.org/doc/html/rfc2437
- **AES Modes of Operation**: 
  - NIST SP 800-38A: https://csrc.nist.gov/publications/detail/sp/800-38a/final
- **Memory Forensics**:
  - "The Art of Memory Forensics" by Michael Hale Ligh et al.
### CTF Resources
- **CryptoHack**: https://cryptohack.org/ - Learn cryptography through challenges
- **Memory Forensics Training**: https://www.memoryanalysis.net/

---

**Disclaimer** 
This write-up is for educational purposes only. The techniques described should only be used in authorized CTF competitions, penetration testing engagements, or personal learning environments. Always obtain proper authorization before testing or exploiting any system.