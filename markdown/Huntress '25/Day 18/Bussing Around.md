
> **Platform Name**: CTF Challenge
> **Category**: #Forensics #ICS #SCADA #Modbus
> **Difficulty**: Medium
> **Date**: October 18, 2025
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
Extract a hidden flag from Modbus/TCP traffic captured in a PCAP file from an Industrial Control System (ICS) environment.

**Description:**
An engineer noticed that an HMI (Human-Machine Interface) was behaving abnormally and captured network traffic. The traffic appears to be gibberish, but some of it originates from someone's computer rather than legitimate PLC traffic. Our goal is to analyze the Modbus protocol communications and extract the hidden data.

**Challenge Prompt:**
```
One of the engineers noticed that an HMI was going haywire.

He took a packet capture of some of the traffic but he can't make any sense of it... 
it just looks like gibberish!

For some reason, some of the traffic seems to be coming from someone's computer. 
Can you help us figure out what's going on?
```

**Flag Format:** `flag{[32 hex characters]}`

---
## Setup

- **Operating System:** macOS (any Linux distribution with TShark works)
- **Tools Used:** 
  - #TShark (Wireshark CLI tool)
  - #Python3
  - Standard Unix utilities (unzip, cat)
- **Files Provided:** `bussing_around.pcapng`

```bash
# Verify TShark is installed
tshark --version

# Verify Python3 is available
python3 --version
```

---
## Reconnaissance

### Initial PCAP Analysis
First, we need to understand what's in the PCAP file and identify the communication patterns.

```bash
# Check basic statistics about the capture
tshark -r bussing_around.pcapng -q -z io,phs

# View TCP conversations
tshark -r bussing_around.pcapng -q -z conv,tcp
```

**Findings:**
- **Single TCP Stream**: `172.20.10.6:55995 <-> 172.20.10.2:502`
- **Port 502**: Standard Modbus/TCP port
- **16,906 total frames** with approximately 1.2 MB of data
- Traffic duration: ~2.16 seconds

### Modbus Traffic Overview
```bash
# View sample Modbus packets
tshark -r bussing_around.pcapng -Y "modbus" | head -20
```

**Key Observations:**
- Modbus Function Code 6: Write Single Register
- Modbus Function Code 5: Write Single Coil
- Traffic is from `172.20.10.6` (attacker's computer) to `172.20.10.2` (PLC/HMI)
- Multiple Unit IDs in use: 3, 6, 12, 38

---
## Enumeration

### Identifying Modbus Unit IDs
Different Modbus unit IDs may contain different parts of the hidden data.

```bash
# Count packets by unit ID
tshark -r bussing_around.pcapng -Y "modbus" -T fields -e mbtcp.unit_id | sort | uniq -c
```

**Results:**
- **Unit 3**: 2,240 packets (Function Code 6 - Write Register)
- **Unit 6**: 2,274 packets (Function Code 6 - Write Register)
- **Unit 12**: 2,224 packets (Function Code 5 - Write Coil)
- **Unit 38**: 4,528 packets (Function Code 6 - Write Register) ⚠️ **Twice as many!**

### Analyzing Each Unit ID

#### Unit 38 - The Suspicious Unit
Unit 38 has exactly twice as many packets as the others, suggesting data duplication.

```bash
# Extract register values from Unit 38
tshark -r bussing_around.pcapng -Y "modbus.func_code == 6 && mbtcp.unit_id == 38" \
  -T fields -e modbus.regval_uint16 | head -20
```

**Discovery:** Values are either 0 or 1, and each value appears twice consecutively!
```
0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1...
```

This is a **bitstream** where each bit is duplicated.

#### Unit 3 - Base64-like Data
```bash
# Extract register values from Unit 3
tshark -r bussing_around.pcapng -Y "modbus.func_code == 6 && mbtcp.unit_id == 3" \
  -T fields -e modbus.regval_uint16 | head -20
```

**Discovery:** Values like 63, 79, 64, 43, 66, 78 appear twice. When converted to ASCII:
- 63 = '?', 79 = 'O', 64 = '@', 43 = '+', 66 = 'B', 78 = 'N'
- Pattern: `?O@+BNO...` resembles Base64 encoding

#### Unit 6 - Control Characters
Contains mostly non-printable characters with occasional `~` and `}` characters.

#### Unit 12 - Coil Data
Uses Function Code 5 (Write Single Coil) with values `ff00` (ON) and `0000` (OFF).

---
## Exploitation

### Method 1: Analyzing Unit 3 (Dead End)
Initially attempted to decode Unit 3 as Base64:

```bash
tshark -r bussing_around.pcapng -Y "modbus.func_code == 6 && mbtcp.unit_id == 3" \
  -T fields -e modbus.regval_uint16 | python3 -c "
import sys
import base64
values = [int(line.strip()) for line in sys.stdin if line.strip()]
# Take every other value (skip duplicates)
unique_vals = values[::2]
data = ''.join(chr(v) for v in unique_vals)
decoded = base64.b64decode(data)
print(decoded.decode('latin-1'))
"
```

**Result:** Binary data, but no flag found. This was a decoy or additional layer.

### Method 2: Extracting ZIP File from Unit 38 (Success!)

#### Step 1: Extract the Bitstream
```bash
tshark -r bussing_around.pcapng \
  -Y "modbus.func_code == 6 && mbtcp.unit_id == 38" \
  -T fields -e modbus.regval_uint16 | python3 -c "
import sys
values = [int(line.strip()) for line in sys.stdin if line.strip()]
# Take every other value to remove duplicates
unique_vals = values[::2]
bit_string = ''.join(str(v) for v in unique_vals)
# Convert bits to bytes
byte_data = bytearray()
for i in range(0, len(bit_string) - 7, 8):
    byte = bit_string[i:i+8]
    byte_data.append(int(byte, 2))
# Save to file
with open('extracted.zip', 'wb') as f:
    f.write(byte_data)
print('Saved', len(byte_data), 'bytes to extracted.zip')
"
```

**Output:** `Saved 283 bytes to extracted.zip`

#### Step 2: Verify ZIP File
```bash
# Check if it's a valid ZIP file
file extracted.zip
```

**Result:** `extracted.zip: Zip archive data, at least v1.0 to extract`

#### Step 3: Examine ZIP Contents
```bash
# List contents without extracting
unzip -l extracted.zip
```

**Discovery:** 
- Contains `flag.txt`
- ZIP comment reveals password: `The password is 5939f3ec9d820f23df20948af09a5682`

#### Step 4: Extract with Password
```bash
unzip -P 5939f3ec9d820f23df20948af09a5682 extracted.zip
```

**Success!** File `flag.txt` extracted.

---
## Post-Exploitation/Flag

### Capturing the Flag
```bash
cat flag.txt
```

> [!success] Flag
> `flag{4d2a66c5ed8bb8cd4e4e1ab32c71f7a3}`

### Complete Solution Script

For future reference, here's a complete Python script to extract the flag:

```python
#!/usr/bin/env python3
import subprocess
import sys

# Extract bitstream from Unit 38
cmd = "tshark -r bussing_around.pcapng -Y 'modbus.func_code == 6 && mbtcp.unit_id == 38' -T fields -e modbus.regval_uint16"
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
values = [int(line.strip()) for line in result.stdout.strip().split('\n') if line.strip()]

# Remove duplicates (take every other value)
unique_vals = values[::2]

# Convert to bitstring
bit_string = ''.join(str(v) for v in unique_vals)

# Convert bits to bytes
byte_data = bytearray()
for i in range(0, len(bit_string) - 7, 8):
    byte = bit_string[i:i+8]
    byte_data.append(int(byte, 2))

# Save ZIP file
with open('extracted.zip', 'wb') as f:
    f.write(byte_data)

print(f"[+] Extracted {len(byte_data)} bytes to extracted.zip")
print("[+] Password found in ZIP comment: 5939f3ec9d820f23df20948af09a5682")
print("[+] Extract with: unzip -P 5939f3ec9d820f23df20948af09a5682 extracted.zip")
```

---
## Lessons Learned

### Key Takeaways

1. **Modbus Protocol Understanding**
   - Modbus/TCP uses port 502
   - Function Code 6: Write Single Register (holds 16-bit values)
   - Function Code 5: Write Single Coil (binary on/off)
   - Unit IDs can be used to multiplex different data streams

2. **Data Exfiltration via Industrial Protocols**
   - Attackers can abuse ICS protocols to hide data in plain sight
   - Modbus register writes can encode arbitrary data
   - Data duplication is a common technique to ensure reliability or evade detection

3. **Analysis Techniques**
   - Always enumerate ALL data sources (different unit IDs, function codes)
   - Look for patterns: duplicated values, unusual packet counts
   - Binary data often has magic numbers (e.g., `PK` for ZIP files)
   - Check for embedded metadata (ZIP comments, file headers)

4. **Tool Proficiency**
   - TShark is essential for automated PCAP analysis
   - Python is perfect for data transformation and decoding
   - Understanding file formats (ZIP, compression) helps identify hidden data

5. **Methodical Approach**
   - Don't get tunnel vision on the first promising lead
   - Unit 3 looked promising but was a red herring
   - Statistical analysis (packet counts) revealed Unit 38's importance
   - Always verify assumptions with data

### Common Pitfalls to Avoid

- ❌ Assuming the first "readable" data is the answer
- ❌ Ignoring duplicated values as redundancy
- ❌ Not checking all available data streams (unit IDs)
- ❌ Overlooking file format magic numbers (PK, GIF, PNG, etc.)
- ✅ Systematically enumerate all data sources
- ✅ Look for anomalies in packet counts or patterns
- ✅ Test multiple decoding methods (ASCII, Base64, binary, hex)

### Similar Challenge Patterns

This technique appears in challenges involving:
- **DNS Tunneling**: Data hidden in DNS queries/responses
- **ICMP Tunneling**: Payloads in ping packets
- **HTTP Header Smuggling**: Data in custom headers
- **Steganography**: Files hidden in images or audio
- **Protocol Abuse**: Any protocol can be misused for data exfiltration

---
## References

### Tools
- [TShark Documentation](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
- [Python3 Documentation](https://docs.python.org/3/)

### Modbus Protocol
- [Modbus Protocol Specification](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [Modbus Function Codes](https://www.simplymodbus.ca/FAQ.htm)
- [Industrial Control Systems Security](https://www.cisa.gov/ics)

### Similar Writeups
- [The Magic Modbus CTF Writeup](https://notcicada.medium.com/write-up-the-magic-modbus-2692eaf5ee73) - Inspired our approach
- [SCADA CTF Challenges](https://github.com/topics/scada-security)

### Additional Resources
- [ICS/SCADA Security Best Practices](https://www.sans.org/white-papers/36297/)
- [Modbus Security Extensions](https://modbus.org/docs/MB-TCP-Security-v21_2018-07-24.pdf)

---
**Disclaimer** 
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system. Industrial Control Systems are critical infrastructure and should never be tested without explicit permission.

---
**Tags:** #Modbus #ICS #SCADA #Forensics #NetworkAnalysis #TShark #Python #DataExfiltration #CTF