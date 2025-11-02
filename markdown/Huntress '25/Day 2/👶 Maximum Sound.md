> **Platform Name**: Huntress CTF 2025
> **Category**: #steganography, #QRCode, #audio
> **Date**: 10-03-2025
> **Author**: Joe Lipinski
---
## Table of Contents
1. [Introduction](#introduction)
2. [Setup](#Setup)
3. [Reconnaissance](#reconnaissance)
4. [Enumeration](#enumeration)
5. [Exploitation](#exploitation)
6. [Privilege Escalation](#privilege%20escalation)
7. [Post-Exploitation/Flag](#Post-Exploitation/Flag)
8. [Lessons Learned](#lessons%20learned)
9. [References](#References)

---
## Introduction

**Description:**
Dang, this track really hits the target! It sure does get loud though, headphone users be warned!!
File Included: Maximum_Sound.wav

---
## Setup

- **Operating System:** MacOS
- **Tools Used:** [SSTV Decoder](https://sstv-decoder.mathieurenaud.fr), [MaxiCode Decoder](https://zxing.org/w/decode.jspx)
- **Network Configuration:** None

---
## Walkthrough

Upon listening to the included `Maximum_Sound.wav` file, a series of high and low tones can be heard. It is clear that this is some type of frequency modulation. It is likely this is either a dial tone or some type of RF signal. When researching by describing the sound pattern to ChatGPT, it is recommended to check if the signal is an SSTV capture. The WAV file seems to match the format of an SSTV file with a series of high and low notes (preamble header) followed by other tones.

After trying to process the SSTV signal through an Android app (Robot36), an image appeared with what appears to be a target. The image appeared to be a QR code with a bullseye in the middle and no finder pattern. After trying to upload the captured image to zxing, no data could be decoded. Since the image captured through the Android app was of poor quality, an alternative solution to decode the WAV was needed. 

After a bit of googling, an SSTV online decoder was found that yielded a higher resolution decoded image. When the image was cropped and processed through Zxing, the data revealed the flag.

Decoded Cropped image
![[Huntress-CTF-2025-Day-2-Max-Sound-1.png]]

---
## Post-Exploitation/Flag
### Capturing the Flag
The flag was found in the decoded data from the Maxicode QR code, which was part of the waterfall output from the SSTV decoding of the `Maximum_Sound.wav` file.

> [!success] Flag
> `flag{d60ea9faec46c2de1c72533ae3ad11d7}`

---
## Lessons Learned
- There are tools online that can process WAV files and demodulate the data into an SSTV image.
- MaxiCode is a QR Code-like code. **MaxiCode** is a fixed-size, hexagon-module symbol with a central bullseye, built for high-speed, omnidirectional scanning on moving packages and carrying compact, structured shipping data. **QR Code** uses square modules with three corner finders, scales from tiny to very dense, and holds much more general-purpose data (URLs, payments, text) for easy phone/camera scanning.

---
**Disclaimer** 
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.