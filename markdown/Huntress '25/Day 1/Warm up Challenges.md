> **Platform Name**: Huntress CTF - 2025
> **Category**: #DFIR, #Forensics , #Malware
> **Date**: 10-03-2025
> **Author**: Joe Lipinski
## Read the Rules
In the source code, `ctrl+f` and search for 'flag{'

> [!flag]
> `flag{bf61aced6e7f9335385a70f33b20d188}`

## Technical Support
Access the `#ctf-open-ticket` channel on Discord and look for the flag

> [!flag]
> `flag{68cc5f95b59112d7d6b041cd16f9f19d}`

## Spam Test
Google `Generic Test for Unsolicited Bulk Email (GTUBE)` and obtain the string from https://spamassassin.apache.org/gtube/; use CyberChef to encode to MD5

> [!flag]
> `flag{6a684e1cdca03e6a436d182dd4069183}`

## Cover Your Bases
Use Cyberchef with the operations below
Challenge 1: `8-bit Binary` (8 character sets of 1's and 0's)
Challenge 2: `Octal` (3 character sets of numbers)
Challenge 3: `Decimal` (3 character sets of numbers)
Challenge 4: `Charcode` (2 character sets of letters and/or numbers)
Challenge 5: `Base32`
Challenge 6: `Base45`
Challenge 7: `Base64`
Challenge 8: `Base85`
Challenge 9: Remove whitespaces then `Base92`
Challenge 10: `Base65536`

## Just a little bit
Use Cyberchef with a Binary operator with a 7-bit byte length

> [!flag]
> `flag{2c33c169aebdf2ee31e3895d5966d93f}`

## QRception
Use [ Zxing](https://zxing.org/w/decode.jspx) to view QR code data and scan QR code data with an iPhone QR code reader. Profit!

> [!flag]
> `flag{e1487f138f885bfef64f07cdeac96908}`

## RFC 9309
Access the VM website. Check the robots.txt file. Obtain the flag from the source code.

> [!flag]
> `flag{aec1142c199aa5d8ad0f3ae3fa82e13c}`

