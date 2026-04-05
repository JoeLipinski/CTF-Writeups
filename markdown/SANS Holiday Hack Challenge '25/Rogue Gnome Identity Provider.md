> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Web, #Authentication, #JWT
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
Exploit a JWT/JWKS vulnerability in a rogue identity provider to gain admin access to a gnome diagnostic interface and discover a file the gnome downloaded.

**Description:**
Paul has access to a gnome diagnostic interface at `gnome-48371.atnascorp` but only low-privilege credentials (`gnome:SittingOnAShelf`). The interface delegates authentication to an ATNAS identity provider (IdP) using JWTs. The challenge involves manipulating the JWT — specifically the `jku` (JWK Set URL) header — to point to an attacker-controlled key set, forging an admin token.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #curl, #jwt_tool, #CyberChef

---
## Enumeration

### Review Paul's Notes
```bash
cat ~/notes
```

Key findings from the notes:
- Gnome diagnostic interface: `http://gnome-48371.atnascorp`
- ATNAS IdP: `http://idp.atnascorp/`
- Paul's CyberChef site: `http://paulweb.neighborhood/`
- Credentials: `gnome:SittingOnAShelf`

The notes also contain pre-built curl commands for the full authentication flow.

### Authenticate to the IdP
```bash
curl -X POST --data-binary $'username=gnome&password=SittingOnAShelf&return_uri=http%3A%2F%2Fgnome-48371.atnascorp%2Fauth' http://idp.atnascorp/login
```

The response redirects to the gnome interface with a JWT appended as a `token` query parameter.

### Inspect the JWT
Pass the token to `jwt_tool.py` for analysis:

```bash
jwt_tool.py <JWT>
```

The JWT header contains:
- `"alg": "RS256"`
- `"jku": "http://idp.atnascorp/.well-known/jwks.json"` — the JWKS endpoint the gnome server uses to verify the token signature
- `"kid": "idp-key-2025"`

The payload contains `"admin": false`.

---
## Exploitation

### JWKS Spoofing (jku Injection)
The `jku` header tells the verifying server where to fetch the public key for signature validation. If the server follows the `jku` URL without restricting it to a trusted domain, an attacker can:

1. Generate a new RSA key pair
2. Host the public key at an attacker-controlled URL (Paul's CyberChef site at `~/www/`)
3. Modify the JWT payload to set `"admin": true`
4. Sign the new JWT with the attacker's private key
5. Set `jku` in the JWT header to point to the attacker-controlled JWKS endpoint

```bash
# Place attacker JWKS at:
# http://paulweb.neighborhood/.well-known/jwks.json
```

Craft the forged JWT with `jwt_tool.py` or manually, then pass it to the gnome interface:

```bash
curl -v http://gnome-48371.atnascorp/auth?token=<forged-JWT>
```

### Access the Diagnostic Interface
Extract the session cookie from the auth response, then access the interface:

```bash
curl -H 'Cookie: session=<session-cookie>' http://gnome-48371.atnascorp/diagnostic-interface
```

---
## Post-Exploitation/Flag

### Capturing the Flag
The diagnostic interface reveals the filename the gnome downloaded.

---
## Lessons Learned

- **`jku` injection is a critical JWT vulnerability**: If a JWT verifier fetches the signing key from the URL in the `jku` header without validating that it belongs to a trusted domain, an attacker can forge arbitrary tokens. Always pin the JWKS URL server-side.
- **`admin: false` in a JWT payload is not access control**: JWTs are only as secure as their signature verification. Changing the payload value is trivial — the signature check is the only thing that provides security.
- **`jwt_tool.py` for JWT analysis and attacks**: This tool automates JWT inspection, signature algorithm confusion attacks, `jku` injection, `kid` injection, and more.
- **RS256 doesn't mean secure**: RS256 is asymmetric and strong — but the key fetch mechanism (`jku`) can undermine it entirely if not implemented correctly.

---
## References
- [JWT Attack Playbook – PortSwigger](https://portswigger.net/web-security/jwt)
- [jwt_tool – GitHub](https://github.com/ticarpi/jwt_tool)
- [RFC 7517 – JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [MITRE ATT&CK T1550 – Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
