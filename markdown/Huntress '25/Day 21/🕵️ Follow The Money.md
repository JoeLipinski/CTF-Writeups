> **Platform Name**: Huntress CTF 2025
> **Category**: #Web #OSINT
> **Difficulty**: Medium
> **Date**: 2025-10-21
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

**Objective:**
Quietly investigate a suspected fraudulent money transfer involving Harbor Line Bank and a real-estate closing. The goal is to trace how the transfer was referenced in provided artifacts and locate the CTF flag.

**Description:**
The challenge provided five `.eml` files and noted the ZIP archive password (`follow_the_money`). Initial artifacts included Base64-encoded attachments and MIME-encoded links. By decoding embedded links and interacting with a title-company web form, a Base64 payload and a retrieval ID were discovered that led to an attacker-controlled Netlify blog and a GitHub repository. Following the repo instructions produced the final flag.

---
## Setup

- **Operating System:** Kali (or your preferred analysis OS)
- **Tools Used:** #strings, #ripgrep, #munpack, #openssl (base64), web browser, curl, jq
- **Network Configuration:** Offline analysis of `.eml` files; web access used to follow decoded links (no VPN required)

``` bash
# Example: show forensic working directory
ls -la
```

---
## Reconnaissance

### Initial Scanning
The starting point was extracting and inspecting the five `.eml` files. We looked for attachments, inline bodies, and MIME-encoded data.

```bash
# Example: extract body and headers
ripgrep -n "^From:|Content-Type:|base64|quoted-printable" *.eml
```

**Findings:**
- **`Attachments`**: Base64-encoded images (headshots) — no steganographic payload found.
- **`Embedded Links`**: Several MIME/quoted-printable encoded URLs, including a Googleusercontent link (403) and links to the bank and title company sites.

---
## Enumeration

### Web Enumeration (if applicable)
The title company website included a **Transfer Closing Funds** button that triggered a modal with a matrix-like backdrop. Submitting arbitrary data to the modal produced a response containing a Base64 string and a Retrieval ID.

```bash
# Example: decode quoted-printable (Python)
python - <<'PY'
import quopri, sys
s = '=aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw=='
print(quopri.decodestring(s))
PY
```

**Interesting Discoveries:**
- **Discovery**: Submitting nonsense data to the title company form returned a Base64 payload `aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw==` and `Retrieval ID: 471082`.
- **Decoded Payload**: `https://n0trustx-blog.netlify.app/` — a Netlify blog controlled by the actor `N0TrustX`.

---
## Exploitation

### Vulnerability Identification
There was no classic exploit — the attack flow was social/OSINT oriented. The key "exploitation" step in this CTF was following artifacts: decode MIME, visit decoded links, and interact with the title-company form which intentionally exposed a pointer to attacker infrastructure.

**Exploitation Steps:**
1. Decode quoted-printable / MIME encoded links from `.eml` files.
2. Visit the decoded Netlify blog and follow links to the GitHub account `https://github.com/N0TrustX`.
3. Download the HTML payload from the repository as instructed in the README.
4. Open the HTML locally and enter the provided `Retrieval ID`.

```bash
# Example: decode base64 string
echo 'aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw==' | base64 -d
```

---
## Privilege Escalation

### Enumerating for Privilege Escalation
This CTF did not include host compromise or privilege escalation — the challenge was focused on OSINT, artifact parsing, and following an investigation chain to a hosted resource that yielded the flag.

**Steps to Escalate Privileges:**
1. N/A in this challenge — no system-level access was required.

---
## Post-Exploitation/Flag
### Capturing the Flag
The GitHub repo README instructed to download an HTML file and input the Retrieval ID obtained from the title company modal (`471082`). Doing so displayed the flag.

```bash
# Example: show the retrieval ID captured earlier
echo "Retrieval ID: 471082"
```

> [!success] Flag
> `flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}`

---
## Lessons Learned
- OSINT and careful decoding of MIME/quoted-printable strings can reveal hidden routes to attacker infrastructure.
- Web forms and developer/test pages on organizations' websites can leak pointers (IDs, encoded URLs) when manipulated — always treat unexpected form responses as potential leads.
- Follow the chain of evidence: attachments → encoded links → decoded domains → GitHub/hosted resources.

---
## References
- Base64 decoding: `base64` CLI / `openssl base64 -d`
- Quoted-printable decoding: Python `quopri` module or `ripmime`/`munpack`
- GitHub: `https://github.com/N0TrustX`
- Netlify blog discovered: `https://n0trustx-blog.netlify.app/`

---
**Disclaimer** 
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.