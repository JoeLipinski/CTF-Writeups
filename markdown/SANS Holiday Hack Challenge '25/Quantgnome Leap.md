> **Platform Name**: SANs Holiday Hack Challenge '25
> **Category**: #Cryptography, #SSH, #PostQuantum
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
Navigate a multi-step SSH challenge by progressively authenticating to remote accounts using post-quantum cryptographic keys, culminating in admin access and flag retrieval.

**Description:**
The QuantGnome challenge is an educational walkthrough of post-quantum cryptography (PQC). Using a custom `pqc-keygen` tool, keys are generated for a series of accounts (`gnome1` through `gnome4`, then `admin`) on a remote server. Each account's banner explains the cryptographic properties of the key used to authenticate, ending with the highest security level hybrid key.

---
## Setup

- **Operating System:** Kali
- **Tools Used:** #SSH, #pqc-keygen

---
## Enumeration

### Explore the Home Directory
```bash
ls -la ~
ls /usr/local/bin
```

`/usr/local/bin` contains an executable `pqc-keygen`. Check its options:

```bash
./pqc-keygen -h
```

### Generate PQC Keys
```bash
/usr/local/bin/pqc-keygen
```

Generates 28 algorithm keys. Run with `-t` to display the key table:

```bash
pqc-keygen -t
```

This shows all 28 algorithms, their bit sizes, NIST security levels, and types (Classical, PQC, Hybrid).

### Identify the SSH Username
```bash
cat ~/.ssh/id_rsa.pub
```

The comment on the key reveals `gnome1` as the initial username.

---
## Exploitation

### Progressive SSH Authentication
Authenticate to each account in sequence. Each successful login reveals the next target account name and explains the cryptographic upgrade:

```bash
ssh gnome1@pqc-server.com   # RSA key (classical)
ssh gnome2@pqc-server.com   # Next key type
ssh gnome3@pqc-server.com   # Next key type
ssh gnome4@pqc-server.com   # Hybrid: ECDSA P-256 + SPHINCS+ (NIST Level 1)
ssh admin@pqc-server.com    # Hybrid: ECDSA P-521 + ML-DSA-87 (NIST Level 5)
```

The `admin` banner confirms authentication with the strongest available hybrid key: ECDSA P-521 paired with ML-DSA-87 (NIST FIPS 204 security level 5 — equivalent strength to AES-256).

---
## Post-Exploitation/Flag

### Capturing the Flag
After gaining `admin` access, look in `/opt/` for the flag:

```bash
ls /opt/oqs-ssh/flag/
cat /opt/oqs-ssh/flag/flag
```

> [!success] Flag
> `HHC{L3aping_0v3r_Quantum_Crypt0}`

---
## Lessons Learned

- **RSA is vulnerable to quantum attacks**: Shor's algorithm running on a sufficiently powerful quantum computer can factor RSA primes. RSA keys (and ECDSA) will eventually be broken — migration to PQC is necessary.
- **NIST PQC standardization**: NIST standardized three PQC algorithms in 2024: ML-DSA (CRYSTALS-Dilithium, FIPS 204), SLH-DSA (SPHINCS+, FIPS 205), and ML-KEM (CRYSTALS-Kyber, FIPS 203). ML-DSA-87 is the highest security level.
- **Hybrid keys for quantum agility**: Combining a classical key (ECDSA) with a PQC key in a hybrid approach provides a safe migration path — if one is broken, the other still protects the session. This is the recommended first step for organizations adopting PQC.
- **Open Quantum Safe (OQS)**: The Linux Foundation's OQS project (`liboqs`) provides production-ready PQC implementations integrated into OpenSSH and other tools.

---
## References
- [Open Quantum Safe – openquantumsafe.org](https://openquantumsafe.org/)
- [NIST FIPS 204 – ML-DSA (CRYSTALS-Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 – SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [Shor's Algorithm – Wikipedia](https://en.wikipedia.org/wiki/Shor%27s_algorithm)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system.
