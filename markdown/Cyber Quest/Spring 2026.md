> **Platform Name**: U.S. Cyber Challenge — Cyber Quests 2026 Spring
> **Category**: #Forensics , #SCADA, #NetworkAnalysis, #Wireshark
> **Date**: 04/06/2026
> **Author**: Joe Lipinski

---
## Introduction

**Objective:**
Analyze six packet captures to reconstruct the full attack chain against an internet-exposed SCADA test environment — from initial entry through internal reconnaissance, protocol analysis, web interface probing, and a Man-in-the-Middle attack.

**Description:**
A small utility's SCADA test environment was connected to the internet via a DSL line without adequate security. After the lead engineer observed odd behavior, six packet captures were collected for forensic analysis. This write-up walks through all 29 challenge questions, demonstrating how to use Wireshark to answer each one and reproduce the findings.

---
## Setup

- **Operating System:** Kali Linux / any OS with Wireshark
- **Tools Used:** #Wireshark
- **Artifact Files:**

| File                 | Description                                               |
| -------------------- | --------------------------------------------------------- |
| `entry.pcap`         | Initial external connections and port scanning            |
| `init.recon.pcap`    | Internal network reconnaissance from the compromised host |
| `HMI2PLC.pcap`       | Normal HMI-to-PLC SCADA communications                    |
| `web_recon.pcap`     | Attacker probing the PLC web interface                    |
| `hmi_web_recon.pcap` | Attacker probing the HMI web interface via SSH tunnel     |
| `ettercap.pcap`      | ARP spoofing Man-in-the-Middle attack                     |

**Key Hosts:**

| IP | Role | MAC |
|----|------|-----|
| 172.31.255.28 | Attacker (external) | — |
| 10.1.10.33 | Compromised SSH gateway (Linux/Ubuntu) | 08:00:27:fb:b8:10 |
| 10.1.10.20 | HMI — PeakHMI (Windows) | 14:fe:b5:ab:23:be |
| 10.1.10.130 | PLC — Allen-Bradley 1763-L16BWA | 00:0f:73:02:52:51 |
| 10.1.10.60 | Internal SSH host | — |

``` bash
# Load a capture in Wireshark from the command line
wireshark entry.pcap &
```

---
## Section 1: Entry (Questions 1–4)
**Artifact:** `entry.pcap`
This capture covers the attacker's initial external activity — a port scan of exposed hosts followed by connection attempts to open services.

---
### Q1 — Identifying the Connection Tool
**Which tool was most likely used to establish connections to each of the open ports?**

> [!success] Answer
> **Telnet**

After the initial SYN→RST scan sweep, the attacker made full connections to each of the three open ports (Streams 9, 10, 11 in Wireshark). The key evidence is in Stream 10 (the connection to 10.1.10.20:3389), which contains **Telnet IAC (Interpret As Command) control sequences** in the client data:

```
ff f4 ff fd 06 → IAC IP (Interrupt Process), IAC DO TIMING-MARK
ff ed ff fd 06 → IAC DATA-MARK, IAC DO TIMING-MARK
0d 0a → CR+LF line endings
```

The `0xff` byte is the Telnet IAC prefix. Netcat sends raw data and would **never** generate IAC sequences — only the `telnet` client does.

The other two connections also match telnet behavior:
- **Port 2200** (Stream 9): Received SSH banner, sent CR/LF → server replied "Protocol mismatch." (classic result of `telnet <host> <port>` to an SSH service)
- **Port 22** (Stream 11): Same pattern — SSH banner, CR/LF, "Protocol mismatch."

The `telnet` command can connect to any TCP port (not just port 23), making it suitable for probing all three open ports (2200, 3389, 22).

---
### Q2 — Which IP Had Port 2200 Open
**Which IP address had port 2200 open?**

> [!success] Answer
> **10.1.10.33**
#### Steps to Reproduce
In `entry.pcap`, filter for SYN-ACK responses on port 2200:

```
tcp.srcport == 2200 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

The result shows a single host responding affirmatively:

```
Frame 33: 10.1.10.33:2200 → 172.31.255.28  [SYN, ACK]  ← port is open
```

A SYN-ACK means the port accepted the connection. Any RST-ACK would indicate a closed port.

---
### Q3 — Service Running on Port 2200

**What service appears to be running on port 2200?**

> [!success] Answer
> **Secure Shell (SSH)**

#### Steps to Reproduce

In `entry.pcap`, filter for SSH protocol banners:

```
ssh
```

Or use the display filter:

```
tcp.port == 2200
```

Right-click any packet in the stream → **Follow → TCP Stream**. You will see the SSH version banners exchanged at connection establishment:

```
Server (10.1.10.33):   SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7
Client (172.31.255.28): SSH-2.0-OpenSSH_5.2
```

The `SSH-2.0` prefix in the banner confirms this is an SSH service. The server is running a Debian-packaged OpenSSH.

---
### Q4 — Attacker SSH Version

**Which version of SSH was the attacker using?**

> [!success] Answer
> **OpenSSH 5.2**

#### Steps to Reproduce

In `entry.pcap`, apply:

```
ssh
```

Locate frames 155 and 157. The two banners will be visible in the packet details pane under the SSH protocol layer:

| Frame | Source | Banner |
|-------|--------|--------|
| 155 | 10.1.10.33 (server) | `SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7` |
| 157 | 172.31.255.28 (attacker) | `SSH-2.0-OpenSSH_5.2` |

The attacker is the **external IP 172.31.255.28**, so their SSH client version is **OpenSSH 5.2**. The 5.3p1 version belongs to the server.

---
## Section 2: Initial Recon (Questions 5–10)

**Artifact:** `init.recon.pcap`

After gaining SSH access to 10.1.10.33, the attacker used it as a pivot point to scan the internal network and manually browse the web interfaces of discovered devices.

---
### Q5 — Identifying the Same Device Type

**Which IP addresses appear to be the same type of device?**

> [!success] Answer
> **10.1.10.15 and 10.1.10.13**

#### Steps to Reproduce

In `init.recon.pcap`, filter for HTTP responses:

```
http.response
```

For each host, right-click a response → **Follow → TCP Stream** to view the full HTTP response body. Look at the `<title>` tag in the HTML:

| IP | TCP Stream | Page Title |
|----|------------|------------|
| 10.1.10.13 | Stream 88 | `Grandstream Device Configuration` |
| 10.1.10.15 | Stream 89 | `Grandstream Device Configuration` |
| 10.1.10.29 | — | `RICOH Maintenance Shell` |
| 10.1.10.130 | — | Allen-Bradley PLC |
| 10.1.10.20 | — | PeakHMI |

Both 10.1.10.13 and 10.1.10.15 return the identical Grandstream configuration page — these are **Grandstream VoIP devices**.

---
### Q6 — Which IP Did NOT Have Port 23 Open

**Which IP address did NOT have port 23 (Telnet) open?**

> [!success] Answer
> **10.1.10.10**

#### Steps to Reproduce

In `init.recon.pcap`, filter for SYN-ACK responses on port 23 (meaning the port was open):

```
tcp.srcport == 23 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

**Hosts that responded with SYN-ACK (port 23 open):**
10.1.10.1, 10.1.10.13, 10.1.10.15, 10.1.10.16, 10.1.10.27, 10.1.10.29

Now filter for RST-ACK responses on port 23 (port closed):

```
tcp.srcport == 23 && tcp.flags.reset == 1
```

Frame 1067 shows 10.1.10.10 sending a RST-ACK, meaning port 23 is **closed** on that host.

---
### Q7 — Port Scan Duration

**Approximately how long did the port scan take to complete?**

> [!success] Answer
> **4.0 seconds**

#### Steps to Reproduce

The port scan originates from 10.1.10.33 (the compromised gateway). Filter for SYN packets from that host:

```
ip.src == 10.1.10.33 && tcp.flags == 0x002
```

Examine the Time column in Wireshark:

- **First SYN:** Frame 112 at relative time **22.90s**
- **Last SYN in the burst:** Frame 1103 at relative time **26.90s**

After frame 1103 there is a large gap — the next SYN at ~102.5s represents the attacker manually browsing, not scanning. The scan burst ran for approximately **4.0 seconds** (26.90 − 22.90 = 4.0s).

> [!tip] Tip
> In Wireshark, set the time display format to **View → Time Display Format → Seconds Since Beginning of Capture** to make these calculations straightforward.

---
### Q8 — How Many IPs Had Port 3389 Open

**How many IP addresses had port 3389 (RDP) open?**

> [!success] Answer
> **1**

#### Steps to Reproduce

In `init.recon.pcap`, filter for SYN-ACK responses on port 3389:

```
tcp.srcport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

Only **10.1.10.20** appears in the results — one host with RDP open. This is consistent with the HMI being a Windows machine (PeakHMI runs on Windows).

---
### Q9 — Identifying the HMI

**Which IP address appears to be running a Human Machine Interface (HMI)?**

> [!success] Answer
> **10.1.10.20**

#### Steps to Reproduce

In `init.recon.pcap`, filter for HTTP 401 responses:

```
http.response.code == 401
```

Right-click the response from 10.1.10.20 → **Follow → TCP Stream**. The authentication challenge header reveals the realm:

``` http
HTTP/1.1 401 Access Denied
WWW-Authenticate: Digest realm="PeakHMI", ...
WWW-Authenticate: Basic Realm="PeakHMI"
```

**PeakHMI** is a Human Machine Interface software package by Automated Solutions, Inc. This directly identifies 10.1.10.20 as the HMI.

---
### Q10 — Port Not Included in the Internal Scan

**Which port was NOT included in the internal network scan?**

> [!success] Answer
> **TCP 2200**

#### Steps to Reproduce

In `init.recon.pcap`, filter for SYN packets from the attacker's pivot host and examine the destination ports:

```
ip.src == 10.1.10.33 && tcp.flags == 0x002
```

Look at the `Destination Port` column. The scanned ports are:

```
21, 22, 23, 80, 443, 3389
```

**Port 2200 does not appear.** This makes sense — port 2200 is the non-standard SSH port the attacker used to access 10.1.10.33 from the *outside*. Once inside the network, the attacker scanned standard ports only.

---
## Section 3: SCADA Protocols (Questions 11–13)

**Artifact:** `HMI2PLC.pcap`

This capture contains normal, expected SCADA polling traffic between the HMI (10.1.10.20) and the PLC (10.1.10.130). The attacker would use this as intelligence about how the system operates.

---
### Q11 — Locating the Packet Counter Offset

**Which packet offset location contains the counter in packets from .20 to .130?**

> [!success] Answer
> **0x73**

#### Steps to Reproduce

Open `HMI2PLC.pcap` in Wireshark. Filter for packets from the HMI to the PLC:

```
ip.src == 10.1.10.20 && ip.dst == 10.1.10.130
```

Select frame 12. In the **Packet Bytes** pane (bottom of Wireshark), locate the candidate offsets and note the byte values. Then repeat for consecutive request frames (12, 15, 18, 21, 24, 27, 30):

| Frame | Offset 0x42 | Offset 0x73 | Offset 0x26 | Offset 0x2a |
|-------|-------------|-------------|-------------|-------------|
| 12 | 00 | **01** | 4a | 8b |
| 15 | 01 | **02** | 4a | 8b |
| 18 | 02 | **03** | 4a | 8b |
| 21 | 03 | **04** | 4a | 8b |
| 24 | 00 | **05** | 4a | 8b |
| 27 | 01 | **06** | 4a | 8b |
| 30 | 02 | **07** | 4a | 8b |

**Analysis of each offset:**
- **0x26 / 0x2a:** Static values (`4a` and `8b` never change) — these are fixed TCP header fields.
- **0x42:** Cycles 0 → 1 → 2 → 3 → 0 → 1 → 2 — wraps every 4 values, not a true incrementing counter.
- **0x73:** Increments continuously: 01, 02, 03, 04, 05, 06, 07... — this is the **session counter**.

> [!tip] Tip
> To navigate to a specific byte offset in Wireshark, click anywhere in the Packet Bytes pane and use **Edit → Find Packet** or simply count bytes from the start of the frame. The offset shown in Wireshark's hex pane is zero-indexed from the beginning of the Ethernet frame.

---
### Q12 — Protocol Between HMI and PLC

**Which protocol appears to be in use between the HMI and PLC?**

> [!success] Answer
> **Ethernet Industrial Protocol (EtherNet/IP)**

#### Steps to Reproduce

Open `HMI2PLC.pcap`. Look at the Protocol column in the packet list. Wireshark will show:

```
enip:cip:cippccc
```

Clicking on any packet and expanding the protocol layers in the **Packet Details** pane reveals:

- **ENIP** = EtherNet/IP (Ethernet Industrial Protocol)
- **CIP** = Common Industrial Protocol (rides on top of ENIP)

> [!note] Note
> "EtherNet/IP" is not the same as "Ethernet over IP" (EoIP), which is a Mikrotik tunneling protocol. Also, CIP stands for Common *Industrial* Protocol — not "Common Instrumentation Protocol." These are common distractors in this type of question.

---
### Q13 — Nature of HMI–PLC Communications

**Which of the following best describes the nature of the communications between .20 and .130?**

> [!success] Answer
> **The .20 device requests data at regular intervals (polling)**

#### Steps to Reproduce

In `HMI2PLC.pcap`, observe the traffic flow direction. Filter to see requests and responses:

```
ip.src == 10.1.10.20 || ip.src == 10.1.10.130
```

The pattern is consistent and unidirectional in terms of initiation:
1. HMI (10.1.10.20) sends a **request** to the PLC (10.1.10.130)
2. PLC (10.1.10.130) sends a **response** back to the HMI
3. Repeat at regular intervals

This is standard **SCADA polling** — the HMI acts as the master, periodically querying the PLC (slave) for its current state. The PLC never initiates communication on its own.

---
## Section 4: PLC Web Recon (Questions 14–18)

**Artifact:** `web_recon.pcap`

The attacker browses the Allen-Bradley PLC's built-in web interface from 10.1.10.33, initially using `lwp-request` (a Perl command-line HTTP tool) and later switching to Firefox.

---
### Q14 — Username Used to Access the PLC Web Server

**What username was successfully used to access pages on the web server on .130?**

> [!success] Answer
> **guest**

#### Steps to Reproduce

In `web_recon.pcap`, filter for HTTP requests with Authorization headers:

```
http.authorization
```

In the **Packet Details** pane, expand **Hypertext Transfer Protocol → Authorization** on any authenticated request. The Digest auth header reveals the username:

```http
Authorization: Digest username="guest", realm="1763-L16BWA B/9.00", ...
```

All authenticated requests use `username="guest"` — a default account on the Allen-Bradley PLC.

---
### Q15 — Web Server Running on the PLC

**What web server appears to be running on the .130 device?**

> [!success] Answer
> **A-B WWW/0.1**

#### Steps to Reproduce

In `web_recon.pcap`, filter for HTTP responses from the PLC:

```
ip.src == 10.1.10.130 && http.response
```

In the Packet Details pane, expand **Hypertext Transfer Protocol** on any response. Every HTTP response from 10.1.10.130 includes:

```http
Server: A-B WWW/0.1
```

**A-B** stands for **Allen-Bradley** — this is the proprietary embedded web server built into the 1763-L16BWA PLC firmware.

---
### Q16 — URI Returning an ActiveX Reference

**What was the URI that returned an embedded reference to an ActiveX control?**

> [!success] Answer
> **/dataview.htm**

#### Steps to Reproduce

In `web_recon.pcap`, filter for HTTP responses containing "OBJECT" or "ActiveX":

```
http contains "OBJECT"
```

Or simply follow the TCP stream for the request to `/dataview.htm`. The response body contains:

``` html
<OBJECT ID="viewlist" CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83">
  <PARAM NAME="DataURL" VALUE="dataview.dat">
  <PARAM NAME="UseHeader" VALUE="True">
  <PARAM NAME="FieldDelim" VALUE=",">
  <PARAM NAME="TextQualifier" VALUE="'">
  <PARAM NAME="EscapeChar" VALUE="\">
</OBJECT>
```

The CLASSID `333C7BC4-460F-11D0-BC04-0080C7055A83` is the **Microsoft Tabular Data Control** — an ActiveX control used to display tabular data from a CSV-like source. This page exposes live PLC data to any Internet Explorer user who authenticates.

> [!note] Note
> `/newdata.htm` also contains a similar ActiveX reference, but `/dataview.htm` is the canonical answer as it is the first page that both triggers authentication and embeds the ActiveX object.

---
### Q17 — Tool Used to Probe the PLC Web Server

**What tool do the attackers appear to be using to probe the web server on .130?**

> [!success] Answer
> **Firefox**

#### Steps to Reproduce

In `web_recon.pcap`, filter for HTTP requests to the PLC:

```
ip.dst == 10.1.10.130 && http.request
```

Select any request and expand **Hypertext Transfer Protocol** in the Packet Details pane. Look at the `User-Agent` field:

```
Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.24) Gecko/20111107
Ubuntu/10.04 (lucid) Firefox/3.6.24
```

This User-Agent string identifies **Firefox 3.6.24** running on Ubuntu 10.04 (Lucid Lynx) — consistent with the compromised SSH gateway (10.1.10.33) which showed a Debian/Ubuntu SSH banner.

> [!note] Note
> Earlier requests in this capture show a different User-Agent (`libwww-perl`) from `lwp-request`. The attacker switched to Firefox after the initial automated reconnaissance.

---
### Q18 — First URI to Trigger an Auth Challenge

**Which URL request first resulted in an authentication request?**

> [!success] Answer
> **/dataview.htm**

#### Steps to Reproduce

In `web_recon.pcap`, filter for HTTP 401 responses:

```
http.response.code == 401
```

Note the frame number of the first 401 response. Then filter for the corresponding request:

```
http.request
```

Scroll through the requests in order. The early requests to `/`, `/redirect.htm`, `/header.htm`, `/navtree.htm`, `/home.htm`, etc. all returned **200 OK** with no authentication required. Then:

- **Frame 232:** `GET /dataview.htm` — **no Authorization header** → server responds with **401 Unauthorized** and:
  ```
  WWW-Authenticate: Digest realm="1763-L16BWA B/9.00"
  ```
- **Frame 243:** `GET /dataview.htm` — **with Authorization header** → server responds with **200 OK**

`/dataview.htm` is the first URI that required credentials to access.

---
## Section 5: HMI Web Recon (Questions 19–23)

**Artifact:** `hmi_web_recon.pcap`

The attacker accesses the HMI's (10.1.10.20) web interface. Rather than browsing directly, they forward port 80 through their SSH tunnel and browse from their own machine — a technique that makes their real OS and browser visible in the User-Agent.

---
### Q19 — Browser Used to Access the HMI

**What browser did the attackers use to access the HMI?**

> [!success] Answer
> **Safari**

#### Steps to Reproduce

In `hmi_web_recon.pcap`, filter for HTTP requests:

```
http.request
```

Select any request and expand **Hypertext Transfer Protocol** in the Packet Details pane:

```
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.52.7
(KHTML, like Gecko) Version/5.1.2 Safari/534.52.7
```

This is **Safari 5.1.2** on a Mac — the attacker's real machine, not the Linux pivot host.

---
### Q20 — Explaining the OS Discrepancy

**The OS shown in the capture differs from the OS on 10.1.10.33. What is the most likely explanation?**

> [!success] Answer
> **The attackers set up a port-forwarding tunnel for port 80 over an SSH connection**

#### Steps to Reproduce

Three pieces of evidence in `hmi_web_recon.pcap` tell this story together:

**1. Source IP is the Linux pivot host:**
```
ip.src == 10.1.10.33
```
All HTTP traffic to the HMI appears to originate from the Ubuntu gateway.

**2. User-Agent shows a Mac:**
```
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) ... Safari/534.52.7
```

**3. Host header reveals localhost tunneling:**
In the HTTP request headers:
```
Host: 127.0.0.1:8080
```
The browser is connecting to *localhost* on port 8080 — not directly to the HMI.

**What happened:** The attacker ran SSH local port forwarding on their Mac:

```bash
ssh -L 8080:10.1.10.20:80 user@<external_IP_of_10.1.10.33>
```

This command forwards `localhost:8080` on their Mac through the SSH tunnel to `10.1.10.20:80`. They then browsed `http://127.0.0.1:8080` with Safari. Traffic exits from 10.1.10.33 as if the pivot host made the requests, but the Mac's User-Agent and the `Host: 127.0.0.1` header betray the technique.

---
### Q21 — Password Used to Authenticate to the HMI

**Which password was most likely used to authenticate to the HMI web server?**

> [!success] Answer
> **L3tmein**

#### Steps to Reproduce

In `hmi_web_recon.pcap`, filter for the Digest authentication exchange:

```
http.authorization
```

Expand the Authorization header on frame 14 to get the Digest parameters:

```
username="fmeyer"
realm="PeakHMI"
nonce="<value from server>"
nc=<value>
cnonce=<value>
response="e84d8e1c7e3506b2d9ebdbe42068919d"
```

Digest authentication hashes the password — it is never sent in cleartext. To verify which password was used, compute the expected Digest response for each candidate using the RFC 2617 formula:

```
HA1      = MD5(username:realm:password)
         = MD5(fmeyer:PeakHMI:<candidate>)

HA2      = MD5(method:uri)
         = MD5(GET:/)

response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
```

| Candidate Password | Computed Response Matches? |
|--------------------|---------------------------|
| password | No |
| **L3tmein** | **Yes — matches `e84d8e1c7e3506b2d9ebdbe42068919d`** |
| hmiviewonly | No |
| fm3y3r-hmi | No |

The matching password is **L3tmein** — a weak, predictable password for a critical infrastructure system.

> [!tip] Tip
> You can reproduce this offline with Python:

``` python
import hashlib
def md5(s): return hashlib.md5(s.encode()).hexdigest()

user, realm, pw = "fmeyer", "PeakHMI", "L3tmein"
ha1 = md5(f"{user}:{realm}:{pw}")
ha2 = md5("GET:/")
# Plug in nonce, nc, cnonce, qop values from the packet
response = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
print(response)
```

---
### Q22 — HMI Timezone

**Based on the logon times in the event log page, what U.S. timezone does the HMI appear to be in?**

> [!success] Answer
> **Central (CST, UTC-6)**

#### Steps to Reproduce

In `hmi_web_recon.pcap`, filter for the event log page:

```
http contains "EVENTLOG"
```

Follow the TCP stream for the request to `/EVENTLOG.html/Date=322D312D32303132`. The response body contains HMI log entries showing logon events on **2-1-2012 (February 1)**:

```
9:52:06 PM  — Logon from 10.1.10.33
```

Now compare to the packet capture timestamp. In Wireshark, find frame 14 (the first authenticated `GET /` request). The capture timestamp in UTC is:

```
2012-02-02T03:52:15Z  (UTC)
```

**Conversion:**
```
03:52 UTC = 9:52 PM local time (12-hour clock)
03:52 UTC − X hours = 21:52 local
X = 6
UTC − 6 = Central Standard Time (CST)
```

The HMI is in the **Central** timezone.

---
### Q23 — Time Differential Between HMI and Capture Device

**What is the time differential between the HMI web server and the device performing the packet captures?**

> [!success] Answer
> **9 seconds**

#### Steps to Reproduce

Compare the HMI's logged timestamps against the packet capture timestamps (converted to CST) across multiple events:

| Packet Capture Time (CST) | HMI Event Log Time | Difference |
|---------------------------|-------------------|------------|
| 9:52:15 PM (GET /) | 9:52:06 PM | **9s** |
| 9:53:18 PM (/SCRL.html) | 9:53:10 PM | 8s |
| 9:53:21 PM (/SCRS/ID=1) | 9:53:12 PM | 9s |
| 9:53:26 PM (/index.html) | 9:53:17 PM | 9s |
| 9:53:49 PM (/EVENTLOG) | 9:53:40 PM | 9s |

The HMI's internal clock is consistently **~9 seconds behind** the device capturing the packets. This is a minor but measurable clock skew.

---

## Section 6: Man-in-the-Middle Attack (Questions 24–29)

**Artifact:** `ettercap.pcap`

The attacker uses **ettercap** — an open-source ARP spoofing and MITM framework — to intercept all traffic on the 10.1.10.0/24 network segment. This is the final and most disruptive phase of the attack.

---
### Q24 — HMI Event at Feb 1, 3:24:50 PM

**Based on the event log page, what event occurred on the HMI on Feb 1 at 3:24:50 PM?**

> [!success] Answer
> **A watchdog timer event**

#### Steps to Reproduce

This question references the event log viewed in `hmi_web_recon.pcap` (see Q22). In the event log response, locate entries around 3:24 PM on February 1:

```
3:24:55 PM — Watchdog primary port ML1100
3:24:50 PM — Watchdog primary port ML1100
```

A watchdog timer is a hardware/software mechanism that expects a regular "heartbeat" signal from a connected device. If the heartbeat stops, the watchdog fires — indicating a **loss of communication** between the HMI and the PLC (ML1100).

---
### Q25 — Most Likely Cause of the Watchdog Event

**What is the most likely cause of the watchdog timer event?**

> [!success] Answer
> **ARP spoofing disrupted communications between the HMI and PLC**

#### Steps to Reproduce

Open `ettercap.pcap` in Wireshark. Filter for ARP replies:

```
arp.opcode == 2
```

Observe the volume and source: a single MAC address — `54:52:55:53:54:1f` — sends **17,000+ ARP reply packets** claiming to be every IP address on the network:

```
10.1.10.1, .10, .12, .13, .15, .16, .18, .20, .22, .27, .28, .29, .33, .35, .60, .130
```

No legitimate device claims 16 different IP addresses. This is textbook **ARP cache poisoning** (ARP spoofing) by ettercap. When the HMI's ARP table is poisoned to associate the PLC's IP (10.1.10.130) with the attacker's MAC, the HMI's polling packets are redirected to the attacker — breaking the HMI↔PLC link and triggering the watchdog.

---
### Q26 — Packet That First Caused the Communications Failure

**Which packet most likely first caused the communications failure between the HMI and PLC?**

> [!success] Answer
> **Frame 2920**

#### Steps to Reproduce

In `ettercap.pcap`, filter for ARP spoofing packets specifically targeting the HMI or PLC:

```
arp.opcode == 2 && (arp.dst.hw_mac == 14:fe:b5:ab:23:be || arp.dst.hw_mac == 00:0f:73:02:52:51)
```

The ARP flood begins at frame 2878 and cycles through all hosts. Track the progression to find when the HMI↔PLC pair is first poisoned:

| Frame | ARP Reply To | Spoofed IP | Attacker MAC |
|-------|-------------|------------|--------------|
| 2878 | PLC (.130) | .35 | 54:52:55:53:54:1f |
| 2879 | .35 | PLC (.130) | 54:52:55:53:54:1f |
| ... | ... | ... | ... |
| **2920** | **PLC (.130)** | **HMI (.20)** | **54:52:55:53:54:1f** |
| 2922 | HMI (.20) | PLC (.130) | 54:52:55:53:54:1f |

**Frame 2920** is the first ARP reply that poisons the PLC's ARP cache — telling the PLC that the HMI's IP (10.1.10.20) is at the attacker's MAC. After this, the PLC sends its responses to the attacker instead of the real HMI, breaking communication.

---
### Q27 — MAC Address of the ARP Spoofing Device

**What appears to be the MAC address of the device that performed the ARP spoofing?**

> [!success] Answer
> **54:52:55:53:54:1f**

#### Steps to Reproduce

In `ettercap.pcap`, filter for ARP replies:

```
arp.opcode == 2
```

In the **Packet Details** pane, look at the **Ethernet** layer → **Source** and **ARP** layer → **Sender MAC address**. One MAC stands out:

- **54:52:55:53:54:1f** appears in 17,000+ ARP replies, claiming to be 16 different IP addresses.
- All other MACs each map to a single IP address (the real devices).

No legitimate device advertises itself as 16 different IPs simultaneously. This is definitively the attacker's ettercap host.

> [!tip] Tip
> Apply the following filter and look at Statistics → Endpoints to see a summary of which MACs sent how many ARP replies: `arp.opcode == 2`. The spoofing MAC will be far and away the most active.

---
### Q28 — What Restored the PLC–HMI Connection

**What event allowed the PLC and HMI connection to be restored?**

> [!success] Answer
> **The attackers spoofed ARP packets with the correct (legitimate) MAC-to-IP mappings**

#### Steps to Reproduce

In `ettercap.pcap`, jump to frames 20795–20796. Filter with:

```
frame.number >= 20790 && frame.number <= 20800 && arp.opcode == 2
```

These two ARP replies originate from the **attacker's MAC** (`54:52:55:53:54:1f`) but now carry the **correct** MAC-to-IP mappings:

```
Frame 20795: ARP reply to PLC  → "HMI (10.1.10.20) is at 14:fe:b5:ab:23:be"  ✓ CORRECT
Frame 20796: ARP reply to HMI  → "PLC (10.1.10.130) is at 00:0f:73:02:52:51" ✓ CORRECT
```

This is **ettercap's built-in cleanup behavior** — when the attacker terminates the MITM session, ettercap automatically sends corrective ARP replies to restore the victims' ARP caches to their legitimate state. The replies are technically still "spoofed" (coming from the attacker's MAC), but they contain truthful data.

---
### Q29 — Packet That Restored Communications

**Which packet allowed communications between the HMI and PLC to be restored?**

> [!success] Answer
> **Frame 20796**

#### Steps to Reproduce

From Q28, we know frames 20795 and 20796 are the two corrective ARP replies. To determine which one *restored* communication, consider the direction:

| Frame | Recipient | Message |
|-------|-----------|---------|
| 20795 | PLC (.130) | "The HMI (.20) is at its real MAC" → PLC can now send correctly to HMI |
| **20796** | **HMI (.20)** | **"The PLC (.130) is at its real MAC" → HMI can now send correctly to PLC** |

The HMI **initiates** all SCADA communication by polling the PLC. Without frame 20796, the HMI's ARP table still maps the PLC to the attacker's (now-offline) MAC, so HMI requests would go nowhere. After frame 20796 corrects the HMI's ARP cache, the HMI can reach the real PLC — and direct HMI↔PLC traffic resumes at **frame 21203**.

> [!note] Note
> Frame 20784 is a similar corrective ARP for the .35↔PLC pair — a distractor. The answer is specifically frame 20796 for the HMI↔PLC restoration.

---
## Lessons Learned

The following lessons emerge across all six sections of this challenge:

**1. Non-standard ports don't hide services.**
Running SSH on port 2200 instead of 22 provides minimal security. Netcat's port probing (`nc -z`) trivially discovers services regardless of port number. If anything, the non-standard port drew attention to the host as a managed/deliberately configured system.

**2. Banner information is a gift to attackers.**
SSH version banners (OpenSSH 5.2, OpenSSH 5.3p1 Debian) reveal the OS, software, and version in plaintext during every handshake. Outdated versions (5.2, 5.3) may have known CVEs. Suppress banners where possible.

**3. Internal network segmentation is essential in SCADA environments.**
Once the attacker compromised a single internet-facing host (10.1.10.33), the entire flat internal network was exposed. A compromised SSH gateway should never have direct IP reachability to PLCs and HMIs. Network segmentation, VLANs, and industrial DMZs are non-negotiable for OT/ICS environments.

**4. Default and weak credentials persist in ICS/SCADA.**
The PLC was accessed with `username="guest"` — a default credential. The HMI was accessed with `L3tmein` — a simple leet-speak password. Critical infrastructure demands strong, unique credentials and multi-factor authentication where possible.

**5. SSH tunneling defeats network-layer controls.**
An attacker with SSH access to any internal host can tunnel arbitrary traffic to any other host, bypassing firewall rules and making the source appear as the pivot. Network monitoring must inspect traffic at the application layer and track anomalous `Host:` headers (e.g., `Host: 127.0.0.1:8080`).

**6. Digest authentication is not secure without HTTPS.**
While Digest auth avoids sending passwords in cleartext, the captured nonce, nc, cnonce, and realm values allow offline password cracking. Without TLS, the authentication exchange is fully visible and crackable. The HMI's `L3tmein` password was recoverable from the capture alone.

**7. ARP spoofing in flat networks is trivially easy and highly disruptive.**
Ettercap poisoned the ARP caches of all 16 hosts on the /24 in a single burst. The attack directly caused a watchdog timer event — a measurable, operational impact. Defenses include dynamic ARP inspection (DAI) on managed switches, static ARP entries for critical devices, and monitoring for ARP anomalies.

**8. Attacker tools leave forensic fingerprints.**
- Netcat leaves reused source ports and RST after SYN-ACK.
- Firefox and Safari User-Agents reveal the attacker's real OS and browser.
- `libwww-perl` reveals automated scripting.
- Ettercap leaves a single MAC claiming every IP and sends distinctive cleanup packets on exit.
- The SSH tunnel is betrayed by `Host: 127.0.0.1` in HTTP headers.

**9. Packet captures preserve operational context.**
The watchdog timer events in the HMI log, the clock skew between the HMI and capture device, and the precise frame numbers of ARP poisoning events all demonstrate that detailed forensic timelines can be reconstructed from network captures alone — even without host-based logs.

**10. SCADA protocols are not designed with security in mind.**
EtherNet/IP (ENIP) and CIP traffic between the HMI and PLC is unencrypted and unauthenticated. An attacker who positions themselves in the network path (as accomplished via ARP spoofing) can observe, and potentially manipulate, all control communications.

---
## References

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [RFC 2617 — HTTP Digest Authentication](https://datatracker.ietf.org/doc/html/rfc2617)
- [EtherNet/IP and CIP Overview (ODVA)](https://www.odva.org/technology-standards/key-technologies/ethernet-ip/)
- [Allen-Bradley MicroLogix 1100 / 1763 Documentation](https://www.rockwellautomation.com)
- [PeakHMI by Automated Solutions](http://www.automatedsolutions.com/)
- [Ettercap Project](https://www.ettercap-project.org/)
- [CISA ICS Security Guidance](https://www.cisa.gov/topics/industrial-control-systems)

---
**Disclaimer**
This write-up is for educational purposes only. Always obtain proper authorization before testing or exploiting any system. The techniques described here are documented for defensive awareness and CTF/training contexts.