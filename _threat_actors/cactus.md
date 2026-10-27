---
layout: threat_actor
title: "cactus"
aliases: ["Cactus","Cactus Ransomware Group","cactus"]
description: "The CACTUS ransomware is said to have emerged around March 2023. The group became known for exploiting vulnerabilities to gain initial access and maintain a presence within the organization's infrastru"
permalink: /cactus/
---

## Introduction
The CACTUS ransomware is said to have emerged around March 2023. The group became known for exploiting vulnerabilities to gain initial access and maintain a presence within the organization's infrastructure. There is little known information about the ransomware group, except that it emerged on the mentioned date and, following encryption, a text file named 'cAcTuS.readme.txt' would be created. Additionally, encrypted files were altered to the '.cts1' extension, and data exfiltration and victim extortion were conducted through the use of the service known as Tox. As mentioned earlier, the ransomware especially exploits vulnerabilities in VPNs, also utilizing obfuscation techniques to conceal its activities, such as employing UPX and utilizing encryption algorithms like OpenSSL, AES OCB, ChaCha20_Poly1305, system reinitializations, and others.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Network Edge | Pulse Secure / Ivanti | Ivanti MobileIron | CVE-2023-38035 |
| Applications | Qlik | QlikSense | CVE-2023-41265 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Xploit**: 

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Discovery | Nmap, SoftPerfect NetScan |
| Exfiltration | RClone |
| Networking | Chisel |
| OffSec | Cobalt Strike |
| RMM Tools | AnyDesk, Splashtop, SuperOps |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

