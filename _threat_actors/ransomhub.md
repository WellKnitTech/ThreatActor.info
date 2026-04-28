---
layout: threat_actor
title: "RansomHub"
aliases: ["RansomHub RaaS", "RansomHub"]
description: "RansomHub is a dominant ransomware-as-a-service operation that emerged in 2024 and quickly became the most prolific group with 736 disclosed victims."
permalink: /ransomhub/
---

## Introduction
RansomHub is a dominant ransomware-as-a-service operation that emerged in 2024 and quickly became the most prolific group with 736 disclosed victims.

## Activities and Tactics
**Targeted Sectors**: Critical Infrastructure, Healthcare, Education, Manufacturing

**Country of Origin**: 🏳️ Unknown

**Risk Level**: Critical

**First Seen**: 2024

**Last Activity**: 2025


## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations
| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications, Group Profile | Apache | ActiveMQ | CVE-2023-46604 |
| Applications, Group Profile | Atlassian | Confluence Data Center & Server | CVE-2023-22515 |
| Group Profile, Virtualization | Citrix | NetScaler ADC & Gateway | CVE-2023-3519 |
| Group Profile, Network Edge | F5 | BIG-IP | CVE-2023-46747 |
| Group Profile, Network Edge | Fortinet | FortiClientEMS | CVE-2023-48788 |
| Group Profile, Network Edge | Fortinet | FortiOS SSL-VPN & FortiProxy | CVE-2023-27997 |
| Microsoft Products | MS Server Products | SMBv1 | CVE-2017-0144 |
| Applications | Veeam | Backup & Replication | CVE-2023-27532 |
| Group Profile, Microsoft Products | Windows | BITS | CVE-2020-0787 |
| Microsoft Products | Windows | CLFS | CVE-2022-24521 |
| Group Profile, Microsoft Products | Windows | NetLogon | CVE-2020-1472 |
| Group Profile | Windows | SMBv1 | CVE-2017-0144 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Xploit**

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz |
| Defense Evasion | Acronis Disk Director, BadRentdrv2, Revo Uninstaller, ThreatFire System Monitor driver (BYOVD) |
| Discovery | Angry IP Scanner, Nmap, SoftPerfect NetScan, SoftPerfect Network Scanner, WKTools |
| Exfiltration | FileZilla, PSCP, RClone, WinSCP, rclone |
| LOLBAS | BITSAdmin, PsExec, WMIC |
| Networking | Cloudflared, Stowaway, ngrok |
| OffSec | Cobalt Strike, CrackMapExec, Impacket, Kerbrute, Metasploit, NetExec (nxc), Sliver |
| RMM Tools | AnyDesk, Atera, Atera Agent, N-Able, ScreenConnect, Splashtop, TightVNC |

## Attribution and Evidence
**Country of Origin**: Unknown
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

