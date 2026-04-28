---
layout: threat_actor
title: "Akira"
aliases: ["Akira", "Akira Ransomware", "GOLD SAHARA", "Howling Scorpius", "PUNK SPIDER"]
description: "Akira is a ransomware variant and ransomware deployment entity active since at least March 2023.(Citation: Arctic Wolf Akira 2023) Akira uses compromised credentials to access single-factor external ac"
permalink: /akira/
---

## Introduction
Akira is a ransomware variant and ransomware deployment entity active since at least March 2023. Akira uses compromised credentials to access single-factor external access mechanisms such as VPNs for initial access, then various publicly-available tools and techniques for lateral movement. Akira operations are associated with "double extortion" ransomware activity, where data is exfiltrated from victim environments prior to encryption, with threats to publish files if a ransom is not paid. Technical analysis of Akira ransomware indicates variants capable of targeting Windows or VMWare ESXi hypervisors and multiple overlaps with Conti ransomware.

## Activities and Tactics
**Targeted Sectors**: Healthcare, Education, Government, Technology

**Country of Origin**: 🏳️ Unknown

**Risk Level**: High

**First Seen**: 2023

**Last Activity**: 2025


## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations
| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Group Profile, Network Edge | Cisco | ASA & FTD | CVE-2020-3259 |
| Group Profile | Cisco | ASA & FTD | CVE-2023-20263 |
| Group Profile, Network Edge | Cisco | ASA & FTD | CVE-2023-20269 |
| Group Profile | Fortinet | FortiClient | CVE-2023-48788 |
| Group Profile, Network Edge | Fortinet | FortiOS | CVE-2019-6693 |
| Group Profile, Network Edge | Fortinet | FortiOS | CVE-2022-40684 |
| Group Profile, Network Edge | SonicWall | SonicOS SSL-VPN | CVE-2024-40766 |
| Group Profile, Virtualization | VMware | ESXi | CVE-2024-37085 |
| Group Profile, Virtualization | VMware | vSphere Client | CVE-2021-21972 |
| Applications, Group Profile | Veeam | Backup & Replication | CVE-2023-27532 |
| Applications, Group Profile | Veeam | Backup & Replication | CVE-2024-40711 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | DonPAPI, LaZagne, Mimikatz |
| Defense Evasion | PowerTool, ThrottleStop driver (rwdrv.sys), Zemana Anti-Rootkit, Zemana Anti-Rootkit driver, churchill_driver.sys, fidget.sys, consent.exe (msimg32.dll, wmsgapi.dll), icardagt.exe (version.dll), mfpmp.exe (rtworkq.dll) |
| Discovery | Advanced IP Scanner, Advanced Port Scanner, Bloodhound, Masscan, ReconFTW, ShareFinder, SharpHound, SharpShares, SoftPerfect NetScan, SoftPerfect Network Scanner, ldapdomaindump |
| Exfiltration | FileZilla, MEGA, RClone, Temp[.]sh, WinRAR, WinSCP |
| LOLBAS | net, netsh, nltest, vssadmin |
| Networking | Cloudflared, Ngrok, OpenSSH, cloudflared |
| OffSec | CrackMapExec, Impacket, NetExec, NetExec (NXC) |
| RMM Tools | AnyDesk, MeshAgent, MobaXterm, Radmin, RustDesk, TeamViewer |

## Attribution and Evidence
**Country of Origin**: Unknown
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G1024)
   MITRE ATT&CK entry

## CISA Known Exploited Vulnerabilities (KEV)
*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*

| CVE ID | Vendor | Product | Date Added |
|-------|-------|--------|----------|
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |

