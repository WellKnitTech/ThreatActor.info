---
layout: threat_actor
title: "LockBit"
aliases: ["ABCD Ransomware"]
description: "LockBit is a ransomware-as-a-service operation known for its fast encryption and double extortion tactics."
permalink: /lockbit/
---

## Introduction
LockBit is a ransomware-as-a-service operation known for its fast encryption and double extortion tactics.

## Activities and Tactics
**Targeted Sectors**: Critical Infrastructure, Healthcare, Education

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: Critical

**First Seen**: 2019

**Last Activity**: 2024


## Notable Campaigns
- [Boeing](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) (November 2023; LockBit (Ransomware))
- [Advanced Computer Software Group](https://ico.org.uk/media2/gdlfddgc/advanced-penalty-notice-20250327.pdf) (August 2022; LockBit (Ransomware))

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications, Group Profile | Apache | Log4j | CVE-2021-44228 |
| Applications | Atlassian | Confluence Data Center & Server | CVE-2023-22527 |
| Group Profile, Virtualization | Citrix | NetScaler ADC & Gateway | CVE-2023-4966 |
| Group Profile, Network Edge | F5 | iControl REST | CVE-2021-22986 |
| Group Profile, Network Edge | Fortinet | FortiOS | CVE-2018-13379 |
| File Transfer Servers, Group Profile | Fortra | GoAnywhere Managed File Transfer | CVE-2023-0669 |
| Group Profile, Microsoft Products | Windows | NetLogon | CVE-2020-1472 |
| Group Profile, Microsoft Products | Windows | Remote Desktop Services | CVE-2019-0708 |

## Notable Indicators of Compromise (IOCs)
*No separately curated network indicators or file hashes are listed for this actor. Known exploited vulnerabilities appear in the **CISA Known Exploited Vulnerabilities (KEV)** section below.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Gosecretsdump, LaZagne, LostMyPassword, Mimikatz, NirSoft ExtPassword, PasswordFox, ProcDump, Veeam-Get-Creds |
| Defense Evasion | Backstab (Process Explorer driver), Defender Control, GMER, PCHunter, PowerTool, ProcessHacker, TDSSKiller |
| Discovery | AdFind, Advanced IP Scanner, Advanced Port Scanner, Bloodhound, Seatbelt, SoftPerfect NetScan |
| Exfiltration | Anonfiles, FileZilla, File[.]io, FreeFileSync, MEGA, RClone, Sendspace, Temp[.]sh, Tempsend, Transfer[.]sh, Transfert-my-files, WinSCP |
| LOLBAS | BCDEdit, PsExec |
| Networking | Ligolo, Ngrok, Plink |
| OffSec | Cobalt Strike, Impacket, Koadic, Metasploit, PowerShell Empire, ThunderShell |
| RMM Tools | Action1, AnyDesk, FixMeIt, ScreenConnect, Splashtop, TeamViewer, ZohoAssist |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

## CISA Known Exploited Vulnerabilities (KEV)
*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*

| CVE ID | Vendor | Product | Date Added |
|-------|-------|--------|----------|
| CVE-2024-1709 | ConnectWise | ScreenConnect | 2024-02-22 |
| CVE-2023-4966 | Citrix | NetScaler ADC and NetScaler Gateway | 2023-10-18 |
| CVE-2022-36537 | ZK Framework | AuUploader | 2023-02-27 |
| CVE-2022-22965 | VMware | Spring Framework | 2022-04-04 |
| CVE-2021-20028 | SonicWall | Secure Remote Access (SRA) | 2022-03-28 |
| CVE-2022-21999 | Microsoft | Windows | 2022-03-25 |
| CVE-2021-44228 | Apache | Log4j2 | 2021-12-10 |
| CVE-2019-19781 | Citrix | Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance | 2021-11-03 |
| CVE-2021-22986 | F5 | BIG-IP and BIG-IQ Centralized Management | 2021-11-03 |
| CVE-2021-34523 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2019-0708 | Microsoft | Remote Desktop Services | 2021-11-03 |
| CVE-2021-34473 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-31207 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-36942 | Microsoft | Windows | 2021-11-03 |
| CVE-2019-11510 | Ivanti | Pulse Connect Secure | 2021-11-03 |
| CVE-2019-7481 | SonicWall | SMA100 | 2021-11-03 |

