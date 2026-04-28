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
*Information pending cataloguing.*

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
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

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
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |
| cve | vendor | product | dateAdded |

