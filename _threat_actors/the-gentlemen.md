---
layout: threat_actor
title: "The Gentlemen"
aliases: ["GOLD SHERWOOD","Storm-2697","The Gentlemen","the gentlemen"]
description: "The Gentlemen is a ransomware group that employs a dual-extortion strategy, encrypting sensitive files while exfiltrating critical business data to pressure victims into paying ransoms. Their operation"
permalink: /the-gentlemen/
---

## Introduction
The Gentlemen is a ransomware group that employs a dual-extortion strategy, encrypting sensitive files while exfiltrating critical business data to pressure victims into paying ransoms. Their operations leverage advanced techniques such as abusing legitimate utilities like PowerRun.exe for privilege escalation, using custom-built tools for defense evasion, and employing flexible encryption methods based on file size. The group targets medium to large organizations across various sectors, particularly in the Asia-Pacific region, and has demonstrated a high level of technical maturity and operational discipline. Their activities include systematic compromise of enterprise environments, mass account enumeration, and the use of encrypted channels for data exfiltration.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
- [T1027.002 Software Packing](https://attack.mitre.org/techniques/T1027/002)
- [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)
- [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)
- [T1683.001 Written Content](https://attack.mitre.org/techniques/T1683/001)
- [T1036 Masquerading](https://attack.mitre.org/techniques/T1036)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1036.001 Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657)
- [T1683.002 Audio-Visual Content](https://attack.mitre.org/techniques/T1683/002)
- [T1219.002 Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002)
- [T1585 Establish Accounts](https://attack.mitre.org/techniques/T1585)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)

### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Group Profile, Network Edge | Cisco | Erlang/OTP SSH server | CVE-2025-32433 |
| Group Profile, Network Edge | Fortinet | FortiOS & FortiProxy | CVE-2024-55591 |
| Group Profile, Microsoft Products | MS Server Products | SMBv1 | CVE-2017-0144 |
| Group Profile, Microsoft Products | Windows | Local Security Authority (LSA) | CVE-2021-36942 |
| Group Profile, Microsoft Products | Windows | NetLogon | CVE-2020-1472 |
| Group Profile, Microsoft Products | Windows | SMB Client | CVE-2025-33073 |
| Group Profile, Microsoft Products | Windows | SmartScreen | CVE-2024-21412 |

### ATT&CK technique IDs (denormalized)

- [T1018](https://attack.mitre.org/techniques/T1018/)
- [T1027.002](https://attack.mitre.org/techniques/T1027/002/)
- [T1036](https://attack.mitre.org/techniques/T1036/)
- [T1036.001](https://attack.mitre.org/techniques/T1036/001/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1068](https://attack.mitre.org/techniques/T1068/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1219.002](https://attack.mitre.org/techniques/T1219/002/)
- [T1486](https://attack.mitre.org/techniques/T1486/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [T1585](https://attack.mitre.org/techniques/T1585/)
- [T1585.001](https://attack.mitre.org/techniques/T1585/001/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1657](https://attack.mitre.org/techniques/T1657/)
- [T1683.001](https://attack.mitre.org/techniques/T1683/001/)
- [T1683.002](https://attack.mitre.org/techniques/T1683/002/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **PowerDuke**
- **POWERSTATS**
- **Power Loader**
- **POWERSOURCE**
- **PowerRAT**
- **CrossRat**

### MITRE ATT&CK Software
- [Wevtutil (S0645) — tool](https://attack.mitre.org/software/S0645)
- [The Gentlemen Ransomware (S9051) — malware](https://attack.mitre.org/software/S9051)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | DumpBrowserSecrets, KslKatz, Mimikatz |
| Defense Evasion | EDRStartupHinder, KslDump, PowerRun, RedSun, ThrottleStop driver (BYOVD) |
| Discovery | API-C99-NL, Advanced IP Scanner, Censys, CertiHound, Gogo, MANSPIDER, Nmap, PrivHound, RelayKing-Depth, Shodan, SoftPerfect NetScan, TaskHound |
| Exfiltration | RClone, WinSCP |
| LOLBAS | PsExec |
| Networking | Amnezia VPN, Chisel, Cloudflared, OpenSSH, OpenVPN, Proxychains, PuTTY, Wireguard VPN |
| OffSec | Impacket, NetExec, PowerZure, RegPwn, Responder, Titanis, Velociraptor, ZeroPulse |
| RMM Tools | AnyDesk, FreeRDP, MeshAgent |

## Attribution and Evidence
*Information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G1058)
[4] [BradyUnit42_TheGentlemen_July2026](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/)
   Brady, M. (2026, July 10). No Manners Here: The Ruthless Rise of The Gentlemen Ransomware. Retrieved September 18, 2026.
[5] [CarveyODonnellWelchHuntress_TheGentlemen_May2026](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps)
   Carvey, H., O'Donnell-Welch, L. (2026, May 21). The Gentlemen (Ransomware) in Disguise: Defense Evasion and other TTPs. Retrieved September 18, 2026.
[6] [CheckPointResearch_TheGentlemen_April2026](https://research.checkpoint.com/2026/dfir-report-the-gentlemen/)
   Check Point Research. (2026, April 20). DFIR Report – The Gentlemen & SystemBC: A Sneak Peek Behind the Proxy. Retrieved September 18, 2026.
[7] [Intel471_TheGentlemen_Aug2026](https://www.intel471.com/blog/threat-hunting-case-study-the-gentlemen)
   Intel 471. (2026, August 11). Threat Hunting Case Study: The Gentlemen. Retrieved September 18, 2026.
[8] [MSTI_GentelmenRansomware_May2026](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
   Microsoft Threat Intelligence. (2026, May 28). The Gentlemen ransomware: Dissecting a self-propagating Go encryptor . Retrieved September 18, 2026.
[9] [TrendAI_TheGentlemen_Sept2025](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/unmasking-the-gentlemen-ransomware)
   Santos, J., et al. (2025, September 9). Unmasking The Gentlemen Ransomware: Tactics, Techniques, and Procedures Revealed . Retrieved September 18, 2026.
[10] [Sophos_TheGentlemen_Sept2026](https://www.sophos.com/en-gb/blog/ungentlemanly-behavior-insights-into-a-ransomware-operation)
   Sophos Counter Threat Unit Research Team. (2026, September 1). Ungentlemanly behavior: Insights into a ransomware operation. Retrieved September 18, 2026.
[11] [SoučekESET_Gentlemen_Jun2026](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/)
   Souček, J. (2026, June 18). Killing me gently: Inside Gentlemen’s EDR killer framework. Retrieved September 18, 2026.

