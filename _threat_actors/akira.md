---
layout: threat_actor
title: "Akira"
aliases: ["Akira","Akira Ransomware","GOLD SAHARA","Howling Scorpius","PUNK SPIDER","Punk Spider (CrowdStrike)","Storm-1567 (Microsoft)"]
description: "Akira is a ransomware variant and ransomware deployment entity active since at least March 2023. [Arctic Wolf Akira 2023](https://arcticwolf.com/resources/blog/conti-and-akira-chained-together/) Akira "
permalink: /akira/
---

## Introduction
Akira is a ransomware variant and ransomware deployment entity active since at least March 2023. [Arctic Wolf Akira 2023](https://arcticwolf.com/resources/blog/conti-and-akira-chained-together/) Akira uses compromised credentials to access single-factor external access mechanisms such as VPNs for initial access, then various publicly-available tools and techniques for lateral movement. [Arctic Wolf Akira 2023](https://arcticwolf.com/resources/blog/conti-and-akira-chained-together/) [Secureworks GOLD SAHARA](https://www.secureworks.com/research/threat-profiles/gold-sahara) Akira operations are associated with "double extortion" ransomware activity, where data is exfiltrated from victim environments prior to encryption, with threats to publish files if a ransom is not paid. Technical analysis of Akira ransomware indicates variants capable of targeting Windows or VMWare ESXi hypervisors and multiple overlaps with Conti ransomware. [BushidoToken Akira 2023](https://blog.bushidotoken.net/2023/09/tracking-adversaries-akira-another.html) [CISA Akira Ransomware APR 2024](https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf) [Cisco Akira Ransomware OCT 2024](https://blog.talosintelligence.com/akira-ransomware-continues-to-evolve/)

## Activities and Tactics
**Targeted Sectors**: Healthcare, Education, Government, Technology

**Country of Origin**: 🏳️ Unknown

**Risk Level**: High

**First Seen**: 2023

**Last Activity**: 2025


## Notable Campaigns
- [Nissan Australia](https://www.nissan.com.au/website-update.html) (December 2023; Akira (Ransomware))
- [BHI Energy](https://www.documentcloud.org/documents/24075435-bhi-notice) (October 2023; Akira (Ransomware))
- Community-reported ransomware incident: June 2025, Construction, Canada (source: [CR-001-AKIRA-JUN-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-001-AKIRA-JUN-2025.md))
- Community-reported ransomware incident: April 2025, Food and Agriculture, Canada (source: [CR-002-AKIRA-APR-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-002-AKIRA-APR-2025.md))
- Community-reported ransomware incident: June 2025, Manufacturing, Canada (source: [CR-003-AKIRA-JUN-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-003-AKIRA-JUN-2025.md))
- Community-reported ransomware incident: August 2025, Construction, USA (source: [CR-009-AKIRA-AUG-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-009-AKIRA-AUG-2025.md))
- Community-reported ransomware incident: August 2025, Engineering, USA (source: [CR-010-AKIRA-AUG-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-010-AKIRA-AUG-2025.md))
- Community-reported ransomware incident: September 2025, Professional Services, Canada (source: [CR-017-AKIRA-SEP-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-017-AKIRA-SEP-2025.md))
- Community-reported ransomware incident: November 2025, Manufacturing, Canada (source: [CR-018-AKIRA-NOV-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-018-AKIRA-NOV-2025.md))

## Tactics, Techniques, and Procedures (TTPs)
- [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)
- [T1213.002 Sharepoint](https://attack.mitre.org/techniques/T1213/002)
- [T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531)
- [T1482 Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657)
- [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)
- [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133)
- [T1027.001 Binary Padding](https://attack.mitre.org/techniques/T1027/001)
- [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)
- [T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219)
- [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001)

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

### ATT&CK technique IDs (denormalized)

- [T1018](https://attack.mitre.org/techniques/T1018/)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [T1027.001](https://attack.mitre.org/techniques/T1027/001/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1133](https://attack.mitre.org/techniques/T1133/)
- [T1213.002](https://attack.mitre.org/techniques/T1213/002/)
- [T1219](https://attack.mitre.org/techniques/T1219/)
- [T1482](https://attack.mitre.org/techniques/T1482/)
- [T1486](https://attack.mitre.org/techniques/T1486/)
- [T1531](https://attack.mitre.org/techniques/T1531/)
- [T1558](https://attack.mitre.org/techniques/T1558/)
- [T1560.001](https://attack.mitre.org/techniques/T1560/001/)
- [T1567.002](https://attack.mitre.org/techniques/T1567/002/)
- [T1657](https://attack.mitre.org/techniques/T1657/)
- [T1685](https://attack.mitre.org/techniques/T1685/)

## Notable Indicators of Compromise (IOCs)
*No separately curated network indicators or file hashes are listed for this actor. Known exploited vulnerabilities appear in the **CISA Known Exploited Vulnerabilities (KEV)** section below.*

## Malware and Tools
### MITRE ATT&CK Software
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)
- [AdFind (S0552) — tool](https://attack.mitre.org/software/S0552)
- [Akira _v2 (S1194) — malware](https://attack.mitre.org/software/S1194)
- [Akira (S1129) — malware](https://attack.mitre.org/software/S1129)
- [Megazord (S1191) — malware](https://attack.mitre.org/software/S1191)
- [LaZagne (S0349) — tool](https://attack.mitre.org/software/S0349)
- [Rclone (S1040) — tool](https://attack.mitre.org/software/S1040)

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
[1] [mitre-attack](https://attack.mitre.org/groups/G1024)
[5] [CISA Akira Ransomware APR 2024](https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf)
   CISA et al. (2024, April 18). #StopRansomware: Akira Ransomware. Retrieved December 10, 2024.
[6] [CrowdStrike PUNK SPIDER](https://www.crowdstrike.com/adversaries/punk-spider/)
   CrowdStrike. (n.d.). Punk Spider. Retrieved February 20, 2024.
[7] [Cisco Akira Ransomware OCT 2024](https://blog.talosintelligence.com/akira-ransomware-continues-to-evolve/)
   Nutland, J. and Szeliga, M. (2024, October 21). Akira ransomware continues to evolve. Retrieved December 10, 2024.
[8] [Secureworks GOLD SAHARA](https://www.secureworks.com/research/threat-profiles/gold-sahara)
   Secureworks. (n.d.). GOLD SAHARA. Retrieved February 20, 2024.
[9] [Arctic Wolf Akira 2023](https://arcticwolf.com/resources/blog/conti-and-akira-chained-together/)
   Steven Campbell, Akshay Suthar, & Connor Belfiorre. (2023, July 26). Conti and Akira: Chained Together. Retrieved February 20, 2024.
[10] [BushidoToken Akira 2023](https://blog.bushidotoken.net/2023/09/tracking-adversaries-akira-another.html)
   Will Thomas. (2023, September 15). Tracking Adversaries: Akira, another descendent of Conti. Retrieved February 21, 2024.
[11] [Palo Alto Howling Scorpius DEC 2024](https://unit42.paloaltonetworks.com/threat-assessment-howling-scorpius-akira-ransomware/)
   Zemah, Y. (2024, December 2). Threat Assessment: Howling Scorpius (Akira Ransomware). Retrieved January 8, 2025.

## CISA Known Exploited Vulnerabilities (KEV)
*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*

| CVE ID | Vendor | Product | Date Added |
|-------|-------|--------|----------|
| CVE-2019-6693 | Fortinet | FortiOS | 2025-06-25 |
| CVE-2024-40711 | Veeam | Backup & Replication | 2024-10-17 |
| CVE-2024-40766 | SonicWall | SonicOS | 2024-09-09 |
| CVE-2024-37085 | VMware | ESXi | 2024-07-30 |
| CVE-2023-48788 | Fortinet | FortiClient EMS | 2024-03-25 |
| CVE-2020-3259 | Cisco | Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) | 2024-02-15 |
| CVE-2023-20269 | Cisco | Adaptive Security Appliance and Firepower Threat Defense | 2023-09-13 |
| CVE-2023-27532 | Veeam | Backup & Replication | 2023-08-22 |
| CVE-2023-28252 | Microsoft | Windows | 2023-04-11 |
| CVE-2022-40684 | Fortinet | Multiple Products | 2022-10-11 |
| CVE-2020-3580 | Cisco | Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) | 2021-11-03 |

