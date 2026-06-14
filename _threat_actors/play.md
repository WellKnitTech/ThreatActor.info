---
layout: threat_actor
title: "Play"
aliases: ["Play","play","Play Ransomware","PLAY Ransomware"]
description: "Play is a ransomware group that has been active since at least 2022 deploying Playcrypt ransomware against the business, government, critical infrastructure, healthcare, and media sectors in North Amer"
permalink: /play/
---

## Introduction
Play is a ransomware group that has been active since at least 2022 deploying Playcrypt ransomware against the business, government, critical infrastructure, healthcare, and media sectors in North America, South America, and Europe. Play actors employ a double-extortion model, encrypting systems after exfiltrating data, and are presumed by security researchers to operate as a closed group. [CISA Play Ransomware Advisory December 2023](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a) [Trend Micro Ransomware Spotlight Play July 2023](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-play)

## Activities and Tactics
**Targeted Sectors**: Healthcare, Education, Government, Technology

**Country of Origin**: 🏳️ Unknown

**Risk Level**: High

**First Seen**: 2022

**Last Activity**: 2025


## Notable Campaigns
- Community-reported ransomware incident: April 2025, Retail, Canada (source: [CR-016-PLAY-APR-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-016-PLAY-APR-2025.md))

## Tactics, Techniques, and Procedures (TTPs)
- [T1030 Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030)
- [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010)
- [T1587.001 Malware](https://attack.mitre.org/techniques/T1587/001)
- [T1078.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003)
- [T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1078.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002)
- [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1518.001 Security Software Discovery](https://attack.mitre.org/techniques/T1518/001)
- [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657)
- [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)

### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Network Edge | Fortinet | FortiOS | CVE-2018-13379 |
| Network Edge | Fortinet | FortiOS SSL VPN | CVE-2020-12812 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2022-41040, CVE-2022-41082 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2022-41080 |
| Applications | SimpleHelp | SimpleHelp RMM | CVE-2024-57727 |

### ATT&CK technique IDs (denormalized)

- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1016](https://attack.mitre.org/techniques/T1016/)
- [T1018](https://attack.mitre.org/techniques/T1018/)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [T1027.010](https://attack.mitre.org/techniques/T1027/010/)
- [T1030](https://attack.mitre.org/techniques/T1030/)
- [T1048](https://attack.mitre.org/techniques/T1048/)
- [T1057](https://attack.mitre.org/techniques/T1057/)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1078.002](https://attack.mitre.org/techniques/T1078/002/)
- [T1078.003](https://attack.mitre.org/techniques/T1078/003/)
- [T1082](https://attack.mitre.org/techniques/T1082/)
- [T1083](https://attack.mitre.org/techniques/T1083/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1133](https://attack.mitre.org/techniques/T1133/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1518.001](https://attack.mitre.org/techniques/T1518/001/)
- [T1560.001](https://attack.mitre.org/techniques/T1560/001/)
- [T1587.001](https://attack.mitre.org/techniques/T1587/001/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1657](https://attack.mitre.org/techniques/T1657/)
- [T1685](https://attack.mitre.org/techniques/T1685/)
- [T1685.005](https://attack.mitre.org/techniques/T1685/005/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CyberGate**: 
- **Cyber Eye RAT**: 
- **Archelaus Beta**: 
- **RemoteCMD**: 
- **Remote Utilities**: 
- **RemotePC**: 

### MITRE ATT&CK Software
- [Nltest (S0359) — tool](https://attack.mitre.org/software/S0359)
- [AdFind (S0552) — tool](https://attack.mitre.org/software/S0552)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)
- [Empire (S0363) — tool](https://attack.mitre.org/software/S0363)
- [Wevtutil (S0645) — tool](https://attack.mitre.org/software/S0645)
- [Cobalt Strike (S0154) — malware](https://attack.mitre.org/software/S0154)
- [Playcrypt (S1162) — malware](https://attack.mitre.org/software/S1162)
- [BloodHound (S0521) — tool](https://attack.mitre.org/software/S0521)
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | HandleKatz, Mimikatz, Nanodump |
| Defense Evasion | EDRKill (echo_driver.sys + DBUtil 2.3), GMER, IOBit, PCHunter, PowerTool, icardagt.exe |
| Discovery | AdFind, WKTools |
| Exfiltration | WinSCP |
| LOLBAS | PsExec |
| Networking | Fast Reverse Proxy Client (FRPC), Plink |
| OffSec | Cobalt Strike, WinPEAS |

## Attribution and Evidence
**Country of Origin**: Unknown
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G1040)
[2] [CISA Play Ransomware Advisory December 2023](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
   CISA. (2023, December 18). #StopRansomware: Play Ransomware AA23-352A. Retrieved September 24, 2024.
[3] [Trend Micro Ransomware Spotlight Play July 2023](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-play)
   Trend Micro Research. (2023, July 21). Ransomware Spotlight: Play. Retrieved September 24, 2024.

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [How Can Soccer Players Bend Their Shots in Midair?](https://www.wired.com/story/how-can-soccer-players-bend-their-shots-in-midair/)
  Wired - 2026-06-13T

