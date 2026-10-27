---
layout: threat_actor
title: "Dragonforce"
aliases: ["DragonForce","Hackledorb","Storm-2380","dragonforce"]
description: "DragonForce is a ransomware-as-a-service (RaaS) group first identified in late 2023. Originally linked to hacktivist activity, the group pivoted to financially motivated operations by early 2024. Since"
permalink: /dragonforce/
---

## Introduction
DragonForce is a ransomware-as-a-service (RaaS) group first identified in late 2023. Originally linked to hacktivist activity, the group pivoted to financially motivated operations by early 2024. Since then, it has accelerated into a highly organized cartel-like network, providing customizable payloads to affiliates, a sophisticated affiliate portal, and shared infrastructure for leak sites and campaigns. The group has targeted a wide range of sectors globally, including major UK retailers such as M&S, Harrods, and Co-op, along with organizations in government, logistics, and manufacturing. Its operations are known for strategic branding flexibility, enabling affiliates to operate under their own labels using DragonForce’s backend services.

## Activities and Tactics
**Country of Origin**: 🏳️ Malaysia





## Notable Campaigns
- Community-reported ransomware incident: April 2025, UK (source: [CR-021-DRAGONFORCE-APR-2025.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-021-DRAGONFORCE-APR-2025.md))
- Community-reported ransomware incident: February 2026, Australia (source: [CR-022-DRAGONFORCE-FEB-2026.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-022-DRAGONFORCE-FEB-2026.md))
- Community-reported ransomware incident: August 2024, UK (source: [CR-023-DRAGONFORCE-AUG-2024.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-023-DRAGONFORCE-AUG-2024.md))

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications, Group Profile | Apache | Log4j | CVE-2021-44228 |
| Group Profile, Virtualization | Citrix | NetScaler ADC & Gateway | CVE-2025-5777 |
| Group Profile, Network Edge | Fortinet | FortiOS & FortiProxy | CVE-2024-21762 |
| Group Profile, Network Edge | Fortinet | FortiOS & FortiProxy | CVE-2024-55591 |
| Group Profile, Network Edge | Pulse Secure / Ivanti | Ivanti Connect Secure | CVE-2023-46805 |
| Group Profile, Network Edge | Pulse Secure / Ivanti | Ivanti Connect Secure | CVE-2024-21887 |
| Group Profile, Network Edge | Pulse Secure / Ivanti | Ivanti Connect Secure | CVE-2024-21893 |
| Group Profile | SimpleHelp | SimpleHelp RMM | CVE-2024-57727, CVE-2024-57728 |
| Group Profile, Network Edge | SonicWall | SonicOS SSL-VPN | CVE-2024-40766 |
| Group Profile, Microsoft Products | Windows | SmartScreen | CVE-2024-21412 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CyberGate**
- **Cyber Eye RAT**

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Get-VeeamCreds.ps1, LaZagne, Mimikatz, ZeroLogon.exe (CVE-2020-1472) |
| Defense Evasion | ADVobfuscator, Darkside/TrueSight driver (BYOVD), Hangzhou Shunwang Technology driver (BYOVD), KslD.sys (BYOVD), PCHunter, ProcessHacker, TruesightKiller (W32.Riskware.Killav), Vulnerable drivers (BYOVD), Windows Defender Real-time Protection disabled |
| Discovery | AdFind, Advanced IP Scanner, PingCastle, PingCastle 3.1.0.1, SoftPerfect NetScan, SoftPerfect netscan |
| Exfiltration | AWS S3 bucket (wasabisys), MEGA, RClone, Restic |
| LOLBAS | PowerShell (-EncodedCommand), PowerShell (IEX downloadstring), PsExec, RDP (External Remote Services) |
| Networking | rPivot (SOCKS4 reverse proxy) |
| OffSec | Cobalt Strike, Cobalt Strike (attempted download), PsExec (PSEXESVC.exe) |
| RMM Tools | AnyDesk, SimpleHelp |

## Attribution and Evidence
**Country of Origin**: Malaysia
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

