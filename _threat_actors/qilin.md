---
layout: threat_actor
title: "Qilin"
aliases: ["Agenda","Qilin","Qilin Gang","Qilin Group","Qilin Ransomware","Qilin Team"]
description: "Qilin is a ransomware group that first appeared in 2022 but had a breakout year in 2024, with around 200 victims, 156 of them based in the U.S."
permalink: /qilin/
---

## Introduction
Qilin is a ransomware group that first appeared in 2022 but had a breakout year in 2024, with around 200 victims, 156 of them based in the U.S.

## Activities and Tactics
**Targeted Sectors**: Critical Infrastructure, Manufacturing, Healthcare, Government

**Country of Origin**: 🏳️ Unknown

**Risk Level**: High

**First Seen**: 2022

**Last Activity**: 2025


## Notable Campaigns
- Community-reported ransomware incident: April 2023, Manufacturing, Asia Pacific (source: [CR-012-Qilin-April-2023.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-012-Qilin-April-2023.md))
- Community-reported ransomware incident: June 2022, Unknown, Unknown (source: [CR-013-Qilin-June-2022.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-013-Qilin-June-2022.md))
- Community-reported ransomware incident: May 2024, Unknown, USA (source: [CR-014-Qilin-May-2024.md](https://github.com/BushidoUK/Ransomware-Tool-Matrix/blob/main/CommunityReports/CR-014-Qilin-May-2024.md))

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications, Group Profile | Apache | Apache bRPC | CVE-2025-60021 |
| Group Profile, Network Edge | Check Point | VPN Remote Access and Mobile Access | CVE-2026-50751 |
| Group Profile, Network Edge | Fortinet | FortiOS | CVE-2025-59718 |
| Group Profile, Network Edge | Fortinet | FortiOS & FortiProxy | CVE-2024-21762 |
| Group Profile, Network Edge | Fortinet | FortiOS & FortiProxy | CVE-2024-55591 |
| Applications, Group Profile | SmarterTools | SmarterMail | CVE-2026-24423 |
| Applications, Group Profile | SolarWinds | SolarWinds Web Help Desk | CVE-2025-40554 |
| Applications, Group Profile | Telnet | Telnetd in GNU Inetutils | CVE-2026-24061 |
| Applications, Group Profile | Veeam | Backup & Replication | CVE-2023-27532 |
| Group Profile, Network Edge | WatchGuard | WatchGuard Fireware OS | CVE-2025-14733 |
| Group Profile, Network Edge | WatchGuard | WatchGuard Fireware OS | CVE-2025-9242 |
| Group Profile | Zemana | Zemana AntiLogger | CVE-2024-1853 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Agenda**: 
- **Qilin**: 

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz |
| Defense Evasion | EDRSandBlast, PCHunter, PowerTool, Toshiba power management driver (BYOVD), Updater for Carbon Black’s Cloud Sensor AV (upd.exe), YDArk, Zemana Anti-Rootkit driver |
| Discovery | Nmap, Nping |
| Exfiltration | EasyUpload, EasyUpload.io, FTP (102GB), HTTP/S (783GB), MEGA cloud storage (30GB), Not observed (3 systems encrypted) |
| LOLBAS | PowerShell, PsExec, WinRM, fsutil |
| Networking | Proxychains, RDP, Used SCCM and VMWare ESXi for lateral movement in network, Used SMB, RDP, WMI for lateral movement in network, WMI, lateral movement via DCE-RPC and RDP |
| OffSec | Cobalt Strike, Cobalt Strike - (HTTP/SSL traffic linked to Cobalt Strike, including PowerShell request for sihost64.dll), Evilginx, Kali Linux, NetExec, SystemBC, Tofsee a modular trojan |
| RMM Tools | NetSupport, ScreenConnect |

## Attribution and Evidence
**Country of Origin**: Unknown
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

