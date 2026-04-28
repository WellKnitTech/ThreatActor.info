---
layout: threat_actor
title: "Qilin"
aliases: ["Qilin Ransomware"]
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
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations
| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications | Veeam | Backup & Replication | CVE-2023-27532 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
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

