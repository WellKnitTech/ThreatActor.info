---
layout: threat_actor
title: "Conti"
aliases: ["Ryuk", "Wizard Spider"]
description: "Conti is a Russian ransomware-as-a-service operation known for targeting healthcare and critical infrastructure."
permalink: /conti/
---

## Introduction
Conti is a Russian ransomware-as-a-service operation known for targeting healthcare and critical infrastructure.

## Activities and Tactics
**Targeted Sectors**: Healthcare, Critical Infrastructure, Government

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: Critical

**First Seen**: 2020

**Last Activity**: 2022


## Notable Campaigns
- [Gloucester Council](https://democracy.gloucester.gov.uk/documents/s59774/Appendix%201%20-%20Executive%20Summary%20of%20NCC%20Group%20Report.pdf) (November 2021; Conti (Ransomware))
- [Irish HSE](https://www.hse.ie/eng/services/news/media/pressrel/hse-publishes-independent-report-on-conti-cyber-attack.html) (May 2021; Conti (Ransomware))

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Network Edge | Fortinet | FortiOS | CVE-2018-13374 |
| Network Edge | Fortinet | FortiOS | CVE-2018-13379 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2020-0688 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 |
| Microsoft Products | MS Server Products | SMBv3 | CVE-2020-0796 |
| Virtualization | VMware | vCenter Server | CVE-2021-22005 |
| Virtualization | VMware | vSphere Client | CVE-2021-21985 |
| Microsoft Products | Windows | Active Directory | CVE-2021-42278, CVE-2021-42287 |
| Microsoft Products | Windows | MSHTML | CVE-2021-40444 |
| Microsoft Products | Windows | NetLogon | CVE-2020-1472 |
| Microsoft Products | Windows | Print Spooler | CVE-2021-1675, CVE-2021-34527 |
| Microsoft Products | Windows | Remote Desktop Gateway | CVE-2020-0609 |

## Notable Indicators of Compromise (IOCs)
*No separately curated network indicators or file hashes are listed for this actor. Known exploited vulnerabilities appear in the **CISA Known Exploited Vulnerabilities (KEV)** section below.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz, ProcDump, Router Scan, SharpChrome |
| Defense Evasion | GMER, PCHunter |
| Discovery | AdFind, Bloodhound, PowerView, Seatbelt, ShareFinder, SharpView, SoftPerfect NetScan |
| Exfiltration | Dropfiles, MEGA, Qaz[.]im, RClone, Sendspace, WinSCP |
| LOLBAS | BITSAdmin, NTDS Utility (ntdsutil), PsExec, WMIC |
| OffSec | Cobalt Strike, Metasploit, Meterpreter, PowerShell Empire, PowerSploit, Rubeus |
| RMM Tools | AnyDesk, Atera, Splashtop |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

## CISA Known Exploited Vulnerabilities (KEV)
*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*

| CVE ID | Vendor | Product | Date Added |
|-------|-------|--------|----------|
| CVE-2025-29635 | D-Link | DIR-823X | 2026-04-24 |
| CVE-2026-21509 | Microsoft | Office | 2026-01-26 |
| CVE-2025-59374 | ASUS | Live Update | 2025-12-17 |
| CVE-2018-4063 | Sierra Wireless | AirLink ALEOS | 2025-12-12 |
| CVE-2022-37055 | D-Link | Routers | 2025-12-08 |
| CVE-2022-48503 | Apple | Multiple Products | 2025-10-20 |
| CVE-2010-3962 | Microsoft | Internet Explorer | 2025-10-06 |
| CVE-2013-3918 | Microsoft | Windows | 2025-10-06 |
| CVE-2023-50224 | TP-Link | TL-WR841N | 2025-09-03 |
| CVE-2025-9377 | TP-Link | Multiple Routers | 2025-09-03 |
| CVE-2020-24363 | TP-Link | TL-WA855RE | 2025-09-02 |
| CVE-2013-3893 | Microsoft | Internet Explorer | 2025-08-12 |
| CVE-2020-25078 | D-Link | DCS-2530L and DCS-2670L Devices | 2025-08-05 |
| CVE-2020-25079 | D-Link | DCS-2530L and DCS-2670L Devices | 2025-08-05 |
| CVE-2022-40799 | D-Link | DNR-322L | 2025-08-05 |
| CVE-2023-33538 | TP-Link | Multiple Routers | 2025-06-16 |
| CVE-2021-32030 | ASUS | Routers | 2025-06-02 |
| CVE-2024-11120 | GeoVision | Multiple Devices | 2025-05-07 |
| CVE-2024-6047 | GeoVision | Multiple Devices | 2025-05-07 |
| CVE-2025-1316 | Edimax | IC-7100 IP Camera | 2025-03-19 |
| CVE-2018-13374 | Fortinet | FortiOS and FortiADC | 2022-09-08 |
| CVE-2019-1322 | Microsoft | Windows | 2022-03-15 |
| CVE-2020-0796 | Microsoft | SMBv3 | 2022-02-10 |
| CVE-2018-13379 | Fortinet | FortiOS | 2021-11-03 |
| CVE-2020-0688 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-1732 | Microsoft | Win32k | 2021-11-03 |
| CVE-2021-34527 | Microsoft | Windows | 2021-11-03 |
| CVE-2020-1472 | Microsoft | Netlogon | 2021-11-03 |
| CVE-2021-26855 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-26858 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-27065 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-1675 | Microsoft | Windows | 2021-11-03 |
| CVE-2021-26857 | Microsoft | Exchange Server | 2021-11-03 |
| CVE-2021-22005 | VMware | vCenter Server | 2021-11-03 |
| CVE-2021-21972 | VMware | vCenter Server | 2021-11-03 |
| CVE-2021-21985 | VMware | vCenter Server | 2021-11-03 |

