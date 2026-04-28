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
*Information pending cataloguing.*

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
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

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

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [Bridging the AI Agent Authority Gap: Continuous Observability as the Decision Engine](https://thehackernews.com/2026/04/bridging-ai-agent-authority-gap.html)
  The Hacker News - 2026-04-24T

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
| CVE-2013-3918 | Microsoft | Internet Explorer | 2025-10-06 |
| CVE-2025-5419 | Google | Chromium V8 Engine | 2025-08-18 |
| CVE-2025-4123 | Google | Chromium V8 Engine | 2025-08-18 |
| CVE-2019-5086 | Sierra Wireless | ALEOS | 2025-08-11 |
| CVE-2019-5087 | Sierra Wireless | ALEOS | 2025-08-11 |
| CVE-2019-5069 | Sierra Wireless | ALEOS | 2025-08-11 |
| CVE-2021-28711 | Xen | Hypervisor | 2025-08-04 |
| CVE-2021-28712 | Xen | Hypervisor | 2025-08-04 |
| CVE-2012-0151 | Microsoft | Authenticode Signature Verification | 2025-07-28 |
| CVE-2025-24983 | Microsoft | Windows | 2025-07-21 |
| CVE-2025-49706 | Microsoft | SharePoint Server | 2025-07-20 |
| CVE-2024-40766 | SonicWall | SonicOS | 2024-09-09 |
| CVE-2024-37085 | VMware | ESXi | 2024-07-30 |
| CVE-2024-4577 | PHP Group | PHP | 2024-06-12 |
| CVE-2022-29303 | SolarView | Compact | 2024-05-30 |
| CVE-2024-1708 | ConnectWise | ScreenConnect | 2024-02-22 |
| CVE-2024-1709 | ConnectWise | ScreenConnect | 2024-02-22 |
| CVE-2023-27997 | Fortinet | FortiOS | 2023-06-12 |
| CVE-2023-27350 | PaperCut | MF/NG | 2023-05-12 |
| CVE-2023-27351 | PaperCut | MF/NG | 2023-05-12 |
| CVE-2023-26083 | Arm | Mali GPU Kernel Driver | 2023-04-07 |
| CVE-2023-26084 | Arm | Mali GPU Kernel Driver | 2023-04-07 |
| CVE-2022-47966 | Zoho | ManageEngine Multiple Products | 2023-01-23 |
| CVE-2022-27518 | Citrix | ADC and Gateway | 2022-12-13 |
| CVE-2022-22965 | VMware | Spring Framework | 2022-04-04 |
| CVE-2019-11510 | Ivanti | Pulse Connect Secure | 2021-11-03 |
| CVE-2019-19781 | Citrix | Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance | 2021-11-03 |
| CVE-2021-22986 | F5 | BIG-IP and BIG-IQ Centralized Management | 2021-11-03 |
| CVE-2021-34523 | Microsoft | Exchange Server | 2021-11-03 |

