---
layout: threat_actor
title: "Play"
aliases: ["Play", "Play Ransomware"]
description: "Play is a ransomware group that has been active since at least 2022 deploying  Playcrypt ransomware against the business, government, critical infrastructure, healthcare, and media sectors in North Ame"
permalink: /play/
---

## Introduction
Play is a ransomware group that has been active since at least 2022 deploying Playcrypt ransomware against the business, government, critical infrastructure, healthcare, and media sectors in North America, South America, and Europe. Play actors employ a double-extortion model, encrypting systems after exfiltrating data, and are presumed by security researchers to operate as a closed group.

## Activities and Tactics
**Targeted Sectors**: Healthcare, Education, Government, Technology

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
| Network Edge | Fortinet | FortiOS | CVE-2018-13379 |
| Network Edge | Fortinet | FortiOS SSL VPN | CVE-2020-12812 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2022-41040, CVE-2022-41082 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2022-41080 |
| Applications | SimpleHelp | SimpleHelp RMM | CVE-2024-57727 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
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
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G1040)
   MITRE ATT&CK entry

