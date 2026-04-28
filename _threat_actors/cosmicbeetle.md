---
layout: threat_actor
title: "CosmicBeetle"
aliases: ["CosmicBeetle"]
description: "CosmicBeetle is a threat actor known for deploying the ScRansom ransomware, which has replaced its previous variant, Scarab. The actor utilizes a custom toolset called Spacecolon, consisting of ScHackT"
permalink: /cosmicbeetle/
---

## Introduction
CosmicBeetle is a threat actor known for deploying the ScRansom ransomware, which has replaced its previous variant, Scarab. The actor utilizes a custom toolset called Spacecolon, consisting of ScHackTool, ScInstaller, and ScService, to gain initial access through RDP brute forcing and exploiting vulnerabilities like CVE-2020-1472 and FortiOS SSL-VPN. CosmicBeetle has been observed impersonating the LockBit ransomware gang to leverage its reputation and has shown a tendency to leave artifacts on compromised systems. The group primarily targets SMBs globally, employing techniques such as credential dumping and data destruction.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Network Edge | Fortinet | FortiOS SSL-VPN | CVE-2022-42475 |
| Microsoft Products | MS Server Products | SMBv1 | CVE-2017-0144 |
| Applications | Veeam | Backup & Replication | CVE-2023-27532 |
| Microsoft Products | Windows | Active Directory | CVE-2021-42278, CVE-2021-42287 |
| Microsoft Products | Windows | NetLogon | CVE-2020-1472 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CosmicDuke**
- **SPACESHIP**
- **Xploit**

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Defense Evasion | Darkside (TrueSight driver), RealBlindingEDR, Reaper |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

