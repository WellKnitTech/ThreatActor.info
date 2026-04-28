---
layout: threat_actor
title: "Prophet Spider"
aliases: ["GOLD MELODY", "UNC961", "Prophet Spider"]
description: "PROPHET SPIDER is an eCrime actor, active since at least May 2017, that primarily gains access to victims by compromising vulnerable web servers, which commonly involves leveraging a variety of publicl"
permalink: /prophet-spider/
---

## Introduction
PROPHET SPIDER is an eCrime actor, active since at least May 2017, that primarily gains access to victims by compromising vulnerable web servers, which commonly involves leveraging a variety of publicly disclosed vulnerabilities. The adversary has likely functioned as an access broker — handing off access to a third party to deploy ransomware — in multiple instances.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications, Group Profile | Apache | Log4j | CVE-2021-4104 |
| Applications, Group Profile | Apache | Log4j | CVE-2021-44228 |
| Applications, Group Profile | Apache | Struts | CVE-2017-5638 |
| Group Profile, Virtualization | Citrix | ShareFile Storage Zones Controller | CVE-2021-22941 |
| Applications, Group Profile | Java Applications | Jboss Application Server | CVE-2017-7504 |
| Applications, Group Profile | Oracle | E-Business | CVE-2016-0545 |
| Applications, Group Profile | Oracle | WebLogic | CVE-2020-14750 |
| Applications, Group Profile | Oracle | WebLogic | CVE-2020-14882 |
| Applications, Group Profile | Sitecore | Sitecore XP | CVE-2021-42237 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz |
| Discovery | TXPortMap |
| Exfiltration | PSCP |
| LOLBAS | Minidump, PAExec, WinExe |
| OffSec | BurpSuite, ConPtyShell, Godzilla Web Shell, PwnTools, Responder |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

