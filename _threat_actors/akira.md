---
layout: threat_actor
title: "Akira"
aliases: ["Akira", "Akira Ransomware", "GOLD SAHARA", "Howling Scorpius", "PUNK SPIDER"]
description: "Akira is a ransomware variant and ransomware deployment entity active since at least March 2023.(Citation: Arctic Wolf Akira 2023) Akira uses compromised credentials to access single-factor external ac"
permalink: /akira/
country: "Unknown"
first_seen: "2023"
last_activity: "2025"
risk_level: "High"
external_id: "G1024"
country_flag: "🏳️"
sector_focus: ["Healthcare", "Education", "Government", "Technology"]
source_attribution: "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
---

## Introduction
Akira is a ransomware variant and ransomware deployment entity active since at least March 2023.(Citation: Arctic Wolf Akira 2023) Akira uses compromised credentials to access single-factor external access mechanisms such as VPNs for initial access, then various publicly-available tools and techniques for lateral movement.(Citation: Arctic Wolf Akira 2023)(Citation: Secureworks GOLD SAHARA) Akira operations are associated with "double extortion" ransomware activity, where data is exfiltrated from victim environments prior to encryption, with threats to publish files if a ransom is not paid. Technical analysis of Akira ransomware indicates variants capable of targeting Windows or VMWare ESXi hypervisors and multiple overlaps with Conti ransomware.(Citation: BushidoToken Akira 2023)(Citation: CISA Akira Ransomware APR 2024)(Citation: Cisco Akira Ransomware OCT 2024)

## Activities and Tactics

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*This section is pending cataloguing. Check upstream sources for current IOCs.*

### IP Addresses
*Pending*

### File Hashes
*Pending*

### Domains
*Pending*

## Malware and Tools
*Information pending cataloguing.*

## Attribution and Evidence

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G1024)
   MITRE ATT&CK entry
[2] [Arctic Wolf Akira 2023](https://www.google.com/search?q=Arctic+Wolf+Akira+2023+threat+actor)
   External citation
[3] [Arctic Wolf Akira 2023](https://www.google.com/search?q=Arctic+Wolf+Akira+2023+threat+actor)
   External citation
[4] [Secureworks GOLD SAHARA](https://www.google.com/search?q=Secureworks+GOLD+SAHARA+threat+actor)
   External citation
[5] [BushidoToken Akira 2023](https://www.google.com/search?q=BushidoToken+Akira+2023+threat+actor)
   External citation
[6] [CISA Akira Ransomware APR 2024](https://www.google.com/search?q=CISA+Akira+Ransomware+APR+2024+threat+actor)
   External citation
[7] [Cisco Akira Ransomware OCT 2024](https://www.google.com/search?q=Cisco+Akira+Ransomware+OCT+2024+threat+actor)
   External citation

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

