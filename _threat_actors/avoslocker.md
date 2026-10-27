---
layout: threat_actor
title: "AvosLocker"
aliases: ["Avos","AvosLocker"]
description: "In March 2022, the FBI and the U.S. Treasury Financial Crimes Enforcement Network released a joint advisory addressing AvosLocker and their activity targeting organizations across several critical infr"
permalink: /avoslocker/
---

## Introduction
In March 2022, the FBI and the U.S. Treasury Financial Crimes Enforcement Network released a joint advisory addressing AvosLocker and their activity targeting organizations across several critical infrastructure sectors. The RaaS gang deploys ransomware onto their victim’s networks and systems, then threatens to leak their files on the dark web if they don’t pay up. AvosLocker is both the name of the RaaS gang, as well as the name of the ransomware itself. In May 2022, AvosLocker took responsibility for attacking and stealing data from the Texas-based healthcare organization, CHRISTUS Health. CHRISTUS Health runs hundreds of healthcare facilities across Mexico, the U.S., and South America. The group stole information from a cancer patient registry which included names, social security numbers, diagnoses, dates of birth, and other medical information. The nonprofit Catholic health system has more than 600 healthcare facilities in Texas, Louisiana, New Mexico, and Arkansas. There are also facilities in Columbia, Mexico, and Chile. Fortunately, the ransomware attack was quickly identified and was limited. While other healthcare organizations have not been as fortunate with ransomware attacks, the AvosLocker attack didn’t impact CHRISTUS Health’s patient care or clinical operations. CHRISTUS Health didn’t reveal whether or not the security incident included ransomware, data exfiltration or extortion, but due to AvosLocker’s reputation, it is more than likely that the incident included at least one of the three.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications | Apache | Log4j | CVE-2021-44228 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 |
| Applications | Veeam | Backup & Replication | CVE-2022-26500, CVE-2022-26501 |
| Applications | Zoho | ManageEngine ADSelfService Plus | CVE-2021-40539 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Dark DDoSeR**: 
- **CrossRat**: 

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | LaZagne, Mimikatz, XenArmor |
| Defense Evasion | Avast Anti-Rootkit driver |
| Discovery | NirSoft WinLister, Nmap, SoftPerfect NetScan |
| Exfiltration | FileZilla, Gofile[.]io, PSCP, RClone, share[.]riseup[.]net |
| LOLBAS | PsExec, WMIC |
| Networking | Chisel, Ligolo |
| OffSec | Cobalt Strike, Sliver |
| RMM Tools | AnyDesk, Atera, PDQ Deploy, Splashtop, TacticalRMM |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

