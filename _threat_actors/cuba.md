---
layout: threat_actor
title: "Cuba"
aliases: ["COLDDRAW","Cuba","Fidel"]
description: "The Cuba Ransomware, also known as Colddraw Ransomware, was first identified in the threat landscape in 2019 and built a relatively small but selected list of victims. The group is also known as Fidel "
permalink: /cuba/
---

## Introduction
The Cuba Ransomware, also known as Colddraw Ransomware, was first identified in the threat landscape in 2019 and built a relatively small but selected list of victims. The group is also known as Fidel Ransomware, due to a characteristic marker placed at the beginning of all encrypted files. This file marker is used as an indicator for the ransomware and its decoder that the file has been encrypted. Despite its name and the Cuban nationalist style on its leak site, it is difficult to assert any connection or affiliation with the Republic of Cuba. The group has been linked to a Russian-language threat actor by Profero researchers due to some details of incorrect translation they discovered, as well as the discovery of a 404 page containing text in Russian on the threat actor's own leak site. According to BlackBerry, based on the analysis of the code strings used in the campaign analyzed in 2023, there were indications that the developer behind the Cuba ransomware speaks Russian. The ransomware operators use a double extortion approach, and following the USA, in August 2022, it was believed that the Cuba ransomware group had compromised 101 entities, demanding $145 million in ransom payments and receiving up to $60 million. The group used a similar set of TTPs, with only a slight change each year, as they generally consist of LOLBins (executables that are part of the operating system and can be exploited to support an attack), exploits, off-the-shelf and custom malware, as well as intrusion tools like Cobalt Strike and Metasploit. In 2022, the group allegedly developed a relationship with operators of the Industrial Spy market, using their platform as a means of data leakage.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 |
| Applications | Veeam | Backup & Replication | CVE-2022-26500, CVE-2022-26501 |
| Applications | Veeam | Backup & Replication | CVE-2023-27532 |
| Microsoft Products | Windows | CLFS | CVE-2022-24521 |
| Microsoft Products | Windows | NetLogon | CVE-2020-1472 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **BlackEnergy**: 
- **BLACKCOFFEE**: 
- **Blackshades**: 
- **BlackNix**: 
- **Small-Net**: 
- **Xploit**: 
- **Archelaus Beta**: 
- **BlackHole**: 
- **Cobalt Strike**: 

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz |
| Defense Evasion | Avast Anti-Rootkit driver |
| LOLBAS | PsExec |
| Networking | Termite |
| OffSec | Cobalt Strike, Meterpreter |
| RMM Tools | NetSupport |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

