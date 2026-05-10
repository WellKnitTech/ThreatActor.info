---
layout: threat_actor
title: "FIN7"
aliases: ["Anunak","ATK32","Calcium","Carbanak","Carbanak - APT-C-11","Carbanak Group","Carbon Spider","CARBON SPIDER","CarbonSpider","Coreid","Coried","ELBRUS","FIN7","G0008","G0046","GOLD NIAGARA","ITG14","JokerStash","Navigator Group","Sangria Tempest"]
description: "FIN7 is a financially-motivated threat group that has been active since 2013. FIN7 has targeted the retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud s"
permalink: /fin7/
---

## Introduction
FIN7 is a financially-motivated threat group that has been active since 2013. FIN7 has targeted the retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud services, media, food and beverage, transportation, pharmaceutical, and utilities industries in the United States. A portion of FIN7 was operated out of a front company called Combi Security and often used point-of-sale malware for targeting efforts. Since 2020, FIN7 shifted operations to big game hunting (BGH), including use of REvil ransomware and their own Ransomware-as-a-Service (RaaS), Darkside. FIN7 may be linked to the Carbanak Group, but multiple threat groups have been observed using Carbanak, leading these groups to be tracked separately. [FireEye FIN7 March 2017](https://web.archive.org/web/20180808125108/https:/www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html) [FireEye FIN7 April 2017](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html) [FireEye CARBANAK June 2017](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html) [FireEye FIN7 Aug 2018](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html) [CrowdStrike Carbon Spider August 2021](https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/) [Mandiant FIN7 Apr 2022](https://www.mandiant.com/resources/evolution-of-fin7) [BiZone Lizar May 2021](https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319)

## Activities and Tactics
**Targeted Sectors**: Retail, Hospitality, Financial

**Country of Origin**: 🏳️ Unknown

**Risk Level**: High

**First Seen**: 2015

**Last Activity**: 2024

**Incident Type**: Financial Theft

## Notable Campaigns
- **Odinaff**

## Tactics, Techniques, and Procedures (TTPs)
- [T1036.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004)
- [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1102.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002)
- [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003)
- [T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1686 Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)

### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications | Veeam | Backup & Replication | CVE-2023-27532 |

### ATT&CK technique IDs (denormalized)

- [T1036.004](https://attack.mitre.org/techniques/T1036/004/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1102.002](https://attack.mitre.org/techniques/T1102/002/)
- [T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [T1219](https://attack.mitre.org/techniques/T1219/)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1686](https://attack.mitre.org/techniques/T1686/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 13 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **PowerSource**: 
- **Mimikatz**: 
- **MBR Eraser**: 
- **SoftPerfect Network Scanner**: 
- **SSHd with BackDoor**: 
- **Ammy Admin**: 
- **CVE-2012-2539 and CVE-2012-0158**: 
- **Netscan**: 
- **PsExec**: 
- **Backdoor Batel**: 
- **Bateleur JScript Backdoor**: 
- **Cobalt Strike**: 
- **Sekur**: 
- **Agent ORM**: 
- **VB Flash**: 
- **JS FLash**: 
- **Bateleur**: 

### MITRE ATT&CK Software
- [Carbanak (S0030) — malware](https://attack.mitre.org/software/S0030)
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)
- [netsh (S0108) — tool](https://attack.mitre.org/software/S0108)

## Attribution and Evidence
**Country of Origin**: Unknown
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G0046)
[7] [Mandiant FIN7 Apr 2022](https://www.mandiant.com/resources/evolution-of-fin7)
   Abdo, B., et al. (2022, April 4). FIN7 Power Hour: Adversary Archaeology and the Evolution of FIN7. Retrieved April 5, 2022.
[8] [FireEye CARBANAK June 2017](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)
   Bennett, J., Vengerik, B. (2017, June 12). Behind the CARBANAK Backdoor. Retrieved June 11, 2018.
[9] [BiZone Lizar May 2021](https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319)
   BI.ZONE Cyber Threats Research Team. (2021, May 13). From pentest to APT attack: cybercriminal group FIN7 disguises its malware as an ethical hacker’s toolkit. Retrieved February 2, 2022.
[10] [FireEye FIN7 April 2017](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)
   Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
[11] [FireEye FIN7 Aug 2018](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
   Carr, N., et al. (2018, August 01). On the Hunt for FIN7: Pursuing an Enigmatic and Evasive Global Criminal Operation. Retrieved August 23, 2018.
[12] [Secureworks GOLD NIAGARA Threat Profile](https://www.secureworks.com/research/threat-profiles/gold-niagara)
   CTU. (n.d.). GOLD NIAGARA. Retrieved September 21, 2021.
[13] [FireEye FIN7 Shim Databases](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)
   Erickson, J., McWhirt, M., Palombo, D. (2017, May 3). To SDB, Or Not To SDB: FIN7 Leveraging Shim Databases for Persistence. Retrieved July 18, 2017.
[14] [Morphisec FIN7 June 2017](http://blog.morphisec.com/fin7-attacks-restaurant-industry)
   Gorelik, M.. (2017, June 9). FIN7 Takes Another Bite at the Restaurant Industry. Retrieved July 13, 2017.
[16] [CrowdStrike Carbon Spider August 2021](https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/)
   Loui, E. and Reynolds, J. (2021, August 30). CARBON SPIDER Embraces Big Game Hunting, Part 1. Retrieved September 20, 2021.
[17] [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide)
   Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
[18] [Microsoft Ransomware as a Service](https://www.microsoft.com/en-us/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/)
   Microsoft. (2022, May 9). Ransomware as a service: Understanding the cybercrime gig economy and how to protect yourself. Retrieved March 10, 2023.
[19] [FireEye FIN7 March 2017](https://web.archive.org/web/20180808125108/https:/www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)
   Miller, S., et al. (2017, March 7). FIN7 Spear Phishing Campaign Targets Personnel Involved in SEC Filings. Retrieved March 8, 2017.
[20] [IBM Ransomware Trends September 2020](https://securityintelligence.com/posts/ransomware-2020-attack-trends-new-techniques-affecting-organizations-worldwide/)
   Singleton, C. and Kiefer, C. (2020, September 28). Ransomware 2020: Attack Trends Affecting Organizations Worldwide. Retrieved September 20, 2021.
[21] [mitre-attack](https://attack.mitre.org/groups/G0008)
[24] [Kaspersky Carbanak](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf)
   Kaspersky Lab's Global Research and Analysis Team. (2015, February). CARBANAK APT THE GREAT BANK ROBBERY. Retrieved August 23, 2018.
[25] [Europol Cobalt Mar 2018](https://www.europol.europa.eu/newsroom/news/mastermind-behind-eur-1-billion-cyber-bank-robbery-arrested-in-spain)
   Europol. (2018, March 26). Mastermind Behind EUR 1 Billion Cyber Bank Robbery Arrested in Spain. Retrieved October 10, 2018.
[26] [Secureworks GOLD KINGSWOOD Threat Profile](https://www.secureworks.com/research/threat-profiles/gold-kingswood?filter=item-financial-gain)
   Secureworks. (n.d.). GOLD KINGSWOOD. Retrieved October 18, 2021.
[27] [Fox-It Anunak Feb 2015](https://www.fox-it.com/en/news/blog/anunak-aka-carbanak-update/)
   Prins, R. (2015, February 16). Anunak (aka Carbanak) Update. Retrieved January 20, 2017.

