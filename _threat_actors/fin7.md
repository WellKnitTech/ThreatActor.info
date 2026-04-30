---
layout: threat_actor
title: "FIN7"
aliases: ["Anunak", "ATK32", "Calcium", "Carbanak", "Carbon Spider", "CARBON SPIDER", "Coreid", "ELBRUS", "FIN7", "G0008", "G0046", "GOLD NIAGARA", "ITG14", "JokerStash", "Navigator Group", "Sangria Tempest", "Coried", "CarbonSpider", "Carbanak Group"]
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
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0046 (YAML `ttps` empty).*

- [T1005 Data from Local System](/techniques/T1005/)
- [T1008 Fallback Channels](/techniques/T1008/)
- [T1021.001 Remote Desktop Protocol](/techniques/T1021.001/)
- [T1021.004 SSH](/techniques/T1021.004/)
- [T1021.005 VNC](/techniques/T1021.005/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1036.004 Masquerade Task or Service](/techniques/T1036.004/)
- [T1036.005 Match Legitimate Resource Name or Location](/techniques/T1036.005/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1053.005 Scheduled Task](/techniques/T1053.005/)
- [T1059 Command and Scripting Interpreter](/techniques/T1059/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1059.005 Visual Basic](/techniques/T1059.005/)
- [T1059.007 JavaScript](/techniques/T1059.007/)
- [T1071.004 DNS](/techniques/T1071.004/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1091 Replication Through Removable Media](/techniques/T1091/)
- [T1102.002 Bidirectional Communication](/techniques/T1102.002/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1113 Screen Capture](/techniques/T1113/)
- [T1125 Video Capture](/techniques/T1125/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1210 Exploitation of Remote Services](/techniques/T1210/)
- [T1218.005 Mshta](/techniques/T1218.005/)
- [T1486 Data Encrypted for Impact](/techniques/T1486/)
- [T1497.002 User Activity Based Checks](/techniques/T1497.002/)
- [T1543.003 Windows Service](/techniques/T1543.003/)
- [T1546.011 Application Shimming](/techniques/T1546.011/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1553.002 Code Signing](/techniques/T1553.002/)
- [T1558.003 Kerberoasting](/techniques/T1558.003/)
- [T1559.002 Dynamic Data Exchange](/techniques/T1559.002/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1567.002 Exfiltration to Cloud Storage](/techniques/T1567.002/)
- [T1571 Non-Standard Port](/techniques/T1571/)
- [T1583.001 Domains](/techniques/T1583.001/)
- [T1587.001 Malware](/techniques/T1587.001/)

### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications | Veeam | Backup & Replication | CVE-2023-27532 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

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

## Attribution and Evidence
**Country of Origin**: Unknown
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0046)
   MITRE ATT&CK entry
[2] [FireEye FIN7 March 2017](https://web.archive.org/web/20180808125108/https:/www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)
[3] [FireEye FIN7 April 2017](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html)
[4] [FireEye CARBANAK June 2017](https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html)
[5] [FireEye FIN7 Aug 2018](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
[6] [CrowdStrike Carbon Spider August 2021](https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/)
[7] [Mandiant FIN7 Apr 2022](https://www.mandiant.com/resources/evolution-of-fin7)
[8] [BiZone Lizar May 2021](https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319)

