---
layout: threat_actor
title: "APT40"
aliases: ["APT40", "ATK29", "BRONZE MOHAWK", "G0065", "Gadolinium", "GADOLINIUM", "Gingham Typhoon", "ISLANDDREAMS", "ITG09", "Kryptonite Panda", "KRYPTONITE PANDA", "Leviathan", "MUDCARP", "Red Ladon", "TA423", "TEMP.Jumper", "TEMP.Periscope", "Temp.Jumper", "Hainan Xiandun Technology Company", "ScanBox"]
description: "Leviathan is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company. [CISA A"
permalink: /apt40/
---

## Introduction
Leviathan is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company. [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a) Active since at least 2009, Leviathan has targeted the following sectors: academia, aerospace/aviation, biomedical, defense industrial base, government, healthcare, manufacturing, maritime, and transportation across the US, Canada, Australia, Europe, the Middle East, and Southeast Asia. [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a) [Proofpoint Leviathan Oct 2017](https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets) [FireEye Periscope March 2018](https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html) [CISA Leviathan 2024](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a)

## Activities and Tactics
**Targeted Sectors**: Maritime, Government, Defense

**Country of Origin**: 🇨🇳 China

**Risk Level**: High

**First Seen**: 2013

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: United States, Hong Kong, The Philippines, Asia Pacific Economic Cooperation, Cambodia, Belgium, Germany, Philippines, Malaysia, Norway...

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0065 (YAML `ttps` empty).*

- [T1003 OS Credential Dumping](/techniques/T1003/)
- [T1003.001 LSASS Memory](/techniques/T1003.001/)
- [T1021.001 Remote Desktop Protocol](/techniques/T1021.001/)
- [T1021.004 SSH](/techniques/T1021.004/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1027.001 Binary Padding](/techniques/T1027.001/)
- [T1027.003 Steganography](/techniques/T1027.003/)
- [T1041 Exfiltration Over C2 Channel](/techniques/T1041/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1055.001 Dynamic-link Library Injection](/techniques/T1055.001/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.005 Visual Basic](/techniques/T1059.005/)
- [T1074.001 Local Data Staging](/techniques/T1074.001/)
- [T1074.002 Remote Data Staging](/techniques/T1074.002/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1090.003 Multi-hop Proxy](/techniques/T1090.003/)
- [T1102.003 One-Way Communication](/techniques/T1102.003/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1133 External Remote Services](/techniques/T1133/)
- [T1140 Deobfuscate/Decode Files or Information](/techniques/T1140/)
- [T1189 Drive-by Compromise](/techniques/T1189/)
- [T1197 BITS Jobs](/techniques/T1197/)
- [T1203 Exploitation for Client Execution](/techniques/T1203/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1218.010 Regsvr32](/techniques/T1218.010/)
- [T1505.003 Web Shell](/techniques/T1505.003/)
- [T1534 Internal Spearphishing](/techniques/T1534/)
- [T1546.003 Windows Management Instrumentation Event Subscription](/techniques/T1546.003/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1547.009 Shortcut Modification](/techniques/T1547.009/)
- [T1553.002 Code Signing](/techniques/T1553.002/)
- [T1559.002 Dynamic Data Exchange](/techniques/T1559.002/)
- [T1560 Archive Collected Data](/techniques/T1560/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1567.002 Exfiltration to Cloud Storage](/techniques/T1567.002/)
- [T1572 Protocol Tunneling](/techniques/T1572/)
- [T1583.001 Domains](/techniques/T1583.001/)
- [T1585.001 Social Media Accounts](/techniques/T1585.001/)
- [T1585.002 Email Accounts](/techniques/T1585.002/)
- [T1586.001 Social Media Accounts](/techniques/T1586.001/)
- [T1586.002 Email Accounts](/techniques/T1586.002/)
- [T1589.001 Credentials](/techniques/T1589.001/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **UNITEDRAKE**
- **AIRBREAK**: 
- **BADFLICK**: 
- **PHOTO**: 
- **HOMEFRY**: 
- **LUNCHMONEY**: 
- **MURKYTOP**: 
- **China Chopper**: 
- **Beacon**: 
- **BLACKCOFFEE**: 
- **CVE-2017-11882**: 
- **Derusbi**: 
- **RoyalRoad RTF Weaponizer**: 
- **8.t exploit document builder**: 

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0065)
   MITRE ATT&CK entry
[2] [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a)
[3] [Proofpoint Leviathan Oct 2017](https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets)
[4] [FireEye Periscope March 2018](https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html)
[5] [CISA Leviathan 2024](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a)

