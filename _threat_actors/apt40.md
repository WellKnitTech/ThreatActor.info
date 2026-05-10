---
layout: threat_actor
title: "APT40"
aliases: ["APT40","ATK29","BRONZE MOHAWK","Feverdream","G0065","Gadolinium","GADOLINIUM","Gingham Typhoon","Hainan Xiandun Technology Company","ISLANDDREAMS","ITG09","JJDoor","Kryptonite Panda","KRYPTONITE PANDA","Leviathan","MUDCARP","Red Ladon","ScanBox","TA423","TEMP.Jumper","Temp.Jumper","TEMP.Periscope"]
description: "Leviathan is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company. [CISA A"
permalink: /apt40/
---

## Introduction
Leviathan is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company. [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a) Active since at least 2009, Leviathan has targeted the following sectors: academia, aerospace/aviation, biomedical, defense industrial base, government, healthcare, manufacturing, maritime, and transportation across the US, Canada, Australia, Europe, the Middle East, and Southeast Asia. [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a) [Proofpoint Leviathan Oct 2017](https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets) [FireEye Periscope March 2018](https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html) [CISA Leviathan 2024](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a)

## Activities and Tactics
**Targeted Sectors**: Maritime, Government, Defense, Private sector

**Country of Origin**: 🇨🇳 China

**Risk Level**: High

**First Seen**: 2013

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: United States, Hong Kong, The Philippines, Asia Pacific Economic Cooperation, Cambodia, Belgium, Germany, Philippines, Malaysia, Norway...

## Notable Campaigns
- [Leviathan Australian Intrusions (C0049)](https://attack.mitre.org/campaigns/C0049): Leviathan Australian Intrusions consisted of at least two long-term intrusions against victims in Australia by Leviathan, relying on similar tradecraft such as external service exploitation followed by extensive credential capture and re-use to enable privilege escalation and lateral movement. Leviathan Australian Intrusions were focused on exfiltrating sensitive data including valid credentials for the victim organizations.(Citation: CISA Leviathan 2024)

## Tactics, Techniques, and Procedures (TTPs)
- [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)
- [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002)
- [T1102.003 One-Way Communication](https://attack.mitre.org/techniques/T1102/003)
- [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)
- [T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013)
- [T1589.001 Credentials](https://attack.mitre.org/techniques/T1589/001)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1586.001 Social Media Accounts](https://attack.mitre.org/techniques/T1586/001)
- [T1090.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)
- [T1027.001 Binary Padding](https://attack.mitre.org/techniques/T1027/001)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1585.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189)
- [T1546.003 Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003)
- [T1027.003 Steganography](https://attack.mitre.org/techniques/T1027/003)
- [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1547.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009)
- [T1055.001 Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1584.004 Server](https://attack.mitre.org/techniques/T1584/004)
- [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203)
- [T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002)
- [T1559.002 Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002)
- [T1587.004 Exploits](https://attack.mitre.org/techniques/T1587/004)
- [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197)
- [T1074.001 Local Data Staging](https://attack.mitre.org/techniques/T1074/001)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)
- [T1074.002 Remote Data Staging](https://attack.mitre.org/techniques/T1074/002)
- [T1534 Internal Spearphishing](https://attack.mitre.org/techniques/T1534)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010)
- [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)
- [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003)
- [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)
- [T1584.008 Network Devices](https://attack.mitre.org/techniques/T1584/008)
- [T1027.015 Compression](https://attack.mitre.org/techniques/T1027/015)
- [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560)
- [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572)
- [T1204.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001)
- [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133)
- [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003)
- [T1586.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002)

### ATT&CK technique IDs (denormalized)

- [T1003](https://attack.mitre.org/techniques/T1003/)
- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [T1021.004](https://attack.mitre.org/techniques/T1021/004/)
- [T1027.001](https://attack.mitre.org/techniques/T1027/001/)
- [T1027.003](https://attack.mitre.org/techniques/T1027/003/)
- [T1027.013](https://attack.mitre.org/techniques/T1027/013/)
- [T1027.015](https://attack.mitre.org/techniques/T1027/015/)
- [T1041](https://attack.mitre.org/techniques/T1041/)
- [T1047](https://attack.mitre.org/techniques/T1047/)
- [T1055.001](https://attack.mitre.org/techniques/T1055/001/)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.005](https://attack.mitre.org/techniques/T1059/005/)
- [T1074.001](https://attack.mitre.org/techniques/T1074/001/)
- [T1074.002](https://attack.mitre.org/techniques/T1074/002/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1090.003](https://attack.mitre.org/techniques/T1090/003/)
- [T1102.003](https://attack.mitre.org/techniques/T1102/003/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1133](https://attack.mitre.org/techniques/T1133/)
- [T1140](https://attack.mitre.org/techniques/T1140/)
- [T1189](https://attack.mitre.org/techniques/T1189/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1197](https://attack.mitre.org/techniques/T1197/)
- [T1203](https://attack.mitre.org/techniques/T1203/)
- [T1204.001](https://attack.mitre.org/techniques/T1204/001/)
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [T1218.010](https://attack.mitre.org/techniques/T1218/010/)
- [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [T1534](https://attack.mitre.org/techniques/T1534/)
- [T1546.003](https://attack.mitre.org/techniques/T1546/003/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [T1547.009](https://attack.mitre.org/techniques/T1547/009/)
- [T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [T1559.002](https://attack.mitre.org/techniques/T1559/002/)
- [T1560](https://attack.mitre.org/techniques/T1560/)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [T1567.002](https://attack.mitre.org/techniques/T1567/002/)
- [T1572](https://attack.mitre.org/techniques/T1572/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [T1584.004](https://attack.mitre.org/techniques/T1584/004/)
- [T1584.008](https://attack.mitre.org/techniques/T1584/008/)
- [T1585.001](https://attack.mitre.org/techniques/T1585/001/)
- [T1585.002](https://attack.mitre.org/techniques/T1585/002/)
- [T1586.001](https://attack.mitre.org/techniques/T1586/001/)
- [T1586.002](https://attack.mitre.org/techniques/T1586/002/)
- [T1587.004](https://attack.mitre.org/techniques/T1587/004/)
- [T1589.001](https://attack.mitre.org/techniques/T1589/001/)
- [T1595.002](https://attack.mitre.org/techniques/T1595/002/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 3 public reports that may contain IOCs; see Source Attribution for dataset links.*

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

### MITRE ATT&CK Software
- [Windows Credential Editor (S0005) — tool](https://attack.mitre.org/software/S0005)
- [BITSAdmin (S0190) — tool](https://attack.mitre.org/software/S0190)
- [HOMEFRY (S0232) — malware](https://attack.mitre.org/software/S0232)
- [Derusbi (S0021) — malware](https://attack.mitre.org/software/S0021)
- [at (S0110) — tool](https://attack.mitre.org/software/S0110)
- [BLACKCOFFEE (S0069) — malware](https://attack.mitre.org/software/S0069)
- [BADFLICK (S0642) — malware](https://attack.mitre.org/software/S0642)
- [Empire (S0363) — tool](https://attack.mitre.org/software/S0363)
- [gh0st RAT (S0032) — malware](https://attack.mitre.org/software/S0032)
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [PowerSploit (S0194) — tool](https://attack.mitre.org/software/S0194)
- [MURKYTOP (S0233) — malware](https://attack.mitre.org/software/S0233)
- [NanHaiShu (S0228) — malware](https://attack.mitre.org/software/S0228)
- [Orz (S0229) — malware](https://attack.mitre.org/software/S0229)
- [Cobalt Strike (S0154) — malware](https://attack.mitre.org/software/S0154)
- [China Chopper (S0020) — malware](https://attack.mitre.org/software/S0020)
- [Tor (S0183) — tool](https://attack.mitre.org/software/S0183)

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G0065)
[10] [Accenture MUDCARP March 2019](https://www.accenture.com/us-en/blogs/cyber-defense/mudcarps-focus-on-submarine-technologies)
   Accenture iDefense Unit. (2019, March 5). Mudcarp's Focus on Submarine Technologies. Retrieved August 24, 2021.
[11] [Crowdstrike KRYPTONITE PANDA August 2018](https://www.crowdstrike.com/blog/two-birds-one-stone-panda/)
   Adam Kozy. (2018, August 30). Two Birds, One Stone Panda. Retrieved August 24, 2021.
[12] [Proofpoint Leviathan Oct 2017](https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets)
   Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
[13] [MSTIC GADOLINIUM September 2020](https://www.microsoft.com/security/blog/2020/09/24/gadolinium-detecting-empires-cloud/)
   Ben Koehl, Joe Hannon. (2020, September 24). Microsoft Security - Detecting Empires in the Cloud. Retrieved August 24, 2021.
[14] [CISA Leviathan 2024](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a)
   CISA et al. (2024, July 8). People’s Republic of China (PRC) Ministry of State Security APT40 Tradecraft in Action. Retrieved February 3, 2025.
[15] [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a)
   CISA. (2021, July 19). (AA21-200A) Joint Cybersecurity Advisory – Tactics, Techniques, and Procedures of Indicted APT40 Actors Associated with China’s MSS Hainan State Security Department. Retrieved August 12, 2021.
[17] [FireEye Periscope March 2018](https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html)
   FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
[18] [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide)
   Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
[19] [FireEye APT40 March 2019](https://www.fireeye.com/blog/threat-research/2019/03/apt40-examining-a-china-nexus-espionage-actor.html)
   Plan, F., et al. (2019, March 4). APT40: Examining a China-Nexus Espionage Actor. Retrieved March 18, 2019.
[20] [SecureWorks BRONZE MOHAWK n.d.](https://www.secureworks.com/research/threat-profiles/bronze-mohawk)
   SecureWorks. (n.d.). Threat Profile - BRONZE MOHAWK. Retrieved August 24, 2021.

