---
layout: threat_actor
title: "APT41"
aliases: ["Amoeba", "APT41", "Barium", "BARIUM", "Blackfly", "Brass Typhoon", "BRONZE ATLAS", "BRONZE EXPORT", "Double Dragon", "Earth Baku", "G0044", "G0096", "Grayfly", "HOODOO", "LEAD", "Leopard Typhoon", "Red Kelpie", "TA415", "TG-2633", "Wicked Panda", "WICKED PANDA", "WICKED SPIDER", "Winnti", "Winnti Group", "Winnti Umbrella", "Wicked Spider"]
description: "APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, APT41 has been observe"
permalink: /apt41/
---

## Introduction
APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, APT41 has been observed targeting various industries, including but not limited to healthcare, telecom, technology, finance, education, retail and video game industries in 14 countries. [apt41_mandiant](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf) Notable behaviors include using a wide range of malware and tools to complete mission objectives. APT41 overlaps at least partially with public reporting on groups including BARIUM and Winnti Group. [FireEye APT41 Aug 2019](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf) [Group IB APT 41 June 2021](https://www.group-ib.com/blog/colunmtk-apt41/)

## Activities and Tactics
**Targeted Sectors**: Gaming, Technology, Healthcare

**Country of Origin**: 🇨🇳 China

**Risk Level**: High

**First Seen**: 2012

**Last Activity**: 2024


**Suspected Victims**: China, France, Hong Kong, India, Italy, Japan, Myanmar, Netherlands, Singapore, South Korea...

## Notable Campaigns
- [Avast/CCleaner](https://blog.avast.com/update-ccleaner-attackers-entered-via-teamviewer) (September 2016; WickedPanda (CN APT))

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0096 (YAML `ttps` empty).*

- [T1003.001 LSASS Memory](/techniques/T1003.001/)
- [T1005 Data from Local System](/techniques/T1005/)
- [T1008 Fallback Channels](/techniques/T1008/)
- [T1014 Rootkit](/techniques/T1014/)
- [T1016 System Network Configuration Discovery](/techniques/T1016/)
- [T1021.001 Remote Desktop Protocol](/techniques/T1021.001/)
- [T1021.002 SMB/Windows Admin Shares](/techniques/T1021.002/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1033 System Owner/User Discovery](/techniques/T1033/)
- [T1036.004 Masquerade Task or Service](/techniques/T1036.004/)
- [T1036.005 Match Legitimate Resource Name or Location](/techniques/T1036.005/)
- [T1046 Network Service Discovery](/techniques/T1046/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1049 System Network Connections Discovery](/techniques/T1049/)
- [T1053.005 Scheduled Task](/techniques/T1053.005/)
- [T1055 Process Injection](/techniques/T1055/)
- [T1056.001 Keylogging](/techniques/T1056.001/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1059.004 Unix Shell](/techniques/T1059.004/)
- [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [T1070.003 Clear Command History](/techniques/T1070.003/)
- [T1070.004 File Deletion](/techniques/T1070.004/)
- [T1071.001 Web Protocols](/techniques/T1071.001/)
- [T1071.002 File Transfer Protocols](/techniques/T1071.002/)
- [T1071.004 DNS](/techniques/T1071.004/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1083 File and Directory Discovery](/techniques/T1083/)
- [T1090 Proxy](/techniques/T1090/)
- [T1102.001 Dead Drop Resolver](/techniques/T1102.001/)
- [T1104 Multi-Stage Channels](/techniques/T1104/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1110.002 Password Cracking](/techniques/T1110.002/)
- [T1112 Modify Registry](/techniques/T1112/)
- [T1133 External Remote Services](/techniques/T1133/)
- [T1135 Network Share Discovery](/techniques/T1135/)
- [T1136.001 Local Account](/techniques/T1136.001/)
- [T1190 Exploit Public-Facing Application](/techniques/T1190/)
- [T1195.002 Compromise Software Supply Chain](/techniques/T1195.002/)
- [T1197 BITS Jobs](/techniques/T1197/)
- [T1203 Exploitation for Client Execution](/techniques/T1203/)
- [T1218.001 Compiled HTML File](/techniques/T1218.001/)
- [T1218.011 Rundll32](/techniques/T1218.011/)
- [T1480.001 Environmental Keying](/techniques/T1480.001/)
- [T1486 Data Encrypted for Impact](/techniques/T1486/)
- [T1496 Resource Hijacking](/techniques/T1496/)
- [T1542.003 Bootkit](/techniques/T1542.003/)
- [T1543.003 Windows Service](/techniques/T1543.003/)
- [T1546.008 Accessibility Features](/techniques/T1546.008/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1553.002 Code Signing](/techniques/T1553.002/)
- [T1560.001 Archive via Utility](/techniques/T1560.001/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1568.002 Domain Generation Algorithms](/techniques/T1568.002/)
- [T1569.002 Service Execution](/techniques/T1569.002/)
- [T1574.001 DLL](/techniques/T1574.001/)
- [T1574.002](https://attack.mitre.org/techniques/T1574/002/)
- [T1574.006 Dynamic Linker Hijacking](/techniques/T1574.006/)
- [T1588.002 Tool](/techniques/T1588.002/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CyberGate**
- **Cyber Eye RAT**
- **Winnti Rootkit malware**: 
- **CRACKSHOT**: 
- **GEARSHIFT**: 
- **HIGHNOON**: 
- **JUMPALL**: 
- **POISONPLUG**: 
- **HOTCHAI**: 
- **LATELUNCH**: 
- **LIFEBOAT**: 
- **LOWKEY**: 
- **NJRAT**: 
- **PACMAN**: 
- **PHOTO**: 
- **POTROAST**: 
- **ROCKBOOT**: 
- **SAGEHIRE**: 
- **SWEETCANDLE**: 
- **SOGU**: 
- **TERA**: 
- **TIDYELF**: 
- **WIDETONE**: 
- **WINTERLOVE**: 
- **XDoor**: 
- **Xmrig**: 
- **ZxShell**: 

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0096)
   MITRE ATT&CK entry
[2] [apt41_mandiant](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf)
[3] [Group IB APT 41 June 2021](https://www.group-ib.com/blog/colunmtk-apt41/)

