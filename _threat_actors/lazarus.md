---
layout: threat_actor
title: "Lazarus Group"
aliases: ["Andariel", "Appleworm", "APT 38", "APT-C-26", "APT38", "ATK117", "ATK3", "BeagleBoyz", "Black Artemis", "Bluenoroff", "Bureau 121", "Citrine Sleet", "COPERNICIUM", "COVELLITE", "Dark Seoul", "DEV-0139", "DEV-1222", "Diamond Sleet", "G0032", "G0082", "Group 77", "Guardians of Peace", "Hastati Group", "Hidden Cobra", "HIDDEN COBRA", "Labyrinth Chollima", "Lazarus Group", "Lazarus group", "Moonstone Sleet", "NewRomanic Cyber Army Team", "NICKEL ACADEMY", "Nickel Academy", "NICKEL GLADSTONE", "Operation AppleJeus", "Operation DarkSeoul", "Operation GhostSecret", "Operation Troy", "Sapphire Sleet", "Stardust Chollima", "Subgroup: Bluenoroff", "TA404", "Unit 121", "Whois Hacking Team", "ZINC", "Zinc"]
description: "Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). [US-CERT HIDDEN COBRA June 2017](https://www.us-cert.gov/ncas/alerts/TA17-164A)"
permalink: /lazarus/
---

## Introduction
Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). [US-CERT HIDDEN COBRA June 2017](https://www.us-cert.gov/ncas/alerts/TA17-164A) [Treasury North Korean Cyber Groups September 2019](https://home.treasury.gov/news/press-releases/sm774) Lazarus Group has been active since at least 2009 and is reportedly responsible for the November 2014 destructive wiper attack on Sony Pictures Entertainment, identified by Novetta as part of Operation Blockbuster. Malware used by Lazarus Group correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain. [Novetta Blockbuster](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf) North Korea’s cyber operations have shown a consistent pattern of adaptation, forming and reorganizing units as national priorities shift. These units frequently share personnel, infrastructure, malware, and tradecraft, making it difficult to attribute specific operations with high confidence. Public reporting often uses “Lazarus Group” as an umbrella term for multiple North Korean cyber operators conducting espionage, destructive attacks, and financially motivated campaigns. [Mandiant DPRK Laz Org Breakdown 2022](https://cloud.google.com/blog/topics/threat-intelligence/mapping-dprk-groups-to-government/) [Mandiant DPRK Groups 2023](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-cyber-structure-alignment-2023) [JPCert Blog Laz Subgroups 2025](https://blogs.jpcert.or.jp/en/2025/03/classifying-lazaruss-subgroup.html)

## Activities and Tactics
**Targeted Sectors**: Financial, Cryptocurrency, Entertainment

**Country of Origin**: 🇰🇵 North Korea

**Risk Level**: Critical

**First Seen**: 2009

**Last Activity**: 2024

**Incident Type**: ["Espionage", "Sabotage"]

**Suspected Victims**: South Korea, Bangladesh Bank, Sony Pictures Entertainment, United States, Thailand, France, China, Hong Kong, United Kingdom, Guatemala...

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0032 (YAML `ttps` empty).*

- [T1001.003 Protocol or Service Impersonation](/techniques/T1001.003/)
- [T1005 Data from Local System](/techniques/T1005/)
- [T1008 Fallback Channels](/techniques/T1008/)
- [T1010 Application Window Discovery](/techniques/T1010/)
- [T1012 Query Registry](/techniques/T1012/)
- [T1016 System Network Configuration Discovery](/techniques/T1016/)
- [T1021.001 Remote Desktop Protocol](/techniques/T1021.001/)
- [T1021.002 SMB/Windows Admin Shares](/techniques/T1021.002/)
- [T1021.004 SSH](/techniques/T1021.004/)
- [T1026](https://attack.mitre.org/techniques/T1026/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1027.002 Software Packing](/techniques/T1027.002/)
- [T1033 System Owner/User Discovery](/techniques/T1033/)
- [T1036 Masquerading](/techniques/T1036/)
- [T1036.003 Rename Legitimate Utilities](/techniques/T1036.003/)
- [T1036.004 Masquerade Task or Service](/techniques/T1036.004/)
- [T1036.005 Match Legitimate Resource Name or Location](/techniques/T1036.005/)
- [T1041 Exfiltration Over C2 Channel](/techniques/T1041/)
- [T1043](https://attack.mitre.org/techniques/T1043/)
- [T1046 Network Service Discovery](/techniques/T1046/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](/techniques/T1048.003/)
- [T1049 System Network Connections Discovery](/techniques/T1049/)
- [T1053.005 Scheduled Task](/techniques/T1053.005/)
- [T1055.001 Dynamic-link Library Injection](/techniques/T1055.001/)
- [T1056.001 Keylogging](/techniques/T1056.001/)
- [T1057 Process Discovery](/techniques/T1057/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1059.005 Visual Basic](/techniques/T1059.005/)
- [T1065](https://attack.mitre.org/techniques/T1065/)
- [T1070 Indicator Removal](/techniques/T1070/)
- [T1070.003 Clear Command History](/techniques/T1070.003/)
- [T1070.004 File Deletion](/techniques/T1070.004/)
- [T1070.006 Timestomp](/techniques/T1070.006/)
- [T1071.001 Web Protocols](/techniques/T1071.001/)
- [T1074.001 Local Data Staging](/techniques/T1074.001/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1082 System Information Discovery](/techniques/T1082/)
- [T1083 File and Directory Discovery](/techniques/T1083/)
- [T1087.002 Domain Account](/techniques/T1087.002/)
- [T1090.001 Internal Proxy](/techniques/T1090.001/)
- [T1090.002 External Proxy](/techniques/T1090.002/)
- [T1098 Account Manipulation](/techniques/T1098/)
- [T1102.002 Bidirectional Communication](/techniques/T1102.002/)
- [T1104 Multi-Stage Channels](/techniques/T1104/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1106 Native API](/techniques/T1106/)
- [T1110 Brute Force](/techniques/T1110/)
- [T1110.003 Password Spraying](/techniques/T1110.003/)
- [T1124 System Time Discovery](/techniques/T1124/)
- [T1132.001 Standard Encoding](/techniques/T1132.001/)
- [T1134.002 Create Process with Token](/techniques/T1134.002/)
- [T1140 Deobfuscate/Decode Files or Information](/techniques/T1140/)
- [T1189 Drive-by Compromise](/techniques/T1189/)
- [T1202 Indirect Command Execution](/techniques/T1202/)
- [T1203 Exploitation for Client Execution](/techniques/T1203/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1218 System Binary Proxy Execution](/techniques/T1218/)
- [T1218.005 Mshta](/techniques/T1218.005/)
- [T1218.010 Regsvr32](/techniques/T1218.010/)
- [T1218.011 Rundll32](/techniques/T1218.011/)
- [T1220 XSL Script Processing](/techniques/T1220/)
- [T1221 Template Injection](/techniques/T1221/)
- [T1485 Data Destruction](/techniques/T1485/)
- [T1489 Service Stop](/techniques/T1489/)
- [T1491.001 Internal Defacement](/techniques/T1491.001/)
- [T1497.001 System Checks](/techniques/T1497.001/)
- [T1529 System Shutdown/Reboot](/techniques/T1529/)
- [T1534 Internal Spearphishing](/techniques/T1534/)
- [T1542.003 Bootkit](/techniques/T1542.003/)
- [T1543.003 Windows Service](/techniques/T1543.003/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1547.009 Shortcut Modification](/techniques/T1547.009/)
- [T1553.002 Code Signing](/techniques/T1553.002/)
- [T1557.001 Name Resolution Poisoning and SMB Relay](/techniques/T1557.001/)
- [T1560 Archive Collected Data](/techniques/T1560/)
- [T1560.002 Archive via Library](/techniques/T1560.002/)
- [T1560.003 Archive via Custom Method](/techniques/T1560.003/)
- [T1561.001 Disk Content Wipe](/techniques/T1561.001/)
- [T1561.002 Disk Structure Wipe](/techniques/T1561.002/)
- [T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [T1562.004](https://attack.mitre.org/techniques/T1562/004/)
- [T1564.001 Hidden Files and Directories](/techniques/T1564.001/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1566.003 Spearphishing via Service](/techniques/T1566.003/)
- [T1567.002 Exfiltration to Cloud Storage](/techniques/T1567.002/)
- [T1571 Non-Standard Port](/techniques/T1571/)
- [T1573.001 Symmetric Cryptography](/techniques/T1573.001/)
- [T1574.002](https://attack.mitre.org/techniques/T1574/002/)
- [T1574.013 KernelCallbackTable](/techniques/T1574.013/)
- [T1583.001 Domains](/techniques/T1583.001/)
- [T1583.004 Server](/techniques/T1583.004/)
- [T1583.006 Web Services](/techniques/T1583.006/)
- [T1584.001 Domains](/techniques/T1584.001/)
- [T1584.004 Server](/techniques/T1584.004/)
- [T1585.001 Social Media Accounts](/techniques/T1585.001/)
- [T1585.002 Email Accounts](/techniques/T1585.002/)
- [T1587.001 Malware](/techniques/T1587.001/)
- [T1588.002 Tool](/techniques/T1588.002/)
- [T1588.003 Code Signing Certificates](/techniques/T1588.003/)
- [T1588.004 Digital Certificates](/techniques/T1588.004/)
- [T1589.002 Email Addresses](/techniques/T1589.002/)
- [T1591 Gather Victim Org Information](/techniques/T1591/)
- [T1591.004 Identify Roles](/techniques/T1591.004/)
- [T1593.001 Social Media](/techniques/T1593.001/)
- [T1608.001 Upload Malware](/techniques/T1608.001/)
- [T1608.002 Upload Tool](/techniques/T1608.002/)
- [T1614.001 System Language Discovery](/techniques/T1614.001/)
- [T1620 Reflective Code Loading](/techniques/T1620/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Wiper**
- **RemoteCMD**
- **Remote Utilities**
- **RemotePC**
- **Whois Wiper**: 

## Attribution and Evidence
**Country of Origin**: North Korea
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0032)
   MITRE ATT&CK entry
[2] [US-CERT HIDDEN COBRA June 2017](https://www.us-cert.gov/ncas/alerts/TA17-164A)
[3] [Treasury North Korean Cyber Groups September 2019](https://home.treasury.gov/news/press-releases/sm774)
[4] [Novetta Blockbuster](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)
[5] [Mandiant DPRK Laz Org Breakdown 2022](https://cloud.google.com/blog/topics/threat-intelligence/mapping-dprk-groups-to-government/)
[6] [Mandiant DPRK Groups 2023](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-cyber-structure-alignment-2023)
[7] [JPCert Blog Laz Subgroups 2025](https://blogs.jpcert.or.jp/en/2025/03/classifying-lazaruss-subgroup.html)

