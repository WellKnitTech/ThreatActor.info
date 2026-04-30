---
layout: threat_actor
title: "APT32"
aliases: ["APT 32", "APT-32", "APT-C-00", "APT32", "ATK17", "BISMUTH", "Canvas Cyclone", "Cobalt Kitty", "G0050", "Ocean Buffalo", "Ocean Lotus", "OceanLotus", "OceanLotus Group", "POND LOACH", "Sea Lotus", "SeaLotus", "TIN WOODLAWN"]
description: "APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journ"
permalink: /apt32/
---

## Introduction
APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journalists with a strong focus on Southeast Asian countries like Vietnam, the Philippines, Laos, and Cambodia. They have extensively used strategic web compromises to compromise victims. [FireEye APT32 May 2017](https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html) [Volexity OceanLotus Nov 2017](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/) [ESET OceanLotus](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)

## Activities and Tactics
**Targeted Sectors**: Government, Media, Technology

**Country of Origin**: 🇻🇳 Vietnam

**Risk Level**: High

**First Seen**: 2012

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: China, Germany, United States, Vietnam, Philippines, Association of Southeast Asian Nations

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0050 (YAML `ttps` empty).*

- [T1003 OS Credential Dumping](/techniques/T1003/)
- [T1003.001 LSASS Memory](/techniques/T1003.001/)
- [T1012 Query Registry](/techniques/T1012/)
- [T1016 System Network Configuration Discovery](/techniques/T1016/)
- [T1018 Remote System Discovery](/techniques/T1018/)
- [T1021.002 SMB/Windows Admin Shares](/techniques/T1021.002/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1027.001 Binary Padding](/techniques/T1027.001/)
- [T1033 System Owner/User Discovery](/techniques/T1033/)
- [T1036 Masquerading](/techniques/T1036/)
- [T1036.003 Rename Legitimate Utilities](/techniques/T1036.003/)
- [T1036.004 Masquerade Task or Service](/techniques/T1036.004/)
- [T1036.005 Match Legitimate Resource Name or Location](/techniques/T1036.005/)
- [T1041 Exfiltration Over C2 Channel](/techniques/T1041/)
- [T1046 Network Service Discovery](/techniques/T1046/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](/techniques/T1048.003/)
- [T1049 System Network Connections Discovery](/techniques/T1049/)
- [T1053.005 Scheduled Task](/techniques/T1053.005/)
- [T1055 Process Injection](/techniques/T1055/)
- [T1056.001 Keylogging](/techniques/T1056.001/)
- [T1059 Command and Scripting Interpreter](/techniques/T1059/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1059.005 Visual Basic](/techniques/T1059.005/)
- [T1059.007 JavaScript](/techniques/T1059.007/)
- [T1065](https://attack.mitre.org/techniques/T1065/)
- [T1068 Exploitation for Privilege Escalation](/techniques/T1068/)
- [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [T1070.004 File Deletion](/techniques/T1070.004/)
- [T1070.006 Timestomp](/techniques/T1070.006/)
- [T1071.001 Web Protocols](/techniques/T1071.001/)
- [T1071.003 Mail Protocols](/techniques/T1071.003/)
- [T1072 Software Deployment Tools](/techniques/T1072/)
- [T1078.003 Local Accounts](/techniques/T1078.003/)
- [T1082 System Information Discovery](/techniques/T1082/)
- [T1083 File and Directory Discovery](/techniques/T1083/)
- [T1087.001 Local Account](/techniques/T1087.001/)
- [T1094](https://attack.mitre.org/techniques/T1094/)
- [T1102 Web Service](/techniques/T1102/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1112 Modify Registry](/techniques/T1112/)
- [T1135 Network Share Discovery](/techniques/T1135/)
- [T1137 Office Application Startup](/techniques/T1137/)
- [T1189 Drive-by Compromise](/techniques/T1189/)
- [T1203 Exploitation for Client Execution](/techniques/T1203/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1216.001 PubPrn](/techniques/T1216.001/)
- [T1218.005 Mshta](/techniques/T1218.005/)
- [T1218.010 Regsvr32](/techniques/T1218.010/)
- [T1218.011 Rundll32](/techniques/T1218.011/)
- [T1222.002 Linux and Mac Permissions](/techniques/T1222.002/)
- [T1505.003 Web Shell](/techniques/T1505.003/)
- [T1543.003 Windows Service](/techniques/T1543.003/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1550.002 Pass the Hash](/techniques/T1550.002/)
- [T1550.003 Pass the Ticket](/techniques/T1550.003/)
- [T1552.002 Credentials in Registry](/techniques/T1552.002/)
- [T1560 Archive Collected Data](/techniques/T1560/)
- [T1564.001 Hidden Files and Directories](/techniques/T1564.001/)
- [T1564.003 Hidden Window](/techniques/T1564.003/)
- [T1564.004 NTFS File Attributes](/techniques/T1564.004/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1569.002 Service Execution](/techniques/T1569.002/)
- [T1570 Lateral Tool Transfer](/techniques/T1570/)
- [T1571 Non-Standard Port](/techniques/T1571/)
- [T1574.002](https://attack.mitre.org/techniques/T1574/002/)
- [T1583.001 Domains](/techniques/T1583.001/)
- [T1583.006 Web Services](/techniques/T1583.006/)
- [T1585.001 Social Media Accounts](/techniques/T1585.001/)
- [T1588.002 Tool](/techniques/T1588.002/)
- [T1589 Gather Victim Identity Information](/techniques/T1589/)
- [T1589.002 Email Addresses](/techniques/T1589.002/)
- [T1598.003 Spearphishing Link](/techniques/T1598.003/)
- [T1608.001 Upload Malware](/techniques/T1608.001/)
- [T1608.004 Drive-by Target](/techniques/T1608.004/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CyberGate**
- **Cyber Eye RAT**
- **CrossRat**

## Attribution and Evidence
**Country of Origin**: Vietnam
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0050)
   MITRE ATT&CK entry
[2] [FireEye APT32 May 2017](https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html)
[3] [Volexity OceanLotus Nov 2017](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/)
[4] [ESET OceanLotus](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)

