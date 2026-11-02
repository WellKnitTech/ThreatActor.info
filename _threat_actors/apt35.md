---
layout: threat_actor
title: "APT35"
aliases: ["APT35","Agent Serpens","Ballistic Bobcat","COBALT ILLUSION","COBALT MIRAGE","Charming Kitten","Charming Kitten (Crowdstrike)","CharmingCypress","Cobalt Illusion","Damselfly","Direfate","G0058","G0059","Greycatfish","Group 83","ITG18","Iridium Group","Magic Hound","Mint Sandstorm","Mint Sandstorm (Microsoft)","NewsBeef","Newscaster","Newscaster Team","PHOSPHORUS","Parastoo","Phosphorus","RICH ION","Saffron Rose","TA453","TunnelVision","White Phosphorous","Yellow Garuda","iKittens"]
description: "Magic Hound is an Iranian-sponsored threat group that conducts long term, resource-intensive cyber espionage operations, likely on behalf of the Islamic Revolutionary Guard Corps. They have targeted Eu"
permalink: /apt35/
---

## Introduction
Magic Hound is an Iranian-sponsored threat group that conducts long term, resource-intensive cyber espionage operations, likely on behalf of the Islamic Revolutionary Guard Corps. They have targeted European, U.S., and Middle Eastern government and military personnel, academics, journalists, and organizations such as the World Health Organization (WHO), via complex social engineering campaigns since at least 2014. [FireEye APT35 2018](https://static.carahsoft.com/concrete/files/1015/2779/3571/M-Trends-2018-Report.pdf) [ClearSky Kittens Back 3 August 2020](https://www.clearskysec.com/wp-content/uploads/2020/08/The-Kittens-are-Back-in-Town-3.pdf) [Certfa Charming Kitten January 2021](https://blog.certfa.com/posts/charming-kitten-christmas-gift/) [Secureworks COBALT ILLUSION Threat Profile](https://www.secureworks.com/research/threat-profiles/cobalt-illusion) [Proofpoint TA453 July2021](https://www.proofpoint.com/us/blog/threat-insight/operation-spoofedscholars-conversation-ta453)

## Activities and Tactics
**Targeted Sectors**: Media, Academia, Government, Defense, Diplomacy, Military, Technology, Government, Administration

**Country of Origin**: 🇮🇷 Iran

**Risk Level**: High

**First Seen**: 2014

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: U.S. government/defense sector websites, Saudi Arabia, Israel, Iraq, United Kingdom

## Notable Campaigns
- **2020-05**
- **During a three-day period in May 2020**
- **IBM X-Force IRIS discovered the 40 GBs of video and data files being uploaded to a server that hosted numerous ITG18 domains used in earlier 2020 activity. Some of the videos showed the operator managing adversary-created accounts while others showed the operator testing access and exfiltrating data from previously compromised accounts.**
- **https://securityintelligence.com/posts/new-research-exposes-iranian-threat-group-operations/**

## Tactics, Techniques, and Procedures (TTPs)
- [T1056.001 Keylogging](https://attack.mitre.org/techniques/T1056/001)
- [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)
- [T1589.001 Credentials](https://attack.mitre.org/techniques/T1589/001)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1016.002 Wi-Fi Discovery](https://attack.mitre.org/techniques/T1016/002)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1584.001 Domains](https://attack.mitre.org/techniques/T1584/001)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572)
- [T1585.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002)
- [T1591.001 Determine Physical Locations](https://attack.mitre.org/techniques/T1591/001)
- [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071)
- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)
- [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)
- [T1016.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001)
- [T1586.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002)
- [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)
- [T1592.002 Software](https://attack.mitre.org/techniques/T1592/002)
- [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)
- [T1087.003 Email Account](https://attack.mitre.org/techniques/T1087/003)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011)
- [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010)
- [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)
- [T1590.005 IP Addresses](https://attack.mitre.org/techniques/T1590/005)
- [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113)
- [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573)
- [T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005)
- [T1685.001 Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001)
- [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002)
- [T1036.010 Masquerade Account Name](https://attack.mitre.org/techniques/T1036/010)
- [T1589.002 Email Addresses](https://attack.mitre.org/techniques/T1589/002)
- [T1204.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001)
- [T1102.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002)
- [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)
- [T1098.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1078.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)
- [T1598.003 Spearphishing Link](https://attack.mitre.org/techniques/T1598/003)
- [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)
- [T1114 Email Collection](https://attack.mitre.org/techniques/T1114)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)
- [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1114.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002)
- [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571)
- [T1686.003 Windows Host Firewall](https://attack.mitre.org/techniques/T1686/003)
- [T1070.003 Clear Command History](https://attack.mitre.org/techniques/T1070/003)
- [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082)
- [T1114.001 Local Email Collection](https://attack.mitre.org/techniques/T1114/001)
- [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003)
- [T1090 Proxy](https://attack.mitre.org/techniques/T1090)
- [T1036.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112)
- [T1482 Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)
- [T1589 Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589)
- [T1078.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002)
- [T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)
- [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001)
- [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)
- [T1564.003 Hidden Window](https://attack.mitre.org/techniques/T1564/003)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)
- [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006)
- [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)
- [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189)

### ATT&CK technique IDs (denormalized)

- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1005](https://attack.mitre.org/techniques/T1005/)
- [T1016](https://attack.mitre.org/techniques/T1016/)
- [T1016.001](https://attack.mitre.org/techniques/T1016/001/)
- [T1016.002](https://attack.mitre.org/techniques/T1016/002/)
- [T1018](https://attack.mitre.org/techniques/T1018/)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [T1027.010](https://attack.mitre.org/techniques/T1027/010/)
- [T1027.013](https://attack.mitre.org/techniques/T1027/013/)
- [T1033](https://attack.mitre.org/techniques/T1033/)
- [T1036.004](https://attack.mitre.org/techniques/T1036/004/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1036.010](https://attack.mitre.org/techniques/T1036/010/)
- [T1046](https://attack.mitre.org/techniques/T1046/)
- [T1047](https://attack.mitre.org/techniques/T1047/)
- [T1049](https://attack.mitre.org/techniques/T1049/)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [T1056.001](https://attack.mitre.org/techniques/T1056/001/)
- [T1057](https://attack.mitre.org/techniques/T1057/)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [T1059.005](https://attack.mitre.org/techniques/T1059/005/)
- [T1070.003](https://attack.mitre.org/techniques/T1070/003/)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- [T1071](https://attack.mitre.org/techniques/T1071/)
- [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [T1078.001](https://attack.mitre.org/techniques/T1078/001/)
- [T1078.002](https://attack.mitre.org/techniques/T1078/002/)
- [T1082](https://attack.mitre.org/techniques/T1082/)
- [T1083](https://attack.mitre.org/techniques/T1083/)
- [T1087.003](https://attack.mitre.org/techniques/T1087/003/)
- [T1090](https://attack.mitre.org/techniques/T1090/)
- [T1098.002](https://attack.mitre.org/techniques/T1098/002/)
- [T1098.007](https://attack.mitre.org/techniques/T1098/007/)
- [T1102.002](https://attack.mitre.org/techniques/T1102/002/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1112](https://attack.mitre.org/techniques/T1112/)
- [T1113](https://attack.mitre.org/techniques/T1113/)
- [T1114](https://attack.mitre.org/techniques/T1114/)
- [T1114.001](https://attack.mitre.org/techniques/T1114/001/)
- [T1114.002](https://attack.mitre.org/techniques/T1114/002/)
- [T1136.001](https://attack.mitre.org/techniques/T1136/001/)
- [T1189](https://attack.mitre.org/techniques/T1189/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1204.001](https://attack.mitre.org/techniques/T1204/001/)
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [T1482](https://attack.mitre.org/techniques/T1482/)
- [T1486](https://attack.mitre.org/techniques/T1486/)
- [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [T1560.001](https://attack.mitre.org/techniques/T1560/001/)
- [T1564.003](https://attack.mitre.org/techniques/T1564/003/)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [T1566.003](https://attack.mitre.org/techniques/T1566/003/)
- [T1567](https://attack.mitre.org/techniques/T1567/)
- [T1570](https://attack.mitre.org/techniques/T1570/)
- [T1571](https://attack.mitre.org/techniques/T1571/)
- [T1572](https://attack.mitre.org/techniques/T1572/)
- [T1573](https://attack.mitre.org/techniques/T1573/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [T1583.006](https://attack.mitre.org/techniques/T1583/006/)
- [T1584.001](https://attack.mitre.org/techniques/T1584/001/)
- [T1585.001](https://attack.mitre.org/techniques/T1585/001/)
- [T1585.002](https://attack.mitre.org/techniques/T1585/002/)
- [T1586.002](https://attack.mitre.org/techniques/T1586/002/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1589](https://attack.mitre.org/techniques/T1589/)
- [T1589.001](https://attack.mitre.org/techniques/T1589/001/)
- [T1589.002](https://attack.mitre.org/techniques/T1589/002/)
- [T1590.005](https://attack.mitre.org/techniques/T1590/005/)
- [T1591.001](https://attack.mitre.org/techniques/T1591/001/)
- [T1592.002](https://attack.mitre.org/techniques/T1592/002/)
- [T1595.002](https://attack.mitre.org/techniques/T1595/002/)
- [T1598.003](https://attack.mitre.org/techniques/T1598/003/)
- [T1685](https://attack.mitre.org/techniques/T1685/)
- [T1685.001](https://attack.mitre.org/techniques/T1685/001/)
- [T1686.003](https://attack.mitre.org/techniques/T1686/003/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 2 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **Back Orifice**
- **Back Orifice 2000**

### MITRE ATT&CK Software
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [Impacket (S0357) — tool](https://attack.mitre.org/software/S0357)
- [Ping (S0097) — tool](https://attack.mitre.org/software/S0097)
- [CharmPower (S0674) — malware](https://attack.mitre.org/software/S0674)
- [FRP (S1144) — tool](https://attack.mitre.org/software/S1144)
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [Systeminfo (S0096) — tool](https://attack.mitre.org/software/S0096)
- [ipconfig (S0100) — tool](https://attack.mitre.org/software/S0100)
- [netsh (S0108) — tool](https://attack.mitre.org/software/S0108)
- [PowerLess (S1012) — malware](https://attack.mitre.org/software/S1012)
- [Pupy (S0192) — tool](https://attack.mitre.org/software/S0192)
- [DownPaper (S0186) — malware](https://attack.mitre.org/software/S0186)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)

## Attribution and Evidence
**Country of Origin**: Iran
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0059)
   MITRE ATT&CK entry
[2] [FireEye APT35 2018](https://static.carahsoft.com/concrete/files/1015/2779/3571/M-Trends-2018-Report.pdf)
[3] [ClearSky Kittens Back 3 August 2020](https://www.clearskysec.com/wp-content/uploads/2020/08/The-Kittens-are-Back-in-Town-3.pdf)
[4] [Certfa Charming Kitten January 2021](https://blog.certfa.com/posts/charming-kitten-christmas-gift/)
[5] [Secureworks COBALT ILLUSION Threat Profile](https://www.secureworks.com/research/threat-profiles/cobalt-illusion)
[6] [Proofpoint TA453 July2021](https://www.proofpoint.com/us/blog/threat-insight/operation-spoofedscholars-conversation-ta453)

