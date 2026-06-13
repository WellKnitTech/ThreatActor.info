---
layout: threat_actor
title: "APT32"
aliases: ["APT 32","APT-32","APT-C-00","APT32","ATK17","BISMUTH","Canvas Cyclone","Cobalt Kitty","G0050","Ocean Buffalo","OCEAN BUFFALO","Ocean Lotus","OceanLotus","OceanLotus Group","POND LOACH","Sea Lotus","SeaLotus","TIN WOODLAWN","海莲花 - APT-C-00"]
description: "APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journ"
permalink: /apt32/
---

## Introduction
APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journalists with a strong focus on Southeast Asian countries like Vietnam, the Philippines, Laos, and Cambodia. They have extensively used strategic web compromises to compromise victims. [FireEye APT32 May 2017](https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html) [Volexity OceanLotus Nov 2017](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/) [ESET OceanLotus](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)

## Activities and Tactics
**Targeted Sectors**: Government, Media, Technology, Dissidents, Government, Administration, Journalist, Private sector, Civil society

**Country of Origin**: 🇻🇳 Vietnam

**Risk Level**: High

**First Seen**: 2012

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: China, Germany, United States, Vietnam, Philippines, Association of Southeast Asian Nations

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
- [T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002)
- [T1036 Masquerading](https://attack.mitre.org/techniques/T1036)
- [T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007)
- [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)
- [T1072 Software Deployment Tools](https://attack.mitre.org/techniques/T1072)
- [T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)
- [T1564.004 NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004)
- [T1552.002 Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)
- [T1055 Process Injection](https://attack.mitre.org/techniques/T1055)
- [T1216.001 PubPrn](https://attack.mitre.org/techniques/T1216/001)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1135 Network Share Discovery](https://attack.mitre.org/techniques/T1135)
- [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)
- [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571)
- [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1012 Query Registry](https://attack.mitre.org/techniques/T1012)
- [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)
- [T1574.001 DLL](https://attack.mitre.org/techniques/T1574/001)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1598.003 Spearphishing Link](https://attack.mitre.org/techniques/T1598/003)
- [T1087.001 Local Account](https://attack.mitre.org/techniques/T1087/001)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)
- [T1608.004 Drive-by Target](https://attack.mitre.org/techniques/T1608/004)
- [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)
- [T1036.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004)
- [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003)
- [T1078.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003)
- [T1589 Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589)
- [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006)
- [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189)
- [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011)
- [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)
- [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112)
- [T1071.003 Mail Protocols](https://attack.mitre.org/techniques/T1071/003)
- [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560)
- [T1204.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001)
- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1027.011 Fileless Storage](https://attack.mitre.org/techniques/T1027/011)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)
- [T1036.003 Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003)
- [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003)
- [T1608.001 Upload Malware](https://attack.mitre.org/techniques/T1608/001)
- [T1222.002 Linux and Mac Permissions](https://attack.mitre.org/techniques/T1222/002)
- [T1569.002 Service Execution](https://attack.mitre.org/techniques/T1569/002)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)
- [T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [T1550.003 Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)
- [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006)
- [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003)
- [T1564.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001)
- [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1027.016 Junk Code Insertion](https://attack.mitre.org/techniques/T1027/016)
- [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)
- [T1564.003 Hidden Window](https://attack.mitre.org/techniques/T1564/003)
- [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013)
- [T1056.001 Keylogging](https://attack.mitre.org/techniques/T1056/001)
- [T1589.002 Email Addresses](https://attack.mitre.org/techniques/T1589/002)
- [T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010)
- [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)
- [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)
- [T1137 Office Application Startup](https://attack.mitre.org/techniques/T1137)
- [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1102 Web Service](https://attack.mitre.org/techniques/T1102)

### ATT&CK technique IDs (denormalized)

- [T1003](https://attack.mitre.org/techniques/T1003/)
- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1012](https://attack.mitre.org/techniques/T1012/)
- [T1016](https://attack.mitre.org/techniques/T1016/)
- [T1018](https://attack.mitre.org/techniques/T1018/)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [T1027.010](https://attack.mitre.org/techniques/T1027/010/)
- [T1027.011](https://attack.mitre.org/techniques/T1027/011/)
- [T1027.013](https://attack.mitre.org/techniques/T1027/013/)
- [T1027.016](https://attack.mitre.org/techniques/T1027/016/)
- [T1033](https://attack.mitre.org/techniques/T1033/)
- [T1036](https://attack.mitre.org/techniques/T1036/)
- [T1036.003](https://attack.mitre.org/techniques/T1036/003/)
- [T1036.004](https://attack.mitre.org/techniques/T1036/004/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1041](https://attack.mitre.org/techniques/T1041/)
- [T1046](https://attack.mitre.org/techniques/T1046/)
- [T1047](https://attack.mitre.org/techniques/T1047/)
- [T1048.003](https://attack.mitre.org/techniques/T1048/003/)
- [T1049](https://attack.mitre.org/techniques/T1049/)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [T1055](https://attack.mitre.org/techniques/T1055/)
- [T1056.001](https://attack.mitre.org/techniques/T1056/001/)
- [T1059](https://attack.mitre.org/techniques/T1059/)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [T1059.005](https://attack.mitre.org/techniques/T1059/005/)
- [T1059.007](https://attack.mitre.org/techniques/T1059/007/)
- [T1068](https://attack.mitre.org/techniques/T1068/)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- [T1070.006](https://attack.mitre.org/techniques/T1070/006/)
- [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [T1071.003](https://attack.mitre.org/techniques/T1071/003/)
- [T1072](https://attack.mitre.org/techniques/T1072/)
- [T1078.003](https://attack.mitre.org/techniques/T1078/003/)
- [T1082](https://attack.mitre.org/techniques/T1082/)
- [T1083](https://attack.mitre.org/techniques/T1083/)
- [T1087.001](https://attack.mitre.org/techniques/T1087/001/)
- [T1102](https://attack.mitre.org/techniques/T1102/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1112](https://attack.mitre.org/techniques/T1112/)
- [T1135](https://attack.mitre.org/techniques/T1135/)
- [T1137](https://attack.mitre.org/techniques/T1137/)
- [T1189](https://attack.mitre.org/techniques/T1189/)
- [T1203](https://attack.mitre.org/techniques/T1203/)
- [T1204.001](https://attack.mitre.org/techniques/T1204/001/)
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [T1216.001](https://attack.mitre.org/techniques/T1216/001/)
- [T1218.005](https://attack.mitre.org/techniques/T1218/005/)
- [T1218.010](https://attack.mitre.org/techniques/T1218/010/)
- [T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [T1222.002](https://attack.mitre.org/techniques/T1222/002/)
- [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [T1550.003](https://attack.mitre.org/techniques/T1550/003/)
- [T1552.002](https://attack.mitre.org/techniques/T1552/002/)
- [T1560](https://attack.mitre.org/techniques/T1560/)
- [T1564.001](https://attack.mitre.org/techniques/T1564/001/)
- [T1564.003](https://attack.mitre.org/techniques/T1564/003/)
- [T1564.004](https://attack.mitre.org/techniques/T1564/004/)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [T1569.002](https://attack.mitre.org/techniques/T1569/002/)
- [T1570](https://attack.mitre.org/techniques/T1570/)
- [T1571](https://attack.mitre.org/techniques/T1571/)
- [T1574.001](https://attack.mitre.org/techniques/T1574/001/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [T1583.006](https://attack.mitre.org/techniques/T1583/006/)
- [T1585.001](https://attack.mitre.org/techniques/T1585/001/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1589](https://attack.mitre.org/techniques/T1589/)
- [T1589.002](https://attack.mitre.org/techniques/T1589/002/)
- [T1598.003](https://attack.mitre.org/techniques/T1598/003/)
- [T1608.001](https://attack.mitre.org/techniques/T1608/001/)
- [T1608.004](https://attack.mitre.org/techniques/T1608/004/)
- [T1685.005](https://attack.mitre.org/techniques/T1685/005/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 3 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **CyberGate**
- **Cyber Eye RAT**
- **CrossRat**

### MITRE ATT&CK Software
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [ipconfig (S0100) — tool](https://attack.mitre.org/software/S0100)
- [Kerrdown (S0585) — malware](https://attack.mitre.org/software/S0585)
- [Cobalt Strike (S0154) — malware](https://attack.mitre.org/software/S0154)
- [SOUNDBITE (S0157) — malware](https://attack.mitre.org/software/S0157)
- [OSX_OCEANLOTUS.D (S0352) — malware](https://attack.mitre.org/software/S0352)
- [KOMPROGO (S0156) — malware](https://attack.mitre.org/software/S0156)
- [netsh (S0108) — tool](https://attack.mitre.org/software/S0108)
- [RotaJakiro (S1078) — malware](https://attack.mitre.org/software/S1078)
- [PHOREAL (S0158) — malware](https://attack.mitre.org/software/S0158)
- [Arp (S0099) — tool](https://attack.mitre.org/software/S0099)
- [WINDSHIELD (S0155) — malware](https://attack.mitre.org/software/S0155)
- [Denis (S0354) — malware](https://attack.mitre.org/software/S0354)
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [Goopy (S0477) — malware](https://attack.mitre.org/software/S0477)

## Attribution and Evidence
**Country of Origin**: Vietnam
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G0050)
[8] [Amnesty Intl. Ocean Lotus February 2021](https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf)
   Amnesty International. (2021, February 24). Vietnamese activists targeted by notorious hacking group. Retrieved March 1, 2021.
[9] [FireEye APT32 May 2017](https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html)
   Carr, N.. (2017, May 14). Cyber Espionage is Alive and Well: APT32 and the Threat to Global Corporations. Retrieved June 18, 2017.
[10] [Cybereason Oceanlotus May 2017](https://www.cybereason.com/blog/operation-cobalt-kitty-apt)
   Dahan, A. (2017, May 24). OPERATION COBALT KITTY: A LARGE-SCALE APT IN ASIA CARRIED OUT BY THE OCEANLOTUS GROUP. Retrieved November 5, 2018.
[11] [ESET OceanLotus Mar 2019](https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/)
   Dumont, R. (2019, March 20). Fake or Fake: Keeping up with OceanLotus decoys. Retrieved April 1, 2019.
[12] [ESET OceanLotus](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)
   Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.
[13] [Volexity OceanLotus Nov 2017](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/)
   Lassalle, D., et al. (2017, November 6). OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society. Retrieved November 6, 2017.
[14] [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide)
   Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.

