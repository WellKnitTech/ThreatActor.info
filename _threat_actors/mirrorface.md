---
layout: threat_actor
title: "MirrorFace"
aliases: ["Earth Kasha","MirrorFace"]
description: "MirrorFace is a People's Republic of China (PRC)-aligned cyberespionage actor believed to be a subgroup under the menuPass umbrella based on targeting, tools, and infrastructure overlaps. MirrorFace ha"
permalink: /mirrorface/
---

## Introduction
MirrorFace is a People's Republic of China (PRC)-aligned cyberespionage actor believed to be a subgroup under the menuPass umbrella based on targeting, tools, and infrastructure overlaps. MirrorFace has been active since at least 2019, at first exclusively targeting Japanese organizations across the media, defense, diplomatic, financial, manufacturing, and academic sectors. Subsequent MirrorFace operations included targets in Central Europe and featured use of LODEINFO, HiddenFace, and UPPERCUT malware. [Kaspersky LODEINFO OCT 2022](https://securelist.com/apt10-tracking-down-lodeinfo-2022-part-i/107742/) [Kaspersky LODEINFO Part II OCT 2022](https://securelist.com/apt10-tracking-down-lodeinfo-2022-part-ii/107745/) [ESET MirrorFace DEC 2022](https://www.welivesecurity.com/2022/12/14/unmasking-mirrorface-operation-liberalface-targeting-japanese-political-entities/) [JPCERT MirrorFace JUL 2024](https://blogs.jpcert.or.jp/en/2024/07/mirrorface-attack-against-japanese-organisations.html) [Trend Micro Earth Kasha NOV 2024](https://www.trendmicro.com/en_us/research/24/k/lodeinfo-campaign-of-earth-kasha.html) [Trend Micro Earth Kasha Updates APR 2025](https://www.trendmicro.com/en_us/research/25/d/earth-kasha-updates-ttps.html)

## Activities and Tactics
**Country of Origin**: 🇨🇳 China





## Notable Campaigns
- [Operation AkaiRyū (C0060)](https://attack.mitre.org/campaigns/C0060): Operation AkaiRyū (Japanese for RedDragon) was a cyberespionage spearphishing campaign conducted by MirrorFace between June and September 2024 against entities in Japan and Central Europe. Operation AkaiRyū notably included the first reported targeting of a European entity by MirrorFace, as well as their use of UPPERCUT, which was thought to be exclusive to menuPass.(Citation: ESET MirrorFace 2025)(Citation: Trend Micro Earth Kasha Anel NOV 2024)

## Tactics, Techniques, and Procedures (TTPs)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1686.003 Windows Host Firewall](https://attack.mitre.org/techniques/T1686/003)
- [T1074.002 Remote Data Staging](https://attack.mitre.org/techniques/T1074/002)
- [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)
- [T1087.002 Domain Account](https://attack.mitre.org/techniques/T1087/002)
- [T1614.001 System Language Discovery](https://attack.mitre.org/techniques/T1614/001)
- [T1591 Gather Victim Org Information](https://attack.mitre.org/techniques/T1591)
- [T1090 Proxy](https://attack.mitre.org/techniques/T1090)
- [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)
- [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)
- [T1587.001 Malware](https://attack.mitre.org/techniques/T1587/001)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1003.002 Security Account Manager](https://attack.mitre.org/techniques/T1003/002)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1482 Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)
- [T1684.001 Impersonation](https://attack.mitre.org/techniques/T1684/001)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
- [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005)
- [T1007 System Service Discovery](https://attack.mitre.org/techniques/T1007)
- [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082)
- [T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002)
- [T1574.001 DLL](https://attack.mitre.org/techniques/T1574/001)
- [T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [T1071.002 File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1036.008 Masquerade File Type](https://attack.mitre.org/techniques/T1036/008)
- [T1003.003 NTDS](https://attack.mitre.org/techniques/T1003/003)
- [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001)
- [T1221 Template Injection](https://attack.mitre.org/techniques/T1221)
- [T1556.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002)
- [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)
- [T1114.001 Local Email Collection](https://attack.mitre.org/techniques/T1114/001)
- [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013)
- [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)

### ATT&CK technique IDs (denormalized)

- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1003.002](https://attack.mitre.org/techniques/T1003/002/)
- [T1003.003](https://attack.mitre.org/techniques/T1003/003/)
- [T1005](https://attack.mitre.org/techniques/T1005/)
- [T1007](https://attack.mitre.org/techniques/T1007/)
- [T1016](https://attack.mitre.org/techniques/T1016/)
- [T1018](https://attack.mitre.org/techniques/T1018/)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [T1027.013](https://attack.mitre.org/techniques/T1027/013/)
- [T1033](https://attack.mitre.org/techniques/T1033/)
- [T1036.008](https://attack.mitre.org/techniques/T1036/008/)
- [T1047](https://attack.mitre.org/techniques/T1047/)
- [T1048.002](https://attack.mitre.org/techniques/T1048/002/)
- [T1057](https://attack.mitre.org/techniques/T1057/)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [T1059.005](https://attack.mitre.org/techniques/T1059/005/)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- [T1071.002](https://attack.mitre.org/techniques/T1071/002/)
- [T1074.002](https://attack.mitre.org/techniques/T1074/002/)
- [T1082](https://attack.mitre.org/techniques/T1082/)
- [T1083](https://attack.mitre.org/techniques/T1083/)
- [T1087.002](https://attack.mitre.org/techniques/T1087/002/)
- [T1090](https://attack.mitre.org/techniques/T1090/)
- [T1114.001](https://attack.mitre.org/techniques/T1114/001/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [T1221](https://attack.mitre.org/techniques/T1221/)
- [T1482](https://attack.mitre.org/techniques/T1482/)
- [T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [T1556.002](https://attack.mitre.org/techniques/T1556/002/)
- [T1560.001](https://attack.mitre.org/techniques/T1560/001/)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [T1574.001](https://attack.mitre.org/techniques/T1574/001/)
- [T1587.001](https://attack.mitre.org/techniques/T1587/001/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1591](https://attack.mitre.org/techniques/T1591/)
- [T1614.001](https://attack.mitre.org/techniques/T1614/001/)
- [T1684.001](https://attack.mitre.org/techniques/T1684/001/)
- [T1685](https://attack.mitre.org/techniques/T1685/)
- [T1685.005](https://attack.mitre.org/techniques/T1685/005/)
- [T1686.003](https://attack.mitre.org/techniques/T1686/003/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Umbreon**: 
- **China Chopper**: 
- **CyberGate**: 
- **Cyber Eye RAT**: 

### MITRE ATT&CK Software
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [Cobalt Strike (S0154) — malware](https://attack.mitre.org/software/S0154)
- [MirrorStealer (S9022) — malware](https://attack.mitre.org/software/S9022)
- [UPPERCUT (S0275) — malware](https://attack.mitre.org/software/S0275)
- [Nltest (S0359) — tool](https://attack.mitre.org/software/S0359)
- [BITSAdmin (S0190) — tool](https://attack.mitre.org/software/S0190)
- [Tasklist (S0057) — tool](https://attack.mitre.org/software/S0057)
- [ipconfig (S0100) — tool](https://attack.mitre.org/software/S0100)
- [LODEINFO (S9020) — malware](https://attack.mitre.org/software/S9020)
- [ROAMINGHOUSE (S9026) — malware](https://attack.mitre.org/software/S9026)
- [DOWNIISSA (S9021) — malware](https://attack.mitre.org/software/S9021)
- [nbtstat (S0102) — tool](https://attack.mitre.org/software/S0102)
- [HiddenFace (S9023) — malware](https://attack.mitre.org/software/S9023)
- [Ping (S0097) — tool](https://attack.mitre.org/software/S0097)
- [Wevtutil (S0645) — tool](https://attack.mitre.org/software/S0645)
- [NOOPLDR (S9025) — malware](https://attack.mitre.org/software/S9025)

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G1054)
[3] [ESET MirrorFace DEC 2022](https://www.welivesecurity.com/2022/12/14/unmasking-mirrorface-operation-liberalface-targeting-japanese-political-entities/)
   Breitenbacher, D. (2022, December 14). Unmasking MirrorFace: Operation LiberalFace targeting Japanese political entities. Retrieved April 17, 2026.
[4] [Trend Micro Earth Kasha Updates APR 2025](https://www.trendmicro.com/en_us/research/25/d/earth-kasha-updates-ttps.html)
   Hiroaki, H. (2025, April 30). Earth Kasha Updates TTPs in Latest Campaign Targeting Taiwan and Japan. Retrieved April 17, 2026.
[5] [Kaspersky LODEINFO OCT 2022](https://securelist.com/apt10-tracking-down-lodeinfo-2022-part-i/107742/)
   Ishimaru, S. (2022, October 31). APT10: Tracking down LODEINFO 2022, part I. Retrieved April 17, 2026.
[6] [Kaspersky LODEINFO Part II OCT 2022](https://securelist.com/apt10-tracking-down-lodeinfo-2022-part-ii/107745/)
   Ishimaru, S. (2022, October 31). APT10: Tracking down LODEINFO 2022, part II. Retrieved April 17, 2026.
[7] [JPCERT MirrorFace JUL 2024](https://blogs.jpcert.or.jp/en/2024/07/mirrorface-attack-against-japanese-organisations.html)
   Tomonaga, S. (2024, July 16). MirrorFace Attack against Japanese Organisations. Retrieved April 17, 2026.
[8] [Trend Micro Earth Kasha NOV 2024](https://www.trendmicro.com/en_us/research/24/k/lodeinfo-campaign-of-earth-kasha.html)
   Trend Micro. (2024, November 19). Spot the Difference: Earth Kasha's New LODEINFO Campaign And The Correlation Analysis With The APT10 Umbrella. Retrieved April 17, 2026.

