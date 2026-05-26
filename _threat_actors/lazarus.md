---
layout: threat_actor
title: "Lazarus Group"
aliases: ["Andariel","Appleworm","APT 38","APT-C-26","APT38","ATK117","ATK3","BeagleBoyz","Black Artemis","Bluenoroff","Bureau 121","Citrine Sleet","COPERNICIUM","COVELLITE","Dark Seoul","DEV-0139","DEV-1222","Diamond Sleet","G0032","G0082","Group 77","Guardians of Peace","Hastati Group","Hidden Cobra","HIDDEN COBRA","Labyrinth Chollima","Lazarus Group","Lazarus group","Moonstone Sleet","NewRomanic Cyber Army Team","NICKEL ACADEMY","Nickel Academy","NICKEL GLADSTONE","Operation AppleJeus","Operation DarkSeoul","Operation GhostSecret","Operation Troy","Sapphire Sleet","Stardust Chollima","Subgroup: Bluenoroff","TA404","Unit 121","Whois Hacking Team","ZINC","Zinc","Lazarus - APT-C-26","Lazarus","Genie Spider","UNC1069","Alluring Pisces","CageyChameleon","CryptoCore","MASAN"]
description: "Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). [US-CERT HIDDEN COBRA June 2017](https://www.us-cert.gov/ncas/alerts/TA17-164A)"
permalink: /lazarus/
---

## Introduction
Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). [US-CERT HIDDEN COBRA June 2017](https://www.us-cert.gov/ncas/alerts/TA17-164A) [Treasury North Korean Cyber Groups September 2019](https://home.treasury.gov/news/press-releases/sm774) Lazarus Group has been active since at least 2009 and is reportedly responsible for the November 2014 destructive wiper attack on Sony Pictures Entertainment, identified by Novetta as part of Operation Blockbuster. Malware used by Lazarus Group correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain. [Novetta Blockbuster](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf) North Korea’s cyber operations have shown a consistent pattern of adaptation, forming and reorganizing units as national priorities shift. These units frequently share personnel, infrastructure, malware, and tradecraft, making it difficult to attribute specific operations with high confidence. Public reporting often uses “Lazarus Group” as an umbrella term for multiple North Korean cyber operators conducting espionage, destructive attacks, and financially motivated campaigns. [Mandiant DPRK Laz Org Breakdown 2022](https://cloud.google.com/blog/topics/threat-intelligence/mapping-dprk-groups-to-government/) [Mandiant DPRK Groups 2023](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-cyber-structure-alignment-2023) [JPCert Blog Laz Subgroups 2025](https://blogs.jpcert.or.jp/en/2025/03/classifying-lazaruss-subgroup.html)

## Activities and Tactics
**Targeted Sectors**: Financial, Cryptocurrency, Entertainment, Government, Private sector

**Country of Origin**: 🇰🇵 North Korea

**Risk Level**: Critical

**First Seen**: 2009

**Last Activity**: 2024

**Incident Type**: ["Espionage", "Sabotage"]

**Suspected Victims**: South Korea, Bangladesh Bank, Sony Pictures Entertainment, United States, Thailand, France, China, Hong Kong, United Kingdom, Guatemala...

## Notable Campaigns
- [Operation Dream Job (C0022)](https://attack.mitre.org/campaigns/C0022): Operation Dream Job was a cyber espionage operation likely conducted by Lazarus Group that targeted the defense, aerospace, government, and other sectors in the United States, Israel, Australia, Russia, and India. In at least one case, the cyber actors tried to monetize their network access to conduct a business email compromise (BEC) operation. In 2020, security researchers noted overlapping TTPs, to include fake job lures and code similarities, between Operation Dream Job, Operation North Star,

## Tactics, Techniques, and Procedures (TTPs)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1202 Indirect Command Execution](https://attack.mitre.org/techniques/T1202)
- [T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)
- [T1001.003 Protocol or Service Impersonation](https://attack.mitre.org/techniques/T1001/003)
- [T1584.004 Server](https://attack.mitre.org/techniques/T1584/004)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005)
- [T1010 Application Window Discovery](https://attack.mitre.org/techniques/T1010)
- [T1587.001 Malware](https://attack.mitre.org/techniques/T1587/001)
- [T1134.002 Create Process with Token](https://attack.mitre.org/techniques/T1134/002)
- [T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004)
- [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098)
- [T1564.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001)
- [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485)
- [T1591 Gather Victim Org Information](https://attack.mitre.org/techniques/T1591)
- [T1106 Native API](https://attack.mitre.org/techniques/T1106)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1027.009 Embedded Payloads](https://attack.mitre.org/techniques/T1027/009)
- [T1012 Query Registry](https://attack.mitre.org/techniques/T1012)
- [T1090.002 External Proxy](https://attack.mitre.org/techniques/T1090/002)
- [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013)
- [T1104 Multi-Stage Channels](https://attack.mitre.org/techniques/T1104)
- [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1489 Service Stop](https://attack.mitre.org/techniques/T1489)
- [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1588.004 Digital Certificates](https://attack.mitre.org/techniques/T1588/004)
- [T1573.001 Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001)
- [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082)
- [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)
- [T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620)
- [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)
- [T1102.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002)
- [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560)
- [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1074.001 Local Data Staging](https://attack.mitre.org/techniques/T1074/001)
- [T1036.003 Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003)
- [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)
- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)
- [T1557.001 Name Resolution Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)
- [T1589.002 Email Addresses](https://attack.mitre.org/techniques/T1589/002)
- [T1561.001 Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001)
- [T1491.001 Internal Defacement](https://attack.mitre.org/techniques/T1491/001)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1547.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009)
- [T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005)
- [T1542.003 Bootkit](https://attack.mitre.org/techniques/T1542/003)
- [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011)
- [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006)
- [T1056.001 Keylogging](https://attack.mitre.org/techniques/T1056/001)
- [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571)
- [T1132.001 Standard Encoding](https://attack.mitre.org/techniques/T1132/001)
- [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189)
- [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002)
- [T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)
- [T1560.002 Archive via Library](https://attack.mitre.org/techniques/T1560/002)
- [T1027.007 Dynamic API Resolution](https://attack.mitre.org/techniques/T1027/007)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1090.001 Internal Proxy](https://attack.mitre.org/techniques/T1090/001)
- [T1008 Fallback Channels](https://attack.mitre.org/techniques/T1008)
- [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)
- [T1680 Local Storage Discovery](https://attack.mitre.org/techniques/T1680)
- [T1561.002 Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)
- [T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1574.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013)
- [T1055.001 Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001)
- [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)
- [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)
- [T1529 System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529)
- [T1124 System Time Discovery](https://attack.mitre.org/techniques/T1124)
- [T1036.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004)
- [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006)
- [T1070.003 Clear Command History](https://attack.mitre.org/techniques/T1070/003)
- [T1574.001 DLL](https://attack.mitre.org/techniques/T1574/001)
- [T1686.003 Windows Host Firewall](https://attack.mitre.org/techniques/T1686/003)
- [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003)
- [T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [T1585.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002)
- [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)
- [T1560.003 Archive via Custom Method](https://attack.mitre.org/techniques/T1560/003)
- [T0865 Spearphishing Attachment](https://attack.mitre.org/techniques/T0865)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 18 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **Wiper**
- **RemoteCMD**
- **Remote Utilities**
- **RemotePC**
- **Whois Wiper**: 

### MITRE ATT&CK Software
- [RawDisk (S0364) — tool](https://attack.mitre.org/software/S0364)
- [Proxysvc (S0238) — malware](https://attack.mitre.org/software/S0238)
- [BADCALL (S0245) — malware](https://attack.mitre.org/software/S0245)
- [FALLCHILL (S0181) — malware](https://attack.mitre.org/software/S0181)
- [WannaCry (S0366) — malware](https://attack.mitre.org/software/S0366)
- [MagicRAT (S1182) — malware](https://attack.mitre.org/software/S1182)
- [HOPLIGHT (S0376) — malware](https://attack.mitre.org/software/S0376)
- [TYPEFRAME (S0263) — malware](https://attack.mitre.org/software/S0263)
- [Dtrack (S0567) — malware](https://attack.mitre.org/software/S0567)
- [HotCroissant (S0431) — malware](https://attack.mitre.org/software/S0431)
- [HARDRAIN (S0246) — malware](https://attack.mitre.org/software/S0246)
- [Dacls (S0497) — malware](https://attack.mitre.org/software/S0497)
- [KEYMARBLE (S0271) — malware](https://attack.mitre.org/software/S0271)
- [TAINTEDSCRIBE (S0586) — malware](https://attack.mitre.org/software/S0586)
- [AuditCred (S0347) — malware](https://attack.mitre.org/software/S0347)
- [netsh (S0108) — tool](https://attack.mitre.org/software/S0108)
- [ECCENTRICBANDWAGON (S0593) — malware](https://attack.mitre.org/software/S0593)
- [AppleJeus (S0584) — malware](https://attack.mitre.org/software/S0584)
- [route (S0103) — tool](https://attack.mitre.org/software/S0103)
- [BLINDINGCAN (S0520) — malware](https://attack.mitre.org/software/S0520)
- [ThreatNeedle (S0665) — malware](https://attack.mitre.org/software/S0665)
- [Volgmer (S0180) — malware](https://attack.mitre.org/software/S0180)
- [Cryptoistic (S0498) — malware](https://attack.mitre.org/software/S0498)
- [Responder (S0174) — tool](https://attack.mitre.org/software/S0174)
- [RATANKBA (S0241) — malware](https://attack.mitre.org/software/S0241)
- [Bankshot (S0239) — malware](https://attack.mitre.org/software/S0239)

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

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [Lazarus Deploys RemotePE Memory-Only RAT Against Financial and Crypto Firms](https://thehackernews.com/2026/05/lazarus-deploys-remotepe-memory-only.html)
  The Hacker News - 2026-05-25T

