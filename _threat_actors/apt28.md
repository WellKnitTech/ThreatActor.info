---
layout: threat_actor
title: "APT28"
aliases: ["APT-C-20", "APT28", "ATK5", "Blue Athena", "BlueDelta", "Fancy Bear", "FANCY BEAR", "Fighting Ursa", "Forest Blizzard", "FROZENLAKE", "G0007", "Grizzly Steppe", "Group 74", "GruesomeLarch", "IRON TWILIGHT", "ITG05", "Pawn Storm", "Sednit", "SIG40", "SNAKEMACKEREL", "Sofacy", "Sofacy Group", "STRONTIUM", "Swallowtail", "T-APT-12", "TA422", "TG-4127", "Threat Group-4127", "Tsar Team", "UAC-0001", "UAC-0028", "APT 28", "TsarTeam", "Group-4127", "Grey-Cloud", "Strontium", "Armada Collective", "Dark Power"]
description: "APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165. [NSA/FBI Drovorub August 202"
permalink: /apt28/
---

## Introduction
APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165. [NSA/FBI Drovorub August 2020](https://media.defense.gov/2020/Aug/13/2002476465/-1/-1/0/CSA_DROVORUB_RUSSIAN_GRU_MALWARE_AUG_2020.PDF) [Cybersecurity Advisory GRU Brute Force Campaign July 2021](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF) This group has been active since at least 2004. [DOJ GRU Indictment Jul 2018](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf) [Ars Technica GRU indictment Jul 2018](https://arstechnica.com/information-technology/2018/07/from-bitly-to-x-agent-how-gru-hackers-targeted-the-2016-presidential-election/) [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) [FireEye APT28](https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf) [SecureWorks TG-4127](https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign) [FireEye APT28 January 2017](https://www.mandiant.com/sites/default/files/2021-09/APT28-Center-of-Storm-2017.pdf) [GRIZZLY STEPPE JAR](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf) [Sofacy DealersChoice](https://researchcenter.paloaltonetworks.com/2018/03/unit42-sofacy-uses-dealerschoice-target-european-government-agency/) [Palo Alto Sofacy 06-2018](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/) [Symantec APT28 Oct 2018](https://www.symantec.com/blogs/election-security/apt28-espionage-military-government) [ESET Zebrocy May 2019](https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/) APT28 reportedly compromised the Hillary Clinton campaign, the Democratic National Committee, and the Democratic Congressional Campaign Committee in 2016 in an attempt to interfere with the U.S. presidential election. [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) In 2018, the US indicted five GRU Unit 26165 officers associated with APT28 for cyber operations (including close-access operations) conducted between 2014 and 2018 against the World Anti-Doping Agency (WADA), the US Anti-Doping Agency, a US nuclear facility, the Organization for the Prohibition of Chemical Weapons (OPCW), the Spiez Swiss Chemicals Laboratory, and other organizations. [US District Court Indictment GRU Oct 2018](https://www.justice.gov/opa/page/file/1098481/download) Some of these were conducted with the assistance of GRU Unit 74455, which is also referred to as Sandworm Team.

## Activities and Tactics
**Targeted Sectors**: Government, Military, Media, Government, Administration, Security Service

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: High

**First Seen**: 2007

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: Georgia, France, Jordan, United States, Hungary, World Anti-Doping Agency, Armenia, Tajikistan, Japan, NATO...

## Notable Campaigns
- **Russian Doll**
- **Bundestag**
- **TV5 Monde "Cyber Caliphate"**
- **EFF Attack**
- **DNC Hack**
- **OpOlympics**
- **Burisma**

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0007 (YAML `ttps` empty).*

- [T1001.001 Junk Data](/techniques/T1001.001/)
- [T1003 OS Credential Dumping](/techniques/T1003/)
- [T1003.001 LSASS Memory](/techniques/T1003.001/)
- [T1003.003 NTDS](/techniques/T1003.003/)
- [T1005 Data from Local System](/techniques/T1005/)
- [T1014 Rootkit](/techniques/T1014/)
- [T1021.002 SMB/Windows Admin Shares](/techniques/T1021.002/)
- [T1025 Data from Removable Media](/techniques/T1025/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1030 Data Transfer Size Limits](/techniques/T1030/)
- [T1036 Masquerading](/techniques/T1036/)
- [T1036.005 Match Legitimate Resource Name or Location](/techniques/T1036.005/)
- [T1037.001 Logon Script (Windows)](/techniques/T1037.001/)
- [T1039 Data from Network Shared Drive](/techniques/T1039/)
- [T1040 Network Sniffing](/techniques/T1040/)
- [T1043](https://attack.mitre.org/techniques/T1043/)
- [T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/techniques/T1048.002/)
- [T1056.001 Keylogging](/techniques/T1056.001/)
- [T1057 Process Discovery](/techniques/T1057/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1068 Exploitation for Privilege Escalation](/techniques/T1068/)
- [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [T1070.004 File Deletion](/techniques/T1070.004/)
- [T1070.006 Timestomp](/techniques/T1070.006/)
- [T1071.001 Web Protocols](/techniques/T1071.001/)
- [T1071.003 Mail Protocols](/techniques/T1071.003/)
- [T1074.001 Local Data Staging](/techniques/T1074.001/)
- [T1074.002 Remote Data Staging](/techniques/T1074.002/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1078.004 Cloud Accounts](/techniques/T1078.004/)
- [T1083 File and Directory Discovery](/techniques/T1083/)
- [T1090.002 External Proxy](/techniques/T1090.002/)
- [T1090.003 Multi-hop Proxy](/techniques/T1090.003/)
- [T1091 Replication Through Removable Media](/techniques/T1091/)
- [T1092 Communication Through Removable Media](/techniques/T1092/)
- [T1098.002 Additional Email Delegate Permissions](/techniques/T1098.002/)
- [T1102.002 Bidirectional Communication](/techniques/T1102.002/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1110 Brute Force](/techniques/T1110/)
- [T1110.001 Password Guessing](/techniques/T1110.001/)
- [T1110.003 Password Spraying](/techniques/T1110.003/)
- [T1113 Screen Capture](/techniques/T1113/)
- [T1114.002 Remote Email Collection](/techniques/T1114.002/)
- [T1119 Automated Collection](/techniques/T1119/)
- [T1120 Peripheral Device Discovery](/techniques/T1120/)
- [T1133 External Remote Services](/techniques/T1133/)
- [T1134.001 Token Impersonation/Theft](/techniques/T1134.001/)
- [T1137.002 Office Test](/techniques/T1137.002/)
- [T1140 Deobfuscate/Decode Files or Information](/techniques/T1140/)
- [T1189 Drive-by Compromise](/techniques/T1189/)
- [T1190 Exploit Public-Facing Application](/techniques/T1190/)
- [T1199 Trusted Relationship](/techniques/T1199/)
- [T1203 Exploitation for Client Execution](/techniques/T1203/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1210 Exploitation of Remote Services](/techniques/T1210/)
- [T1211 Exploitation for Stealth](/techniques/T1211/)
- [T1213 Data from Information Repositories](/techniques/T1213/)
- [T1213.002 Sharepoint](/techniques/T1213.002/)
- [T1218.011 Rundll32](/techniques/T1218.011/)
- [T1221 Template Injection](/techniques/T1221/)
- [T1498 Network Denial of Service](/techniques/T1498/)
- [T1505.003 Web Shell](/techniques/T1505.003/)
- [T1528 Steal Application Access Token](/techniques/T1528/)
- [T1542.003 Bootkit](/techniques/T1542.003/)
- [T1546.015 Component Object Model Hijacking](/techniques/T1546.015/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1550.001 Application Access Token](/techniques/T1550.001/)
- [T1550.002 Pass the Hash](/techniques/T1550.002/)
- [T1559.002 Dynamic Data Exchange](/techniques/T1559.002/)
- [T1560 Archive Collected Data](/techniques/T1560/)
- [T1560.001 Archive via Utility](/techniques/T1560.001/)
- [T1564.001 Hidden Files and Directories](/techniques/T1564.001/)
- [T1564.003 Hidden Window](/techniques/T1564.003/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1567 Exfiltration Over Web Service](/techniques/T1567/)
- [T1573.001 Symmetric Cryptography](/techniques/T1573.001/)
- [T1583.001 Domains](/techniques/T1583.001/)
- [T1583.006 Web Services](/techniques/T1583.006/)
- [T1586.002 Email Accounts](/techniques/T1586.002/)
- [T1588.002 Tool](/techniques/T1588.002/)
- [T1589.001 Credentials](/techniques/T1589.001/)
- [T1595.002 Vulnerability Scanning](/techniques/T1595.002/)
- [T1598 Phishing for Information](/techniques/T1598/)
- [T1598.003 Spearphishing Link](/techniques/T1598.003/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 26 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **CyberGate**
- **Cyber Eye RAT**
- **X-Agent**
- **Komplex**
- **ArguePatch**
- **Cannon**
- **DriveOcean**
- **Unidentified 114 (APT28 InfoStealer)**
- **XP PrivEsc (CVE-2014-4076)**
- **X-Tunnel (.NET)**
- **Zebrocy (AutoIT)**
- **LoJax**
- **CredoMap**
- **Mocky LNK**
- **OCEANMAP**
- **SpyPress**
- **STEELHOOK**
- **MASEPIE**
- **LAMEHUG**
- **CaddyWiper**
- **Computrace**
- **Coreshell**
- **Downdelph**
- **FusionDrive**
- **GooseEgg**
- **Graphite**
- **Koadic**
- **OLDBAIT**
- **PocoDown**
- **Sedreco**
- **Seduploader**
- **Unidentified 078 (Zebrocy Nim Loader?)**
- **Zebrocy**
- **GONEPOSTAL**
- **BadPaw**
- **BEARDSHELL**
- **SLIMAGENT**
- **XTunnel**
- **Unidentified JS 007 (Zimbra Stealer)**
- **PixyNetLoader**
- **CHOPSTICK**: 
- **CORESHELL**: 
- **Winexe**: 
- **SOURFACE**: 
- **OLDBAIT**: 
- **Sofacy**: 
- **XAgent**: 
- **XTunnel**: 
- **WinIDS**: 
- **Foozer**: 
- **DownRange**: 
- **Sedreco Dropper**: 
- **Komplex**: 
- **DealersChoice**: 
- **Downdelph**: 
- **Sednit**: 
- **USBStealer**: 
- **Sedkit**: 
- **HideDrv (Rootkit)**: 
- **LoJax**: 
- **SeduUploader**: 
- **Promptsteal**: 
- **Promptflux**: 

### Russian APT Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz |
| LOLBAS | MiniDump, Windows Event Utility (wevtutil) |
| Networking | OpenSSH, ReGeorg, SSHDoor |
| OffSec | Empyre, Impacket, Koadic, Metasploit, Nishang, PowerShell Empire, Responder |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0007)
   MITRE ATT&CK entry
[2] [NSA/FBI Drovorub August 2020](https://media.defense.gov/2020/Aug/13/2002476465/-1/-1/0/CSA_DROVORUB_RUSSIAN_GRU_MALWARE_AUG_2020.PDF)
[3] [Cybersecurity Advisory GRU Brute Force Campaign July 2021](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
[4] [DOJ GRU Indictment Jul 2018](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)
[5] [Ars Technica GRU indictment Jul 2018](https://arstechnica.com/information-technology/2018/07/from-bitly-to-x-agent-how-gru-hackers-targeted-the-2016-presidential-election/)
[6] [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)
[7] [FireEye APT28](https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf)
[8] [SecureWorks TG-4127](https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign)
[9] [FireEye APT28 January 2017](https://www.mandiant.com/sites/default/files/2021-09/APT28-Center-of-Storm-2017.pdf)
[10] [GRIZZLY STEPPE JAR](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)
[11] [Sofacy DealersChoice](https://researchcenter.paloaltonetworks.com/2018/03/unit42-sofacy-uses-dealerschoice-target-european-government-agency/)
[12] [Palo Alto Sofacy 06-2018](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)
[13] [Symantec APT28 Oct 2018](https://www.symantec.com/blogs/election-security/apt28-espionage-military-government)
[14] [ESET Zebrocy May 2019](https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/)
[15] [US District Court Indictment GRU Oct 2018](https://www.justice.gov/opa/page/file/1098481/download)

