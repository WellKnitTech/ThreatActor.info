---
layout: threat_actor
title: "APT28"
aliases: ["APT 28","APT-C-20","APT28","Armada Collective","ATK5","Blue Athena","BlueDelta","Dark Power","Fancy Bear","FANCY BEAR","Fighting Ursa","Forest Blizzard","FROZENLAKE","G0007","Grey-Cloud","Grizzly Steppe","Group 74","Group-4127","GruesomeLarch","IRON TWILIGHT","ITG05","Pawn Storm","Sednit","SIG40","SNAKEMACKEREL","Sofacy","Sofacy Group","STRONTIUM","Strontium","Swallowtail","T-APT-12","TA422","TG-4127","Threat Group-4127","Tsar Team","TsarTeam","UAC-0001","UAC-0028","奇幻熊 - APT-C-20","ATG2","Z-Lom Team","Operation Pawn Storm","CrisisFour","HELLFIRE"]
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
- [APT28 Nearest Neighbor Campaign (C0051)](https://attack.mitre.org/campaigns/C0051): APT28 Nearest Neighbor Campaign was conducted by APT28 from early February 2022 to November 2024 against organizations and individuals with expertise on Ukraine. APT28 primarily leveraged living-off-the-land techniques, while leveraging the zero-day exploitation of CVE-2022-38028. Notably, APT28 leveraged Wi-Fi networks in close proximity to the intended target to gain initial access to the victim environment. By daisy-chaining multiple compromised organizations nearby the intended target, APT28 

## Tactics, Techniques, and Procedures (TTPs)
- [T1003.003 NTDS](https://attack.mitre.org/techniques/T1003/003)
- [T1589.001 Credentials](https://attack.mitre.org/techniques/T1589/001)
- [T1591 Gather Victim Org Information](https://attack.mitre.org/techniques/T1591)
- [T1564.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001)
- [T1583.003 Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)
- [T1596 Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006)
- [T1090.002 External Proxy](https://attack.mitre.org/techniques/T1090/002)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013)
- [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203)
- [T1586.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002)
- [T1114.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002)
- [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003)
- [T1584.008 Network Devices](https://attack.mitre.org/techniques/T1584/008)
- [T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002)
- [T1037.001 Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1564.003 Hidden Window](https://attack.mitre.org/techniques/T1564/003)
- [T1090.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)
- [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)
- [T1056.001 Keylogging](https://attack.mitre.org/techniques/T1056/001)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1669 Wi-Fi Networks](https://attack.mitre.org/techniques/T1669)
- [T1039 Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039)
- [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113)
- [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)
- [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189)
- [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002)
- [T1546.015 Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015)
- [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199)
- [T1120 Peripheral Device Discovery](https://attack.mitre.org/techniques/T1120)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1557.004 Evil Twin](https://attack.mitre.org/techniques/T1557/004)
- [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1598 Phishing for Information](https://attack.mitre.org/techniques/T1598)
- [T1559.002 Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1119 Automated Collection](https://attack.mitre.org/techniques/T1119)
- [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)
- [T1221 Template Injection](https://attack.mitre.org/techniques/T1221)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1213.002 Sharepoint](https://attack.mitre.org/techniques/T1213/002)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1025 Data from Removable Media](https://attack.mitre.org/techniques/T1025)
- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)
- [T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213)
- [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011)
- [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001)
- [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)
- [T1598.003 Spearphishing Link](https://attack.mitre.org/techniques/T1598/003)
- [T1542.003 Bootkit](https://attack.mitre.org/techniques/T1542/003)
- [T1071.003 Mail Protocols](https://attack.mitre.org/techniques/T1071/003)
- [T1036 Masquerading](https://attack.mitre.org/techniques/T1036)
- [T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)
- [T1014 Rootkit](https://attack.mitre.org/techniques/T1014)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001)
- [T1030 Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030)
- [T1134.001 Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001)
- [T1074.002 Remote Data Staging](https://attack.mitre.org/techniques/T1074/002)
- [T1092 Communication Through Removable Media](https://attack.mitre.org/techniques/T1092)
- [T1098.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)
- [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003)
- [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040)
- [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)
- [T1137.002 Office Test](https://attack.mitre.org/techniques/T1137/002)
- [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528)
- [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003)
- [T1204.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001)
- [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133)
- [T1102.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002)
- [T1001.001 Junk Data](https://attack.mitre.org/techniques/T1001/001)
- [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)
- [T1211 Exploitation for Stealth](https://attack.mitre.org/techniques/T1211)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1573.001 Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001)
- [T1074.001 Local Data Staging](https://attack.mitre.org/techniques/T1074/001)
- [T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)
- [T1588.007 Artificial Intelligence](https://attack.mitre.org/techniques/T1588/007)
- [T1110 Brute Force](https://attack.mitre.org/techniques/T1110)
- [T1684.001 Impersonation](https://attack.mitre.org/techniques/T1684/001)
- [T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 20 public reports that may contain IOCs; see Source Attribution for dataset links.*

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

### MITRE ATT&CK Software
- [Wevtutil (S0645) — tool](https://attack.mitre.org/software/S0645)
- [certutil (S0160) — tool](https://attack.mitre.org/software/S0160)
- [CHOPSTICK (S0023) — malware](https://attack.mitre.org/software/S0023)
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [Forfiles (S0193) — tool](https://attack.mitre.org/software/S0193)
- [DealersChoice (S0243) — malware](https://attack.mitre.org/software/S0243)
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [ADVSTORESHELL (S0045) — malware](https://attack.mitre.org/software/S0045)
- [Cannon (S0351) — malware](https://attack.mitre.org/software/S0351)
- [Komplex (S0162) — malware](https://attack.mitre.org/software/S0162)
- [HIDEDRV (S0135) — malware](https://attack.mitre.org/software/S0135)
- [JHUHUGIT (S0044) — malware](https://attack.mitre.org/software/S0044)
- [Koadic (S0250) — tool](https://attack.mitre.org/software/S0250)
- [Winexe (S0191) — tool](https://attack.mitre.org/software/S0191)
- [Responder (S0174) — tool](https://attack.mitre.org/software/S0174)
- [cipher.exe (S1205) — tool](https://attack.mitre.org/software/S1205)
- [XTunnel (S0117) — malware](https://attack.mitre.org/software/S0117)
- [Drovorub (S0502) — malware](https://attack.mitre.org/software/S0502)
- [LAMEHUG (S9035) — malware](https://attack.mitre.org/software/S9035)
- [Tor (S0183) — tool](https://attack.mitre.org/software/S0183)
- [CORESHELL (S0137) — malware](https://attack.mitre.org/software/S0137)
- [OLDBAIT (S0138) — malware](https://attack.mitre.org/software/S0138)
- [Downdelph (S0134) — malware](https://attack.mitre.org/software/S0134)
- [XAgentOSX (S0161) — malware](https://attack.mitre.org/software/S0161)
- [USBStealer (S0136) — malware](https://attack.mitre.org/software/S0136)
- [Zebrocy (S0251) — malware](https://attack.mitre.org/software/S0251)
- [reGeorg (S1187) — malware](https://attack.mitre.org/software/S1187)
- [Fysbis (S0410) — malware](https://attack.mitre.org/software/S0410)
- [LoJax (S0397) — malware](https://attack.mitre.org/software/S0397)
- [X-Agent for Android (S0314) — malware](https://attack.mitre.org/software/S0314)

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
[1] [mitre-attack](https://attack.mitre.org/groups/G0007)
[16] [Accenture SNAKEMACKEREL Nov 2018](https://www.accenture.com/t20181129T203820Z__w__/us-en/_acnmedia/PDF-90/Accenture-snakemackerel-delivers-zekapab-malware.pdf)
   Accenture Security. (2018, November 29). SNAKEMACKEREL. Retrieved April 15, 2019.
[17] [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)
   Alperovitch, D.. (2016, June 15). Bears in the Midst: Intrusion into the Democratic National Committee. Retrieved August 3, 2016.
[18] [Leonard TAG 2023](https://blog.google/threat-analysis-group/ukraine-remains-russias-biggest-cyber-focus-in-2023/)
   Billy Leonard. (2023, April 19). Ukraine remains Russia’s biggest cyber focus in 2023. Retrieved March 1, 2024.
[19] [US District Court Indictment GRU Oct 2018](https://www.justice.gov/opa/page/file/1098481/download)
   Brady, S . (2018, October 3). Indictment - United States vs Aleksei Sergeyevich Morenets, et al.. Retrieved October 1, 2020.
[20] [GRIZZLY STEPPE JAR](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)
   Department of Homeland Security and Federal Bureau of Investigation. (2016, December 29). GRIZZLY STEPPE – Russian Malicious Cyber Activity. Retrieved January 11, 2017.
[21] [ESET Zebrocy May 2019](https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/)
   ESET Research. (2019, May 22). A journey to Zebrocy land. Retrieved June 20, 2019.
[22] [ESET Sednit Part 3](http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part3.pdf)
   ESET. (2016, October). En Route with Sednit - Part 3: A Mysterious Downloader. Retrieved November 21, 2016.
[23] [Sofacy DealersChoice](https://researchcenter.paloaltonetworks.com/2018/03/unit42-sofacy-uses-dealerschoice-target-european-government-agency/)
   Falcone, R. (2018, March 15). Sofacy Uses DealersChoice to Target European Government Agency. Retrieved June 4, 2018.
[24] [FireEye APT28 January 2017](https://www.mandiant.com/sites/default/files/2021-09/APT28-Center-of-Storm-2017.pdf)
   FireEye iSIGHT Intelligence. (2017, January 11). APT28: At the Center of the Storm. Retrieved November 17, 2024.
[25] [FireEye APT28](https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf)
   FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
[26] [Ars Technica GRU indictment Jul 2018](https://arstechnica.com/information-technology/2018/07/from-bitly-to-x-agent-how-gru-hackers-targeted-the-2016-presidential-election/)
   Gallagher, S. (2018, July 27). How they did it (and will likely try again): GRU hackers vs. US elections. Retrieved September 13, 2018.
[27] [TrendMicro Pawn Storm Dec 2020](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)
   Hacquebord, F., Remorin, L. (2020, December 17). Pawn Storm’s Lack of Sophistication as a Strategy. Retrieved January 13, 2021.
[28] [Securelist Sofacy Feb 2018](https://securelist.com/a-slice-of-2017-sofacy-activity/83930/)
   Kaspersky Lab's Global Research & Analysis Team. (2018, February 20). A Slice of 2017 Sofacy Activity. Retrieved November 27, 2018.
[29] [Kaspersky Sofacy](https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/)
   Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.
[30] [Nearest Neighbor Volexity](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
   Koessel, Sean. Adair, Steven. Lancaster, Tom. (2024, November 22). The Nearest Neighbor Attack: How A Russian APT Weaponized Nearby Wi-Fi Networks for Covert Access. Retrieved February 25, 2025.
[31] [Palo Alto Sofacy 06-2018](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)
   Lee, B., Falcone, R. (2018, June 06). Sofacy Group’s Parallel Attacks. Retrieved June 18, 2018.
[32] [Talos Seduploader Oct 2017](https://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html)
   Mercer, W., et al. (2017, October 22). "Cyber Conflict" Decoy Document Used in Real Cyber Conflict. Retrieved November 2, 2018.
[33] [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide)
   Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
[34] [Microsoft STRONTIUM New Patterns Cred Harvesting Sept 2020](https://www.microsoft.com/security/blog/2020/09/10/strontium-detecting-new-patters-credential-harvesting/)
   Microsoft Threat Intelligence Center (MSTIC). (2020, September 10). STRONTIUM: Detecting new patterns in credential harvesting. Retrieved September 11, 2020.
[35] [Microsoft STRONTIUM Aug 2019](https://msrc-blog.microsoft.com/2019/08/05/corporate-iot-a-path-to-intrusion/)
   MSRC Team. (2019, August 5). Corporate IoT – a path to intrusion. Retrieved August 16, 2019.
[36] [DOJ GRU Indictment Jul 2018](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)
   Mueller, R. (2018, July 13). Indictment - United States of America vs. VIKTOR BORISOVICH NETYKSHO, et al. Retrieved November 17, 2024.
[37] [Cybersecurity Advisory GRU Brute Force Campaign July 2021](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
   NSA, CISA, FBI, NCSC. (2021, July). Russian GRU Conducting Global Brute Force Campaign to Compromise Enterprise and Cloud Environments. Retrieved July 26, 2021.
[38] [NSA/FBI Drovorub August 2020](https://media.defense.gov/2020/Aug/13/2002476465/-1/-1/0/CSA_DROVORUB_RUSSIAN_GRU_MALWARE_AUG_2020.PDF)
   NSA/FBI. (2020, August). Russian GRU 85th GTsSS Deploys Previously Undisclosed Drovorub Malware. Retrieved August 25, 2020.
[39] [SecureWorks TG-4127](https://www.secureworks.com/research/threat-group-4127-targets-hillary-clinton-presidential-campaign)
   SecureWorks Counter Threat Unit Threat Intelligence. (2016, June 16). Threat Group-4127 Targets Hillary Clinton Presidential Campaign. Retrieved August 3, 2016.
[40] [Secureworks IRON TWILIGHT Active Measures March 2017](https://www.secureworks.com/research/iron-twilight-supports-active-measures)
   Secureworks CTU. (2017, March 30). IRON TWILIGHT Supports Active Measures. Retrieved February 28, 2022.
[41] [Secureworks IRON TWILIGHT Profile](https://www.secureworks.com/research/threat-profiles/iron-twilight)
   Secureworks CTU. (n.d.). IRON TWILIGHT. Retrieved February 28, 2022.
[42] [Symantec APT28 Oct 2018](https://www.symantec.com/blogs/election-security/apt28-espionage-military-government)
   Symantec Security Response. (2018, October 04). APT28: New Espionage Operations Target Military and Government Organizations. Retrieved November 14, 2018.

