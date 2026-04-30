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
*Information pending cataloguing.*

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

