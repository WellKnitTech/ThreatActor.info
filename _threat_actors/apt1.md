---
layout: threat_actor
title: "APT1"
aliases: ["APT1","Brown Fox","Byzantine Candor","Comment Crew","Comment Group","Comment Panda","COMMENT PANDA","G0006","GIF89a","Group 3","PLA Unit 61398","ShadyRAT","Shanghai Group","TG-8223"]
description: "APT1 is a Chinese cyber espionage group that has been conducting cyber espionage against a broad range of victims."
permalink: /apt1/
---

## Introduction
APT1 is a Chinese cyber espionage group that has been conducting cyber espionage against a broad range of victims.

## Activities and Tactics
**Targeted Sectors**: Government, Defense, Technology, Private sector

**Country of Origin**: 🇨🇳 China

**Risk Level**: High

**First Seen**: 2006

**Last Activity**: 2023

**Incident Type**: Espionage

**Suspected Victims**: United States, Taiwan, Israel, Norway, United Arab Emirates, United Kingdom, Singapore, India, Belgium, South Africa...

## Notable Campaigns
- **Shady RAT**
- **GhostNet**

## Tactics, Techniques, and Procedures (TTPs)
- [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001)
- [T1119 Automated Collection](https://attack.mitre.org/techniques/T1119)
- [T1114.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)
- [T1114.001 Local Email Collection](https://attack.mitre.org/techniques/T1114/001)
- [T1588.001 Malware](https://attack.mitre.org/techniques/T1588/001)
- [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)
- [T1585.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002)
- [T1584.001 Domains](https://attack.mitre.org/techniques/T1584/001)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1087.001 Local Account](https://attack.mitre.org/techniques/T1087/001)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1135 Network Share Discovery](https://attack.mitre.org/techniques/T1135)
- [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1007 System Service Discovery](https://attack.mitre.org/techniques/T1007)
- [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)

### ATT&CK technique IDs (denormalized)

- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1005](https://attack.mitre.org/techniques/T1005/)
- [T1007](https://attack.mitre.org/techniques/T1007/)
- [T1016](https://attack.mitre.org/techniques/T1016/)
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1049](https://attack.mitre.org/techniques/T1049/)
- [T1057](https://attack.mitre.org/techniques/T1057/)
- [T1059.003](https://attack.mitre.org/techniques/T1059/003/)
- [T1087.001](https://attack.mitre.org/techniques/T1087/001/)
- [T1114.001](https://attack.mitre.org/techniques/T1114/001/)
- [T1114.002](https://attack.mitre.org/techniques/T1114/002/)
- [T1119](https://attack.mitre.org/techniques/T1119/)
- [T1135](https://attack.mitre.org/techniques/T1135/)
- [T1550.002](https://attack.mitre.org/techniques/T1550/002/)
- [T1560.001](https://attack.mitre.org/techniques/T1560/001/)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [T1584.001](https://attack.mitre.org/techniques/T1584/001/)
- [T1585.002](https://attack.mitre.org/techniques/T1585/002/)
- [T1588.001](https://attack.mitre.org/techniques/T1588/001/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 2 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **Hacking Team UEFI Rootkit**
- **WEBC2**: 
- **BISCUIT and many others**: 

### MITRE ATT&CK Software
- [Seasalt (S0345) — malware](https://attack.mitre.org/software/S0345)
- [ipconfig (S0100) — tool](https://attack.mitre.org/software/S0100)
- [BISCUIT (S0017) — malware](https://attack.mitre.org/software/S0017)
- [Cachedump (S0119) — tool](https://attack.mitre.org/software/S0119)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)
- [GLOOXMAIL (S0026) — malware](https://attack.mitre.org/software/S0026)
- [Lslsass (S0121) — tool](https://attack.mitre.org/software/S0121)
- [PoisonIvy (S0012) — malware](https://attack.mitre.org/software/S0012)
- [WEBC2 (S0109) — malware](https://attack.mitre.org/software/S0109)
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [gsecdump (S0008) — tool](https://attack.mitre.org/software/S0008)
- [Pass-The-Hash Toolkit (S0122) — tool](https://attack.mitre.org/software/S0122)
- [CALENDAR (S0025) — malware](https://attack.mitre.org/software/S0025)
- [Tasklist (S0057) — tool](https://attack.mitre.org/software/S0057)
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [xCmd (S0123) — tool](https://attack.mitre.org/software/S0123)
- [pwdump (S0006) — tool](https://attack.mitre.org/software/S0006)

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G0006)
[6] [Mandiant APT1](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)
   Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
[7] [CrowdStrike Putter Panda](http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf)
   Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.

