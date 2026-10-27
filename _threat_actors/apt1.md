---
layout: threat_actor
title: "APT1"
aliases: ["APT 1","APT1","Brown Fox","BrownFox","Byzantine Candor","Byzantine Hades","COMMENT PANDA","Comment Crew","Comment Group","Comment Panda","G0006","GIF89a","Group 3","Operation “Oceansalt”","Operation “Seasalt”","Operation “Siesta”","PLA Unit 61398","Shady RAT","ShadyRAT","Shanghai Group","TG-8223"]
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
- **2006/2010**
- **2011-03**
- **2011/2012**
- **2014-02**
- **2018-05**
- **Breach of RSA**
- **FireEye recently looked deeper into the activity discussed in TrendMicro’s blog and dubbed the “Siesta” campaign. The tools**
- **GhostNet**
- **Hackers Plundered Israeli Defense Firms that Built ‘Iron Dome’ Missile Defense System**
- **Method: Oceansalt appears to be the first stage of an advanced persistent threat. The malware can send system data to a control server and execute commands on infected machines**
- **Method: Spear-phishing with malicious documents.**
- **Note: It is possible that this operation was not performed by the actual Comment Crew group (as they are supposedly in jail).**
- **Operation “Oceansalt”**
- **Operation “Seasalt”**
- **Operation “Siesta”**
- **Shady RAT**
- **Target: 140 US companies in the quest for sensitive corporate and intellectual property data.**
- **Target: Oceansalt appears to have been part of an operation targeting South Korea**
- **They breached security systems designed to keep out intruders by creating duplicates to “SecurID” electronic keys from EMC Corp’s EMC.N RSA security division**
- **United States**
- **and Canada in a well-focused attack. A variation of this malware has been distributed from two compromised sites in South Korea.**
- **and infrastructure used in the campaign present two possibilities: either the Chinese cyberespionage unit APT 1 is perpetrating this activity**
- **but we do not yet know its ultimate purpose.**
- **https://blog.trendmicro.com/trendlabs-security-intelligence/the-siesta-campaign-a-new-targeted-attack-awakens/**
- **https://krebsonsecurity.com/2014/07/hackers-plundered-israeli-defense-firms-that-built-iron-dome-missile-defense-system/**
- **https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/operation-oceansalt-delivers-wave-after-wave/**
- **https://www.fireeye.com/blog/threat-research/2014/03/a-detailed-examination-of-the-siesta-campaign.html**
- **https://www.mcafee.com/enterprise/en-us/assets/reports/rp-operation-oceansalt.pdf**
- **https://www.reuters.com/article/us-usa-defense-hackers/exclusive-hackers-breached-u-s-defense-contractors-idUSTRE74Q6VY20110527**
- **https://www.wired.com/story/the-full-story-of-the-stunning-rsa-hack-can-finally-be-told/**
- **modus operandi**
- **or another group is using the same tactics and tools as the legacy APT 1.**
- **said the person who was not authorized to publicly discuss the matter.**

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
- **Auriga**: 
- **BISCUIT**: 
- **Bouncer**: 
- **CALENDAR**: 
- **Cachedump**: 
- **Combos**: 
- **CookieBag**: 
- **Dairy**: 
- **GDOCUPLOAD**: 
- **GLASSES**: 
- **GLOOXMAIL**: 
- **GOGGLES**: 
- **GREENCAT**: 
- **GetMail**: 
- **Hackfase**: 
- **Helauto**: 
- **Kurton**: 
- **LIGHTBOLT**: 
- **LIGHTDART**: 
- **LONGRUN**: 
- **Living off the Land**: 
- **Lslsass**: 
- **MAPIget**: 
- **ManItsMe**: 
- **Mimikatz**: 
- **MiniASP**: 
- **NewsReels**: 
- **Oceansalt**: 
- **Pass-The-Hash Toolkit**: 
- **Poison Ivy**: 
- **ProcDump**: 
- **Seasalt**: 
- **ShadyRAT**: 
- **StarsyPound**: 
- **Sword**: 
- **TabMsgSQL**: 
- **Tarsip**: 
- **WARP**: 
- **bangat**: 
- **gsecdump**: 
- **pwdump**: 

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

