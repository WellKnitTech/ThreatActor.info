---
layout: threat_actor
title: "Hunt"
aliases: ["Hunt-Dharma-Crysis","Hunt"]
description: "Hunt ransomware is a variant of the Dharma/CrySIS ransomware family. This variant creates a unique ID for each victim, appends the extension '.hunt' to encrypted files, and leaves a ransom note known a"
permalink: /hunt/
---

## Introduction
Hunt ransomware is a variant of the Dharma/CrySIS ransomware family. This variant creates a unique ID for each victim, appends the extension '.hunt' to encrypted files, and leaves a ransom note known as info-hunt.txt. The Dharma/CrySIS ransomware family emerged around mid-2016 as a Ransomware-as-a-Service (RaaS) program, utilizing various initial intrusion methods such as phishing, disguising as legitimate software, and exploiting open RDP connections. This variant uses AES-256 encryption (CBC mode) or DES+RSA and demands payment to recover files. Upon execution, the ransomware generates a 256-bit AES decryption key, which is then encrypted along with random bytes using the RSA-1024 algorithm and stored at the end of the encrypted file. The ransomware is written in C/C++ and compiled using MS Visual Studio. Regarding geographic attribution, it has been identified in use by threat actors from Russia, Ukraine, India, and other countries.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Xploit**: 
- **GraphicBooting**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [Sentinels League 2026: Live Rankings for the Threat Hunting World Championship](https://www.sentinelone.com/blog/sentinels-league-2026-live-rankings-for-the-threat-hunting-world-championship/)
  SentinelOne - 2026-05-20T

