---
layout: threat_actor
title: "freeworld"
aliases: ["freeworld"]
description: "FreeWorld is a ransomware variant first observed in September 2023, and is believed to be derived from the Mimic ransomware family. It is deployed through coordinated campaigns dubbed DB#JAMMER, which "
permalink: /freeworld/
---

## Introduction
FreeWorld is a ransomware variant first observed in September 2023, and is believed to be derived from the Mimic ransomware family. It is deployed through coordinated campaigns dubbed DB#JAMMER, which exploit poorly secured Microsoft SQL (MSSQL) servers exposed to the internet. Attackers gain initial access via brute force, leverage the xp_cmdshell feature to execute shell commands, disable defenses, deploy remote access tools like Cobalt Strike and AnyDesk, and eventually deliver the FreeWorld payload. The ransomware encrypts files using hybrid encryption and appends the .FreeWorldEncryption extension. Victims receive a ransom note titled FreeWorld-Contact.txt, directing them on payment and data recovery steps.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **RemoteCMD**: 
- **Remote Utilities**: 
- **RemotePC**: 
- **AnyDesk**: 
- **Xploit**: 
- **Cobalt Strike**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

