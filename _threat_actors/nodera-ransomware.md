---
layout: threat_actor
title: "Nodera Ransomware"
aliases: ["Nodera","Nodera Ransomware"]
description: "Nodera is a ransomware family that uses the Node.js framework and was discovered by Quick Heal researchers. The infection chain starts with a VBS script embedded with multiple JavaScript files. Upon ex"
permalink: /nodera-ransomware/
---

## Introduction
Nodera is a ransomware family that uses the Node.js framework and was discovered by Quick Heal researchers. The infection chain starts with a VBS script embedded with multiple JavaScript files. Upon execution, a directory is created and both the main node.exe program and several required NodeJS files are downloaded into the directory. Additionally, a malicious JavaScript payload that performs the encryption process is saved in this directory. After checking that it has admin privileges and setting applicable variables, the malicious JavaScript file enumerates the drives to create a list of targets. Processes associated with common user file types are stopped and volume shadow copies are deleted. Finally, all user-specific files on the C: drive and all files on other drives are encrypted and are appended with a .encrypted extension. The ransom note containing instructions on paying the Bitcoin ransom are provided along with a batch script to be used for decryption after obtaining the private key. Some mistakes in the ransom note identified by the researchers include the fact that it mentions a 2048-bit RSA public key instead of 4096-bit (the size that was actually used), a hard-coded private key destruction time dating back almost 2 years ago, and a lack of instructions for how the private key will be obtained after the ransom is paid. These are signs that the ransomware may be in the development phase and was likely written by an amateur. For more information, see the QuickHeal blog post in the Reference section below.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Back Orifice**: 
- **Back Orifice 2000**: 
- **Batch NET**: 
- **Archelaus Beta**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

