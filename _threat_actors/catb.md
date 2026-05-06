---
layout: threat_actor
title: "catb"
aliases: ["catb"]
description: "CatB ransomware was first observed in late 2022, gaining attention for abusing DLL hijacking via the Microsoft Distributed Transaction Coordinator (MSDTC) service—loading a malicious payload through DL"
permalink: /catb/
---

## Introduction
CatB ransomware was first observed in late 2022, gaining attention for abusing DLL hijacking via the Microsoft Distributed Transaction Coordinator (MSDTC) service—loading a malicious payload through DLL sideloading methods. The malware arrives in a two-stage dropper: the first DLL unpacks and launches the main payload (commonly named oci.dll), which subsequently encrypts files using hybrid RSA/AES cryptography. Unlike conventional ransomware, CatB does not rename files or distribute typical ransom notes; instead, it prepends the ransom message directly to the start of each encrypted file, making detection more difficult. Victims are instructed to contact the attackers via email (e.g., catB9991@protonmail.com or fishA001@protonmail.com), with the ransom demand escalating daily. Initial analysis suggests CatB may be a rebrand or evolution of Pandora ransomware, sharing various code artifacts and operational behavior.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Pandora**: 
- **GraphicBooting**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

