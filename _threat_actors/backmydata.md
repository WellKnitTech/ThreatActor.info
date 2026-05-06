---
layout: threat_actor
title: "backmydata"
aliases: ["backmydata"]
description: "BackMyData is a variant of the Phobos ransomware family, first observed in early 2024. It follows a double‑extortion model: encrypting files and threatening data exposure. The ransomware primarily targ"
permalink: /backmydata/
---

## Introduction
BackMyData is a variant of the Phobos ransomware family, first observed in early 2024. It follows a double‑extortion model: encrypting files and threatening data exposure. The ransomware primarily targets organizations via weak or misconfigured RDP access (e.g., remote desktop services), though phishing and initial-stage payloads like SmokeLoader have also been noted. Technical behavior includes AES‑256 file encryption, with keys secured via a public RSA‑2048 key embedded in the binary. Post-infection actions involve disabling firewalls, deleting volume shadow copies, inhibiting recovery functionality, and establishing persistence through registry Run keys and startup folder entries. Encrypted files receive the extension .BACKMYDATA, and victims are left with ransom notes (info.txt, info.hta, or .backmydata) that instruct them to contact attackers via email or Session Messenger. A significant incident involved a coordinated attack on Romania’s Hipocrate Information System (HIS), impacting 26 hospitals and causing widespread system outages across nearly 100 facilities, with ransom demands of approximately 3.5 BTC (~$175,000).

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Smoke Loader**: 
- **RemoteCMD**: 
- **Remote Utilities**: 
- **RemotePC**: 
- **DesktopNow**: 
- **CrossRat**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

