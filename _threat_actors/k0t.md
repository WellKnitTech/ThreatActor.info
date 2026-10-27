---
layout: threat_actor
title: "k0t"
aliases: ["CryptoFeel","Member19","QazWsxShop","k0t"]
description: "k0t (also CryptoFeel, Member19, QazWsxShop) is a financially motivated cybercriminal actor, first seen on 22 October 2025, behind a large-scale campaign against exposed network edge devices, according "
permalink: /k0t/
---

## Introduction
k0t (also CryptoFeel, Member19, QazWsxShop) is a financially motivated cybercriminal actor, first seen on 22 October 2025, behind a large-scale campaign against exposed network edge devices, according to a joint investigation by Group-IB and NyxLab published in October 2026. The actor finds targets by mass enumeration with FOFA and ZoomEye rather than by researching specific organizations. It gains access by exploiting known flaws such as CVE-2025-64446 (FortiWeb) and CVE-2026-0257 (PAN-OS/Prisma Access) with custom Python scripts, or by brute-forcing Fortinet FortiGate and Palo Alto GlobalProtect appliances, then connects over OpenConnect VPN. Post-exploitation relies on NetExec, Impacket, noPac, Kerbrute, PetitPotam and Mimikatz, persistence on MeshCentral, Atera, Teramind, AnyDesk and AdaptixC2, and exfiltration on Rclone to Wasabi S3 and MEGA. More than 70,000 exposed credentials are linked to the campaign, with victims mostly in Asia Pacific and Latin America; the actor states that the US and Canada are its priority. Many victims were later listed by the Qilin and The Gentlemen ransomware groups, so k0t is assessed to be an initial access broker or affiliate, but the exact relationship is unclear. The activity partially overlaps in time with the FortiBleed credential-harvesting cluster, with negligible overlap in compromised data.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CyberGate**: 
- **Cyber Eye RAT**: 
- **AnyDesk**: 
- **Xploit**: 
- **Mega**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

