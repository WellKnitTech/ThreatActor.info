---
layout: threat_actor
title: "babylockerkz"
aliases: ["babylockerkz"]
description: "BabyLockerKZ is a variant of MedusaLocker ransomware, first observed in late 2023. It operates under a double‑extortion model, combining file encryption with data exfiltration and extortion. Technicall"
permalink: /babylockerkz/
---

## Introduction
BabyLockerKZ is a variant of MedusaLocker ransomware, first observed in late 2023. It operates under a double‑extortion model, combining file encryption with data exfiltration and extortion. Technically, it reuses MedusaLocker’s AES + RSA‑2048 hybrid encryption, appends the .hazard file extension to encrypted files, and includes a unique autorun registry key (“BabyLockerKZ”) alongside dedicated public/private key data inserted into registry values. Initial access is achieved through opportunistic methods like RDP compromises, with lateral movement facilitated by compromised credentials and tools such as Mimikatz. The variant employs a custom toolkit codenamed paid_memes, which includes tools like "Checker" for scanning credentials, facilitating automation, and bridging toolsets for further exploitation. Starting late 2022, its operators have compromised over 100 organizations per month, initially targeting European victims before shifting toward Latin America in 2023.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Babylon**: 
- **Xploit**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

