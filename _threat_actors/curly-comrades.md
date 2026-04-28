---
layout: threat_actor
title: "Curly COMrades"
aliases: ["Curly COMrades"]
description: "Curly COMrades is a threat actor identified by Amazon Threat Intelligence and Bitdefender, believed to operate in support of Russian interests. They employ techniques such as Hyper-V abuse for EDR evas"
permalink: /curly-comrades/
---

## Introduction
Curly COMrades is a threat actor identified by Amazon Threat Intelligence and Bitdefender, believed to operate in support of Russian interests. They employ techniques such as Hyper-V abuse for EDR evasion and utilize proxy tools like Resocks, SSH, and Stunnel to gain access to internal networks. Their activities include repeated attempts to extract the NTDS database from domain controllers and establishing covert access through virtualization features on compromised Windows 10 machines.

## Activities and Tactics
**Country of Origin**: 🇷🇺 Russia





## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **ComRAT**
- **Windows Remote Desktop**

### Russian APT Tool Matrix observations
| Category | Observed tools |
|---|---|
| Credential Theft | Mimikatz, ProcDump, TrickDump |
| Defense Evasion | Garble |
| LOLBAS | DCSync, curl |
| Networking | Resocks, SOCKS5, stunnel |
| OffSec | Impacket |
| RMM Tools | RemoteUtilities |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

