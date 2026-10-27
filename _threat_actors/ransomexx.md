---
layout: threat_actor
title: "RansomEXX"
aliases: ["Defray 2018","Defray-777","Defray777","Ransom X","RansomEXX"]
description: "We recently discovered a new file-encrypting Trojan built as an ELF executable and intended to encrypt data on machines controlled by Linux-based operating systems. After the initial analysis we notice"
permalink: /ransomexx/
---

## Introduction
We recently discovered a new file-encrypting Trojan built as an ELF executable and intended to encrypt data on machines controlled by Linux-based operating systems. After the initial analysis we noticed similarities in the code of the Trojan, the text of the ransom notes and the general approach to extortion, which suggested that we had in fact encountered a Linux build of the previously known ransomware family RansomEXX. This malware is notorious for attacking large organizations and was most active earlier this year. RansomEXX is a highly targeted Trojan. Each sample of the malware contains a hardcoded name of the victim organization. Moreover, both the encrypted file extension and the email address for contacting the extortionists make use of the victim’s name.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Applications | Jenkins | Jenkins | CVE-2024-23897 |
| Applications | SAP | NetWeaver | CVE-2025-31324 |
| Microsoft Products | Windows | CLFS | CVE-2025-29824 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Trojan.Karagany**: 
- **Trojan.Mebromi**: 

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | LaZagne, Mimikatz, ProcDump |
| LOLBAS | BCDEdit, Windows Event Utility (wevtutil) |
| OffSec | Cobalt Strike |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

