---
layout: threat_actor
title: "REvil"
aliases: ["Sodinokibi", "Sodin", "Water Mare", "GrandCrab", "Revil"]
description: "REvil is a Russian ransomware-as-a-service operation that has targeted major corporations worldwide."
permalink: /revil/
---

## Introduction
REvil is a Russian ransomware-as-a-service operation that has targeted major corporations worldwide.

## Activities and Tactics
**Targeted Sectors**: Technology, Healthcare, Legal

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: Critical

**First Seen**: 2019

**Last Activity**: 2021


## Notable Campaigns
- [Kaseya](https://helpdesk.kaseya.com/hc/en-gb/articles/4403584098961-Incident-Overview-Technical-Details) (July 2021; REvil (Ransomware))

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Virtualization | Citrix | NetScaler ADC & Gateway & SD-WAN | CVE-2019-19781 |
| Network Edge | Fortinet | FortiOS | CVE-2018-13379 |
| Applications | Kaseya | VSA | CVE-2021-30116 |
| Applications | Oracle | WebLogic | CVE-2019-2725 |
| Network Edge | Pulse Secure / Ivanti | Pulse Connect Secure | CVE-2019-11510 |
| Network Edge | Pulse Secure / Ivanti | Pulse Connect Secure & Pulse Policy Secure | CVE-2019-11539 |
| Microsoft Products | Windows | Win32k | CVE-2018-8453 |

## Notable Indicators of Compromise (IOCs)
*No separately curated network indicators or file hashes are listed for this actor. Known exploited vulnerabilities appear in the **CISA Known Exploited Vulnerabilities (KEV)** section below.*

## Malware and Tools
- **Sodinokibi**: 
- **IcedID**: 
- **Qakbot**: 
- **PsExec**: 
- **FileZilla**: 

### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Discovery | AdFind, Bloodhound |
| Exfiltration | PrivatLab, RClone, Sendspace |
| LOLBAS | BITSAdmin |
| OffSec | Cobalt Strike |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

## CISA Known Exploited Vulnerabilities (KEV)
*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*

| CVE ID | Vendor | Product | Date Added |
|-------|-------|--------|----------|
| CVE-2018-8453 | Microsoft | Win32k | 2022-01-21 |
| CVE-2019-2725 | Oracle | WebLogic Server | 2022-01-10 |
| CVE-2021-30116 | Kaseya | Virtual System/Server Administrator (VSA) | 2021-11-03 |
| CVE-2019-11539 | Ivanti | Pulse Connect Secure and Pulse Policy Secure | 2021-11-03 |

