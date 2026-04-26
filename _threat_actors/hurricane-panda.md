---
layout: threat_actor
title: "HURRICANE PANDA"
aliases: ["HURRICANE PANDA"]
description: "We have investigated their intrusions since 2013 and have been battling them nonstop over the last year at several large telecommunications and technology companies. The determination of this China-bas"
permalink: /hurricane-panda/
country: "China"
risk_level: "High"
country_flag: "🇨🇳"
sector_focus: ["Technology", "Telecoms"]
---

## Introduction
We have investigated their intrusions since 2013 and have been battling them nonstop over the last year at several large telecommunications and technology companies. The determination of this China-based adversary is truly impressive: they are like a dog with a bone.
HURRICANE PANDA's preferred initial vector of compromise and persistence is a China Chopper webshell – a tiny and easily obfuscated 70 byte text file that consists of an ‘eval()’ command, which is then used to provide full command execution and file upload/download capabilities to the attackers. This script is typically uploaded to a web server via a SQL injection or WebDAV vulnerability, which is often trivial to uncover in a company with a large external web presence.
Once inside, the adversary immediately moves on to execution of a credential theft tool such as Mimikatz (repacked to avoid AV detection). If they are lucky to have caught an administrator who might be logged into that web server at the time, they will have gained domain administrator credentials and can now roam your network at will via ‘net use’ and ‘wmic’ commands executed through the webshell terminal.

## Activities and Tactics
**Targeted Sectors**: Technology, Telecoms
**Country of Origin**: 🇨🇳 China
**Risk Level**: High

### Notable Campaigns
*Information pending cataloguing.*

### Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*This section is pending cataloguing. Check upstream sources for current IOCs.*

### IP Addresses
*Pending*

### File Hashes
*Pending*

### Domains
*Pending*

## Malware and Tools
*Information pending cataloguing.*

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

