---
layout: threat_actor
title: "Team46"
aliases: ["TaxOff", "Team46"]
description: "Team46 is a sophisticated APT group active since at least late 2024, targeting Russian government, academic, and media organizations through spearphishing emails disguised as forum invitations or servi"
permalink: /team46/
---

## Introduction
Team46 is a sophisticated APT group active since at least late 2024, targeting Russian government, academic, and media organizations through spearphishing emails disguised as forum invitations or service notifications. They exploit zero-day vulnerabilities like CVE-2025-2783 in Google Chrome (March 2025, Operation ForumTroll) and CVE-2024-6473 in Yandex Browser, deploying multi-stage loaders (e.g., winsta.dll, donut shellcode) that decrypt payloads using machine-specific keys like firmware UUID for environmental guardrails. Key malware includes the Trinper backdoor for keylogging, clipboard theft, file/process discovery, and encrypted C2 exfiltration over HTTPS with domain fronting, alongside auxiliary .NET tools (dirlist.exe, ProcessList.exe) and variants using Cobalt Strike or Dante backdoor; the group employs obfuscation, AMSI bypasses, debugger evasion, and self-deletion for persistence and stealth. Positive Technologies attributes TaxOff operations to Team46 based on identical PowerShell patterns, loaders, and hyphenated CDN-mimicking infrastructure (e.g., ms-appdata-*.global.ssl.fastly.net).

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
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
- **Backdoor.Oldrea**: 
- **PowerDuke**: 
- **POWERSTATS**: 
- **Power Loader**: 
- **POWERSOURCE**: 
- **Chrome Remote Desktop**: 
- **Xploit**: 
- **Cobalt Strike**: 
- **PowerRAT**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

