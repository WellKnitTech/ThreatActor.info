---
layout: threat_actor
title: "PowerPool"
aliases: ["IAmTheKing", "PowerPool"]
description: "Malware developers have started to use the zero-day exploit for Task Scheduler component in Windows, two days after proof-of-concept code for the vulnerability appeared online.  A security researcher w"
permalink: /powerpool/
---

## Introduction
Malware developers have started to use the zero-day exploit for Task Scheduler component in Windows, two days after proof-of-concept code for the vulnerability appeared online.

A security researcher who uses the online name SandboxEscaper on August 27 released the source code for exploiting a security bug in the Advanced Local Procedure Call (ALPC) interface used by Windows Task Scheduler.

More specifically, the problem is with the SchRpcSetSecurity API function, which fails to properly check user's permissions, allowing write privileges on files in C:\Windows\Task.

The vulnerability affects Windows versions 7 through 10 and can be used by an attacker to escalate their privileges to all-access SYSTEM account level.

A couple of days after the exploit code became available (source and binary), malware researchers at ESET noticed its use in active malicious campaigns from a threat actor they call PowerPool, because of their tendency to use tools mostly written in PowerShell for lateral movement.

The group appears to have a small number of victims in the following countries: Chile, Germany, India, the Philippines, Poland, Russia, the United Kingdom, the United States, and Ukraine.

The researchers say that PowerPool developers did not use the binary version of the exploit, deciding instead to make some subtle changes to the source code before recompiling it.

## Activities and Tactics
*Information pending cataloguing.*

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
- **PowerDuke**: 
- **POWERSTATS**: 
- **Power Loader**: 
- **POWERSOURCE**: 
- **Small-Net**: 
- **Windows Remote Desktop**: 
- **UNITEDRAKE**: 
- **Xploit**: 
- **Archelaus Beta**: 
- **PowerRAT**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

