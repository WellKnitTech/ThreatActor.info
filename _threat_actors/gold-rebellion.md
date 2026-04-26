---
layout: threat_actor
title: "GOLD REBELLION"
aliases: ["WANDERING SPIDER", "White Dev 115", "Dark Scorpius", "GOLD REBELLION"]
description: "GOLD REBELLION is a financially motivated cybercriminal threat group that operates the Black Basta name-and-shame ransomware. The group posted its first victim to its leak site in April 2022 and has co"
permalink: /gold-rebellion
---

## Introduction
GOLD REBELLION is a financially motivated cybercriminal threat group that operates the Black Basta name-and-shame ransomware. The group posted its first victim to its leak site in April 2022 and has continued to publish victim names at a rate of around 15 a month since then. GOLD REBELLION has not openly advertised or appeared to recruit for an affiliate program but the variety of tactics, techniques and procedures (TTP) observed in Black Basta intrusions suggests that multiple individuals are engaged in the ransomware scheme.Several security vendors and independent researchers have suggested the distributors of Black Basta may be former affiliates of GOLD ULRICK's Conti operation. Technical artifacts analyzed by CTU researchers suggest that Black Basta has been under development since at least early February 2022, several weeks before extensive public leaks detailed GOLD ULRICK's Conti operation. In November 2022, researchers at SentinelOne linked custom tooling used by GOLD REBELLION to the GOLD NIAGARA (FIN7) threat group. CTU researchers have not made independent observations corroborating a relationship between these threat groups or any others.GOLD REBELLION appear to have been a key customer of GOLD LAGOON's Qakbot: CTU researchers observed multiple incidents where Black Basta was distributed through it as an initial access vector (IAV), leading to Cobalt Strike and further lateral movement into the victim network. Following the takedown of Qakbot in August 2023, GOLD REBELLION explored new methods of delivery, including DarkGate and Pikabot. In one incident, CTU researchers observed a threat actor gain access to a victim network through a managed security services provider (MSSP). In October 2024, GOLD REBELLION likely exploited a vulnerability in a Sonic Wall VPN device for access. Also in 2024, CTU researchers observed multiple instances of the group using social engineering to convince victims to download remote management and monitoring tools like AnyDesk and Quick Assist. After spamming inboxes with multiple emails, the threat actors approached the affected users via Teams, purporting to be IT Support or Help Desk employees offering assistance with email inbox issues.Other tools members of the group have used include the SystemBC back connect malware, PsExec for remote execution, RDP for lateral movement, batch files to delete their own tools and disable anti-virus programs for defense evasion, and both Rclone and MegaSync for data exfiltration.

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
*Information pending cataloguing.*

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*
