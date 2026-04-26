---
layout: threat_actor
title: "FIN7"
aliases: ["Carbanak", "Navigator Group"]
description: "FIN7 is a financially motivated cybercrime group known for targeting point-of-sale systems and retail."
permalink: /fin7/
country: "Unknown"
sector_focus: ["Retail", "Hospitality", "Financial"]
first_seen: "2015"
last_activity: "2024"
risk_level: "High"
---

## Introduction
FIN7, also known as Carbanak or Navigator Group, is a financially motivated cybercrime group that has been active since at least 2015. The group is known for targeting point-of-sale (POS) systems, retail organizations, and financial institutions to steal payment card data and conduct financial fraud.

## Activities and Tactics
FIN7 employs sophisticated cybercrime tactics with a focus on financial gain. The group is known for its use of custom malware, social engineering, and persistence techniques to maintain access to compromised networks.

## Notable Campaigns
1. **Point-of-Sale Attacks**: Systematic targeting of POS systems in retail and hospitality
2. **Payment Card Theft**: Large-scale theft of payment card data
3. **Financial Institution Targeting**: Attacks on banks and financial services
4. **Restaurant Chain Attacks**: Targeting of restaurant chains and food service companies
5. **Hotel Chain Attacks**: Targeting of hotel chains and hospitality companies

## Tactics, Techniques, and Procedures (TTPs)
FIN7 is known for the following TTPs:
- **Spear Phishing**: Use of targeted email campaigns with malicious attachments
- **Custom Malware**: Development of sophisticated malware families
- **Living off the Land**: Use of legitimate tools and techniques
- **Persistence**: Long-term access maintenance through multiple techniques
- **Data Exfiltration**: Systematic theft of payment card data
- **Financial Fraud**: Use of stolen data for financial gain

## Notable Indicators of Compromise (IOCs)
Public reporting on FIN7 includes changing infrastructure and malware artifacts, but this repository does not yet maintain a vetted IOC set specific to this actor. This section is intentionally conservative until it can be refreshed with actor-specific indicators and provenance.

## Emulating TTPs with Atomic Red Team
To emulate FIN7's TTPs, you can use Atomic Red Team's tests:
- **Spear Phishing**: [T1566.001 - Phishing: Spearphishing Attachment](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Custom Malware**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md)
- **Persistence**: [T1053.005 - Scheduled Task/Job: Scheduled Task](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053/T1053.md)
- **Data Exfiltration**: [T1041 - Exfiltration Over C2 Channel](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md)

## Malware and Tools
FIN7 uses a range of custom malware and tools, including:
- **Carbanak**: Custom backdoor used for data exfiltration
- **Cobalt Strike**: Commercial penetration testing tool
- **Mimikatz**: Credential dumping tool
- **PsExec**: Legitimate tool for remote execution
- **Custom Backdoors**: Various custom-developed backdoors

## Attribution and Evidence
Cybersecurity researchers have attributed FIN7's activities to financially motivated cybercriminals based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific financial interests.

## References
1. **CrowdStrike FIN7 Report**: [Link to report](https://www.crowdstrike.com/blog/who-is-fin7/)
2. **CISA Alert on FIN7**: [Link to alert](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)

## External Links
- [Wikipedia on FIN7](https://en.wikipedia.org/wiki/FIN7)
- [MITRE ATT&CK - FIN7](https://attack.mitre.org/groups/G0046/)
