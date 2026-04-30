---
layout: threat_actor
title: "APT29"
aliases: ["APT29", "Blue Kitsune", "Cozy Bear", "CozyDuke", "Dark Halo", "IRON HEMLOCK", "IRON RITUAL", "Midnight Blizzard", "NOBELIUM", "NobleBaron", "SolarStorm", "The Dukes", "UNC2452", "UNC3524", "YTTRIUM", "Group 100", "COZY BEAR", "Minidionis", "SeaDuke", "Grizzly Steppe", "G0016", "ATK7", "Cloaked Ursa", "TA421", "ITG11", "BlueBravo", "Nobelium", "UAC-0029", "Dukes", "Cozy Duke", "EuroAPT", "CozyCar", "Cozer", "Office Monkeys / TEMP.Monkeys", "Hammer Toss", "Fritillary", "Yttrium", "StellarParticle", "Cranefly"]
description: "APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR). [White House Imposing Costs RU Gov April 2021](https://www.whitehouse.gov/briefing-room/statements-release"
permalink: /apt29/
---

## Introduction
APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR). [White House Imposing Costs RU Gov April 2021](https://www.whitehouse.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/) [UK Gov Malign RIS Activity April 2021](https://www.gov.uk/government/news/russia-uk-and-us-expose-global-campaigns-of-malign-activity-by-russian-intelligence-services) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. APT29 reportedly compromised the Democratic National Committee starting in the summer of 2015. [F-Secure The Dukes](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf) [GRIZZLY STEPPE JAR](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf) [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) [UK Gov UK Exposes Russia SolarWinds April 2021](https://www.gov.uk/government/news/russia-uk-exposes-russian-involvement-in-solarwinds-cyber-compromise) In April 2021, the US and UK governments attributed the SolarWinds Compromise to the SVR; public statements included citations to APT29, Cozy Bear, and The Dukes. [NSA Joint Advisory SVR SolarWinds April 2021](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF) [UK NSCS Russia SolarWinds April 2021](https://www.ncsc.gov.uk/news/uk-and-us-call-out-russia-for-solarwinds-compromise) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm. [FireEye SUNBURST Backdoor December 2020](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html) [MSTIC NOBELIUM Mar 2021](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/) [CrowdStrike SUNSPOT Implant January 2021](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/) [Volexity SolarWinds](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/) [Cybersecurity Advisory SVR TTP May 2021](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf) [Unit 42 SolarStorm December 2020](https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/)

## Activities and Tactics
**Targeted Sectors**: Government, Healthcare, Energy

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: High

**First Seen**: 2008

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: United States, China, New Zealand, Ukraine, Romania, Georgia, Japan, South Korea, Belgium, Kazakhstan...

## Notable Campaigns
- [Microsoft](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/) (January 2024; CozyBear (RU APT))
- [Microsoft](https://msrc.microsoft.com/blog/2021/02/microsoft-internal-solorigate-investigation-final-update/) (February 2021; CozyBear (RU APT))
- [FireEye](https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html) (December 2020; CozyBear (RU APT))
- [SolarWinds](https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/) (December 2020; CozyBear (RU APT))

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0016 (YAML `ttps` empty).*

- [T1001.002 Steganography](/techniques/T1001.002/)
- [T1003.006 DCSync](/techniques/T1003.006/)
- [T1005 Data from Local System](/techniques/T1005/)
- [T1016.001 Internet Connection Discovery](/techniques/T1016.001/)
- [T1018 Remote System Discovery](/techniques/T1018/)
- [T1021.001 Remote Desktop Protocol](/techniques/T1021.001/)
- [T1021.002 SMB/Windows Admin Shares](/techniques/T1021.002/)
- [T1021.006 Windows Remote Management](/techniques/T1021.006/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1027.001 Binary Padding](/techniques/T1027.001/)
- [T1027.002 Software Packing](/techniques/T1027.002/)
- [T1027.006 HTML Smuggling](/techniques/T1027.006/)
- [T1036 Masquerading](/techniques/T1036/)
- [T1036.004 Masquerade Task or Service](/techniques/T1036.004/)
- [T1036.005 Match Legitimate Resource Name or Location](/techniques/T1036.005/)
- [T1043](https://attack.mitre.org/techniques/T1043/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/techniques/T1048.002/)
- [T1053.005 Scheduled Task](/techniques/T1053.005/)
- [T1057 Process Discovery](/techniques/T1057/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1059.005 Visual Basic](/techniques/T1059.005/)
- [T1059.006 Python](/techniques/T1059.006/)
- [T1068 Exploitation for Privilege Escalation](/techniques/T1068/)
- [T1069 Permission Groups Discovery](/techniques/T1069/)
- [T1069.002 Domain Groups](/techniques/T1069.002/)
- [T1070 Indicator Removal](/techniques/T1070/)
- [T1070.004 File Deletion](/techniques/T1070.004/)
- [T1070.006 Timestomp](/techniques/T1070.006/)
- [T1071.001 Web Protocols](/techniques/T1071.001/)
- [T1074.002 Remote Data Staging](/techniques/T1074.002/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1078.002 Domain Accounts](/techniques/T1078.002/)
- [T1078.003 Local Accounts](/techniques/T1078.003/)
- [T1078.004 Cloud Accounts](/techniques/T1078.004/)
- [T1082 System Information Discovery](/techniques/T1082/)
- [T1083 File and Directory Discovery](/techniques/T1083/)
- [T1087 Account Discovery](/techniques/T1087/)
- [T1087.002 Domain Account](/techniques/T1087.002/)
- [T1087.004 Cloud Account](/techniques/T1087.004/)
- [T1090.001 Internal Proxy](/techniques/T1090.001/)
- [T1090.003 Multi-hop Proxy](/techniques/T1090.003/)
- [T1090.004 Domain Fronting](/techniques/T1090.004/)
- [T1095 Non-Application Layer Protocol](/techniques/T1095/)
- [T1098.001 Additional Cloud Credentials](/techniques/T1098.001/)
- [T1098.002 Additional Email Delegate Permissions](/techniques/T1098.002/)
- [T1098.003 Additional Cloud Roles](/techniques/T1098.003/)
- [T1098.005 Device Registration](/techniques/T1098.005/)
- [T1102.002 Bidirectional Communication](/techniques/T1102.002/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1110.003 Password Spraying](/techniques/T1110.003/)
- [T1114.002 Remote Email Collection](/techniques/T1114.002/)
- [T1133 External Remote Services](/techniques/T1133/)
- [T1136.003 Cloud Account](/techniques/T1136.003/)
- [T1140 Deobfuscate/Decode Files or Information](/techniques/T1140/)
- [T1190 Exploit Public-Facing Application](/techniques/T1190/)
- [T1195.002 Compromise Software Supply Chain](/techniques/T1195.002/)
- [T1199 Trusted Relationship](/techniques/T1199/)
- [T1203 Exploitation for Client Execution](/techniques/T1203/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1213 Data from Information Repositories](/techniques/T1213/)
- [T1213.003 Code Repositories](/techniques/T1213.003/)
- [T1218.005 Mshta](/techniques/T1218.005/)
- [T1218.011 Rundll32](/techniques/T1218.011/)
- [T1482 Domain Trust Discovery](/techniques/T1482/)
- [T1484.002 Trust Modification](/techniques/T1484.002/)
- [T1505.003 Web Shell](/techniques/T1505.003/)
- [T1539 Steal Web Session Cookie](/techniques/T1539/)
- [T1546.003 Windows Management Instrumentation Event Subscription](/techniques/T1546.003/)
- [T1546.008 Accessibility Features](/techniques/T1546.008/)
- [T1547.001 Registry Run Keys / Startup Folder](/techniques/T1547.001/)
- [T1547.009 Shortcut Modification](/techniques/T1547.009/)
- [T1548.002 Bypass User Account Control](/techniques/T1548.002/)
- [T1550 Use Alternate Authentication Material](/techniques/T1550/)
- [T1550.001 Application Access Token](/techniques/T1550.001/)
- [T1550.003 Pass the Ticket](/techniques/T1550.003/)
- [T1550.004 Web Session Cookie](/techniques/T1550.004/)
- [T1552.004 Private Keys](/techniques/T1552.004/)
- [T1553.002 Code Signing](/techniques/T1553.002/)
- [T1553.005 Mark-of-the-Web Bypass](/techniques/T1553.005/)
- [T1555 Credentials from Password Stores](/techniques/T1555/)
- [T1555.003 Credentials from Web Browsers](/techniques/T1555.003/)
- [T1558.003 Kerberoasting](/techniques/T1558.003/)
- [T1560.001 Archive via Utility](/techniques/T1560.001/)
- [T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [T1562.002](https://attack.mitre.org/techniques/T1562/002/)
- [T1562.004](https://attack.mitre.org/techniques/T1562/004/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1566.003 Spearphishing via Service](/techniques/T1566.003/)
- [T1568 Dynamic Resolution](/techniques/T1568/)
- [T1573 Encrypted Channel](/techniques/T1573/)
- [T1583.001 Domains](/techniques/T1583.001/)
- [T1583.006 Web Services](/techniques/T1583.006/)
- [T1584.001 Domains](/techniques/T1584.001/)
- [T1586.002 Email Accounts](/techniques/T1586.002/)
- [T1587.001 Malware](/techniques/T1587.001/)
- [T1587.003 Digital Certificates](/techniques/T1587.003/)
- [T1588.002 Tool](/techniques/T1588.002/)
- [T1589.001 Credentials](/techniques/T1589.001/)
- [T1595.002 Vulnerability Scanning](/techniques/T1595.002/)
- [T1606.001 Web Cookies](/techniques/T1606.001/)
- [T1606.002 SAML Tokens](/techniques/T1606.002/)
- [T1621 Multi-Factor Authentication Request Generation](/techniques/T1621/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **CosmicDuke**
- **PinchDuke**
- **CloudDuke**
- **HAMMERTOSS**
- **GeminiDuke**
- **MiniDuke**
- **SeaDuke**
- **RTM**
- **OnionDuke**
- **CyberGate**
- **Hammertoss**: 
- **OnionDuke**: 
- **CosmicDuke**: 
- **MiniDuke**: 
- **CozyDuke**: 
- **SeaDuke**: 
- **SeaDaddy implant developed in Python and compiled with py2exe**: 
- **AdobeARM**: 
- **ATI-Agent**: 
- **MiniDionis**: 
- **Grizzly Steppe**: 
- **Vernaldrop**: 
- **Tadpole**: 
- **Spikerush**: 
- **POSHSPY**: 
- **PolyglotDuke**: 
- **RegDuke**: 
- **FatDuke**: 

### Russian APT Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | CookieEditor, Mimikatz, SharpChormium, SharpChromium |
| Defense Evasion | EDRSandBlast, VMware Tools (DLL side-loading) |
| Discovery | AADInternals, AdFind, Bloodhound, DSInternals, RoadTools |
| Exfiltration | Dropbox, Firebase, Google Drive, Notion, OneDrive, Trello |
| LOLBAS | PowerPoint.exe (DLL side-loading), PsExec, WMIC, sqlwriter.exe (DLL side-loading) |
| Networking | Dropbear, ReGeorg, Rosockstun, Rsockstun |
| OffSec | Brute Ratel C4, Cobalt Strike, Impacket, PowerSploit, Rubeus, Sliver, WinPEAS |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0016)
   MITRE ATT&CK entry
[2] [White House Imposing Costs RU Gov April 2021](https://www.whitehouse.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/)
[3] [UK Gov Malign RIS Activity April 2021](https://www.gov.uk/government/news/russia-uk-and-us-expose-global-campaigns-of-malign-activity-by-russian-intelligence-services)
[4] [F-Secure The Dukes](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf)
[5] [GRIZZLY STEPPE JAR](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)
[6] [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)
[7] [UK Gov UK Exposes Russia SolarWinds April 2021](https://www.gov.uk/government/news/russia-uk-exposes-russian-involvement-in-solarwinds-cyber-compromise)
[8] [NSA Joint Advisory SVR SolarWinds April 2021](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF)
[9] [UK NSCS Russia SolarWinds April 2021](https://www.ncsc.gov.uk/news/uk-and-us-call-out-russia-for-solarwinds-compromise)
[10] [FireEye SUNBURST Backdoor December 2020](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
[11] [MSTIC NOBELIUM Mar 2021](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
[12] [CrowdStrike SUNSPOT Implant January 2021](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/)
[13] [Volexity SolarWinds](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
[14] [Cybersecurity Advisory SVR TTP May 2021](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf)
[15] [Unit 42 SolarStorm December 2020](https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/)

