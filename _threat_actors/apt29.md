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
*Information pending cataloguing.*

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

