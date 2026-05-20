---
layout: threat_actor
title: "APT41"
aliases: ["Amoeba","APT41","Barium","BARIUM","Blackfly","Brass Typhoon","BRONZE ATLAS","BRONZE EXPORT","Double Dragon","Earth Baku","G0044","G0096","Grayfly","HOODOO","LEAD","Leopard Typhoon","Red Kelpie","TA415","TG-2633","Wicked Panda","WICKED PANDA","WICKED SPIDER","Wicked Spider","Winnti","Winnti Group","Winnti Umbrella"]
description: "APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, APT41 has been observe"
permalink: /apt41/
---

## Introduction
APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, APT41 has been observed targeting various industries, including but not limited to healthcare, telecom, technology, finance, education, retail and video game industries in 14 countries. [apt41_mandiant](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf) Notable behaviors include using a wide range of malware and tools to complete mission objectives. APT41 overlaps at least partially with public reporting on groups including BARIUM and Winnti Group. [FireEye APT41 Aug 2019](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf) [Group IB APT 41 June 2021](https://www.group-ib.com/blog/colunmtk-apt41/)

## Activities and Tactics
**Targeted Sectors**: Gaming, Technology, Healthcare, Automotive, Business, Services, Cryptocurrency, Education, Energy, Financial, High-Tech, Intergovernmental, Media and Entertainment, Pharmaceuticals, Private sector, Retail, Telecommunications, Travel

**Country of Origin**: 🇨🇳 China

**Risk Level**: High

**First Seen**: 2012

**Last Activity**: 2024


**Suspected Victims**: China, France, Hong Kong, India, Italy, Japan, Myanmar, Netherlands, Singapore, South Korea...

## Notable Campaigns
- [Avast/CCleaner](https://blog.avast.com/update-ccleaner-attackers-entered-via-teamviewer) (September 2016; WickedPanda (CN APT))

## Tactics, Techniques, and Procedures (TTPs)
- [T1014 Rootkit](https://attack.mitre.org/techniques/T1014)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057)
- [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002)

### ATT&CK technique IDs (denormalized)

- [T1014](https://attack.mitre.org/techniques/T1014/)
- [T1057](https://attack.mitre.org/techniques/T1057/)
- [T1083](https://attack.mitre.org/techniques/T1083/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 9 public reports that may contain IOCs; see Source Attribution for dataset links.*

## Malware and Tools
- **CyberGate**
- **Cyber Eye RAT**
- **Winnti Rootkit malware**: 
- **CRACKSHOT**: 
- **GEARSHIFT**: 
- **HIGHNOON**: 
- **JUMPALL**: 
- **POISONPLUG**: 
- **HOTCHAI**: 
- **LATELUNCH**: 
- **LIFEBOAT**: 
- **LOWKEY**: 
- **NJRAT**: 
- **PACMAN**: 
- **PHOTO**: 
- **POTROAST**: 
- **ROCKBOOT**: 
- **SAGEHIRE**: 
- **SWEETCANDLE**: 
- **SOGU**: 
- **TERA**: 
- **TIDYELF**: 
- **WIDETONE**: 
- **WINTERLOVE**: 
- **XDoor**: 
- **Xmrig**: 
- **ZxShell**: 

### MITRE ATT&CK Software
- [PipeMon (S0501) — malware](https://attack.mitre.org/software/S0501)
- [Winnti for Windows (S0141) — malware](https://attack.mitre.org/software/S0141)
- [PlugX (S0013) — malware](https://attack.mitre.org/software/S0013)

## Attribution and Evidence
**Country of Origin**: China
*Additional attribution information pending cataloguing.*

## References
[1] [mitre-attack](https://attack.mitre.org/groups/G0096)
[6] [Crowdstrike GTR2020 Mar 2020](https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2020CrowdStrikeGlobalThreatReport.pdf)
   Crowdstrike. (2020, March 2). 2020 Global Threat Report. Retrieved December 11, 2020.
[7] [FireEye APT41 2019](https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf)
   FireEye. (2019). Double DragonAPT41, a dual espionage andcyber crime operationAPT41. Retrieved September 23, 2019.
[8] [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide)
   Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
[9] [Group IB APT 41 June 2021](https://www.group-ib.com/blog/colunmtk-apt41/)
   Rostovcev, N. (2021, June 10). Big airline heist APT41 likely behind a third-party attack on Air India. Retrieved August 26, 2021.
[10] [mitre-attack](https://attack.mitre.org/groups/G0044)
[13] [Symantec Suckfly March 2016](http://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates)
   DiMaggio, J. (2016, March 15). Suckfly: Revealing the secret life of your code signing certificates. Retrieved August 3, 2016.
[14] [401 TRG Winnti Umbrella May 2018](https://401trg.github.io/pages/burning-umbrella.html)
   Hegel, T. (2018, May 3). Burning Umbrella: An Intelligence Report on the Winnti Umbrella and Associated State-Sponsored Attackers. Retrieved July 8, 2018.
[15] [Kaspersky Winnti April 2013](https://securelist.com/winnti-more-than-just-a-game/37029/)
   Kaspersky Lab's Global Research and Analysis Team. (2013, April 11). Winnti. More than just a game. Retrieved February 8, 2017.
[16] [Novetta Winnti April 2015](https://web.archive.org/web/20150412223949/http://www.novetta.com/wp-content/uploads/2015/04/novetta_winntianalysis.pdf)
   Novetta Threat Research Group. (2015, April 7). Winnti Analysis. Retrieved February 8, 2017.
[17] [Kaspersky Winnti June 2015](https://securelist.com/games-are-over/70991/)
   Tarakanov, D. (2015, June 22). Games are over: Winnti is now targeting pharmaceutical companies. Retrieved January 14, 2016.

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [Rapid7’s 2026 Global Cybersecurity Summit: Key Takeaways for Security Leaders](https://www.rapid7.com/blog/post/it-2026-global-cybersecurity-summit-key-takeaways-security-leaders)
  Rapid7 - 2026-05-19T

