---
layout: threat_actor
title: "APT29"
aliases: ["APT29","ATK7","Backswimmer","Blue Kitsune","Blue Nova","BlueBravo","COZY BEAR","Cloaked Ursa","Cozer","Cozy","Cozy Bear","Cozy Bear (CrowdStrike)","Cozy Duke","CozyCar","CozyDuke","Cranefly","DEV-0473","Dark Halo","DarkHalo","Dukes","EuroAPT","Eurostrike","Fritillary","G0016","Grizzly Steppe","Group 100","Hagensia","Hammer Toss","ICE RELIC","ICECAP","IRON HEMLOCK","IRON RITUAL","ITG11","Iron Hemlock","Iron Ritual","Midnight Blizzard","Midnight Blizzard (Microsoft)","Minidionis","NOBELIUM","Nobelium","NobleBaron","Noblebaron","Office Monkeys","Office Monkeys / TEMP.Monkeys","Office Space","SeaDuke","Solar Phoenix","SolarStorm","Solarstorm","StellarParticle","TA421","TAG-11","The Dukes","UAC-0029","UNC2452","UNC3524","YTTRIUM","Yttrium"]
description: "APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR). [White House Imposing Costs RU Gov April 2021](https://www.whitehouse.gov/briefing-room/statements-release"
permalink: /apt29/
---

## Introduction
APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR). [White House Imposing Costs RU Gov April 2021](https://www.whitehouse.gov/briefing-room/statements-releases/2021/04/15/fact-sheet-imposing-costs-for-harmful-foreign-activities-by-the-russian-government/) [UK Gov Malign RIS Activity April 2021](https://www.gov.uk/government/news/russia-uk-and-us-expose-global-campaigns-of-malign-activity-by-russian-intelligence-services) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. APT29 reportedly compromised the Democratic National Committee starting in the summer of 2015. [F-Secure The Dukes](https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf) [GRIZZLY STEPPE JAR](https://www.us-cert.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf) [Crowdstrike DNC June 2016](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/) [UK Gov UK Exposes Russia SolarWinds April 2021](https://www.gov.uk/government/news/russia-uk-exposes-russian-involvement-in-solarwinds-cyber-compromise) In April 2021, the US and UK governments attributed the SolarWinds Compromise to the SVR; public statements included citations to APT29, Cozy Bear, and The Dukes. [NSA Joint Advisory SVR SolarWinds April 2021](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF) [UK NSCS Russia SolarWinds April 2021](https://www.ncsc.gov.uk/news/uk-and-us-call-out-russia-for-solarwinds-compromise) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm. [FireEye SUNBURST Backdoor December 2020](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html) [MSTIC NOBELIUM Mar 2021](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/) [CrowdStrike SUNSPOT Implant January 2021](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/) [Volexity SolarWinds](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/) [Cybersecurity Advisory SVR TTP May 2021](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf) [Unit 42 SolarStorm December 2020](https://unit42.paloaltonetworks.com/solarstorm-supply-chain-attack-timeline/)

## Activities and Tactics
**Targeted Sectors**: Government, Healthcare, Energy, Think Tanks, Government, Administration, Private sector

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: High

**First Seen**: 2008

**Last Activity**: 2024

**Incident Type**: Espionage

**Suspected Victims**: United States, China, New Zealand, Ukraine, Romania, Georgia, Japan, South Korea, Belgium, Kazakhstan...

## Notable Campaigns
- [SolarWinds Compromise (C0024)](https://attack.mitre.org/campaigns/C0024): The SolarWinds Compromise was a sophisticated supply chain cyber operation conducted by APT29 that was discovered in mid-December 2020. APT29 used customized malware to inject malicious code into the SolarWinds Orion software build process that was later distributed through a normal software update; they also used password spraying, token theft, API abuse, spear phishing, and other supply chain attacks to compromise user accounts and leverage their associated access. Victims of this campaign incl
- [Operation Ghost (C0023)](https://attack.mitre.org/campaigns/C0023): Operation Ghost was an APT29 campaign starting in 2013 that included operations against ministries of foreign affairs in Europe and the Washington, D.C. embassy of a European Union country. During Operation Ghost, APT29 used new families of malware and leveraged web services, steganography, and unique C2 infrastructure for each victim.(Citation: ESET Dukes October 2019)


## Tactics, Techniques, and Procedures (TTPs)
- [T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621)
- [T1003.002 Security Account Manager](https://attack.mitre.org/techniques/T1003/002)
- [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002)
- [T1090.004 Domain Fronting](https://attack.mitre.org/techniques/T1090/004)
- [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528)
- [T1568 Dynamic Resolution](https://attack.mitre.org/techniques/T1568)
- [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)
- [T1546.003 Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1136.003 Cloud Account](https://attack.mitre.org/techniques/T1136/003)
- [T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005)
- [T1587.003 Digital Certificates](https://attack.mitre.org/techniques/T1587/003)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651)
- [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)
- [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)
- [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)
- [T1016.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001)
- [T1587.001 Malware](https://attack.mitre.org/techniques/T1587/001)
- [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006)
- [T1090.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)
- [T1037 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037)
- [T1027.006 HTML Smuggling](https://attack.mitre.org/techniques/T1027/006)
- [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004)
- [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203)
- [T1550.003 Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)
- [T1204.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003)
- [T1114.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002)
- [T1027.001 Binary Padding](https://attack.mitre.org/techniques/T1027/001)
- [T1556.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)
- [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133)
- [T1037.004 RC Scripts](https://attack.mitre.org/techniques/T1037/004)
- [T1021.007 Cloud Services](https://attack.mitre.org/techniques/T1021/007)
- [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)
- [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006)
- [T1586.003 Cloud Accounts](https://attack.mitre.org/techniques/T1586/003)
- [T1090.002 External Proxy](https://attack.mitre.org/techniques/T1090/002)
- [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573)
- [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)
- [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)
- [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199)
- [T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003)
- [T1059.006 Python](https://attack.mitre.org/techniques/T1059/006)
- [T1665 Hide Infrastructure](https://attack.mitre.org/techniques/T1665)
- [T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005)
- [T1003.004 LSA Secrets](https://attack.mitre.org/techniques/T1003/004)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1553.005 Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005)
- [T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649)
- [T1087.004 Cloud Account](https://attack.mitre.org/techniques/T1087/004)
- [T1098.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)
- [T1078.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003)
- [T1546.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008)
- [T1059.009 Cloud API](https://attack.mitre.org/techniques/T1059/009)
- [T1586.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002)
- [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002)
- [T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002)
- [T1548.002 Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)
- [T1027.002 Software Packing](https://attack.mitre.org/techniques/T1027/002)

### ATT&CK technique IDs (denormalized)

- [T1003.002](https://attack.mitre.org/techniques/T1003/002/)
- [T1003.004](https://attack.mitre.org/techniques/T1003/004/)
- [T1005](https://attack.mitre.org/techniques/T1005/)
- [T1016.001](https://attack.mitre.org/techniques/T1016/001/)
- [T1021.007](https://attack.mitre.org/techniques/T1021/007/)
- [T1027.001](https://attack.mitre.org/techniques/T1027/001/)
- [T1027.002](https://attack.mitre.org/techniques/T1027/002/)
- [T1027.006](https://attack.mitre.org/techniques/T1027/006/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1037](https://attack.mitre.org/techniques/T1037/)
- [T1037.004](https://attack.mitre.org/techniques/T1037/004/)
- [T1047](https://attack.mitre.org/techniques/T1047/)
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1059.006](https://attack.mitre.org/techniques/T1059/006/)
- [T1059.009](https://attack.mitre.org/techniques/T1059/009/)
- [T1068](https://attack.mitre.org/techniques/T1068/)
- [T1070.004](https://attack.mitre.org/techniques/T1070/004/)
- [T1070.006](https://attack.mitre.org/techniques/T1070/006/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1078.003](https://attack.mitre.org/techniques/T1078/003/)
- [T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [T1087.004](https://attack.mitre.org/techniques/T1087/004/)
- [T1090.002](https://attack.mitre.org/techniques/T1090/002/)
- [T1090.003](https://attack.mitre.org/techniques/T1090/003/)
- [T1090.004](https://attack.mitre.org/techniques/T1090/004/)
- [T1098.002](https://attack.mitre.org/techniques/T1098/002/)
- [T1098.005](https://attack.mitre.org/techniques/T1098/005/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [T1114.002](https://attack.mitre.org/techniques/T1114/002/)
- [T1133](https://attack.mitre.org/techniques/T1133/)
- [T1136.003](https://attack.mitre.org/techniques/T1136/003/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1199](https://attack.mitre.org/techniques/T1199/)
- [T1203](https://attack.mitre.org/techniques/T1203/)
- [T1204.001](https://attack.mitre.org/techniques/T1204/001/)
- [T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [T1218.005](https://attack.mitre.org/techniques/T1218/005/)
- [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [T1528](https://attack.mitre.org/techniques/T1528/)
- [T1546.003](https://attack.mitre.org/techniques/T1546/003/)
- [T1546.008](https://attack.mitre.org/techniques/T1546/008/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [T1548.002](https://attack.mitre.org/techniques/T1548/002/)
- [T1550.003](https://attack.mitre.org/techniques/T1550/003/)
- [T1553.005](https://attack.mitre.org/techniques/T1553/005/)
- [T1556.007](https://attack.mitre.org/techniques/T1556/007/)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [T1566.003](https://attack.mitre.org/techniques/T1566/003/)
- [T1568](https://attack.mitre.org/techniques/T1568/)
- [T1573](https://attack.mitre.org/techniques/T1573/)
- [T1583.006](https://attack.mitre.org/techniques/T1583/006/)
- [T1586.002](https://attack.mitre.org/techniques/T1586/002/)
- [T1586.003](https://attack.mitre.org/techniques/T1586/003/)
- [T1587.001](https://attack.mitre.org/techniques/T1587/001/)
- [T1587.003](https://attack.mitre.org/techniques/T1587/003/)
- [T1588.002](https://attack.mitre.org/techniques/T1588/002/)
- [T1595.002](https://attack.mitre.org/techniques/T1595/002/)
- [T1621](https://attack.mitre.org/techniques/T1621/)
- [T1649](https://attack.mitre.org/techniques/T1649/)
- [T1651](https://attack.mitre.org/techniques/T1651/)
- [T1665](https://attack.mitre.org/techniques/T1665/)
- [T1685.002](https://attack.mitre.org/techniques/T1685/002/)

## Notable Indicators of Compromise (IOCs)
*No atomic indicators are listed in this profile. The APTnotes snapshot indexes 5 public reports that may contain IOCs; see Source Attribution for dataset links.*

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

### MITRE ATT&CK Software
- [PinchDuke (S0048) — malware](https://attack.mitre.org/software/S0048)
- [ROADTools (S0684) — tool](https://attack.mitre.org/software/S0684)
- [WellMail (S0515) — malware](https://attack.mitre.org/software/S0515)
- [CozyCar (S0046) — malware](https://attack.mitre.org/software/S0046)
- [Mimikatz (S0002) — tool](https://attack.mitre.org/software/S0002)
- [meek (S0175) — tool](https://attack.mitre.org/software/S0175)
- [TrailBlazer (S0682) — malware](https://attack.mitre.org/software/S0682)
- [Tasklist (S0057) — tool](https://attack.mitre.org/software/S0057)
- [OnionDuke (S0052) — malware](https://attack.mitre.org/software/S0052)
- [FatDuke (S0512) — malware](https://attack.mitre.org/software/S0512)
- [POSHSPY (S0150) — malware](https://attack.mitre.org/software/S0150)
- [EnvyScout (S0634) — malware](https://attack.mitre.org/software/S0634)
- [SoreFang (S0516) — malware](https://attack.mitre.org/software/S0516)
- [GeminiDuke (S0049) — malware](https://attack.mitre.org/software/S0049)
- [reGeorg (S1187) — malware](https://attack.mitre.org/software/S1187)
- [BloodHound (S0521) — tool](https://attack.mitre.org/software/S0521)
- [GoldMax (S0588) — malware](https://attack.mitre.org/software/S0588)
- [FoggyWeb (S0661) — malware](https://attack.mitre.org/software/S0661)
- [SDelete (S0195) — tool](https://attack.mitre.org/software/S0195)
- [PolyglotDuke (S0518) — malware](https://attack.mitre.org/software/S0518)
- [AADInternals (S0677) — tool](https://attack.mitre.org/software/S0677)
- [MiniDuke (S0051) — malware](https://attack.mitre.org/software/S0051)
- [TEARDROP (S0560) — malware](https://attack.mitre.org/software/S0560)
- [SeaDuke (S0053) — malware](https://attack.mitre.org/software/S0053)
- [Sibot (S0589) — malware](https://attack.mitre.org/software/S0589)
- [Raindrop (S0565) — malware](https://attack.mitre.org/software/S0565)
- [RegDuke (S0511) — malware](https://attack.mitre.org/software/S0511)
- [CloudDuke (S0054) — malware](https://attack.mitre.org/software/S0054)
- [GoldFinder (S0597) — malware](https://attack.mitre.org/software/S0597)
- [AdFind (S0552) — tool](https://attack.mitre.org/software/S0552)
- [PsExec (S0029) — tool](https://attack.mitre.org/software/S0029)
- [Tor (S0183) — tool](https://attack.mitre.org/software/S0183)
- [NativeZone (S0637) — malware](https://attack.mitre.org/software/S0637)
- [Systeminfo (S0096) — tool](https://attack.mitre.org/software/S0096)
- [ipconfig (S0100) — tool](https://attack.mitre.org/software/S0100)
- [SUNSPOT (S0562) — malware](https://attack.mitre.org/software/S0562)
- [Impacket (S0357) — tool](https://attack.mitre.org/software/S0357)
- [Cobalt Strike (S0154) — malware](https://attack.mitre.org/software/S0154)
- [PowerDuke (S0139) — malware](https://attack.mitre.org/software/S0139)
- [Net (S0039) — tool](https://attack.mitre.org/software/S0039)
- [QUIETEXIT (S1084) — malware](https://attack.mitre.org/software/S1084)
- [HAMMERTOSS (S0037) — malware](https://attack.mitre.org/software/S0037)
- [BoomBox (S0635) — malware](https://attack.mitre.org/software/S0635)
- [Sliver (S0633) — tool](https://attack.mitre.org/software/S0633)
- [CosmicDuke (S0050) — malware](https://attack.mitre.org/software/S0050)
- [SUNBURST (S0559) — malware](https://attack.mitre.org/software/S0559)
- [WellMess (S0514) — malware](https://attack.mitre.org/software/S0514)
- [VaporRage (S0636) — malware](https://attack.mitre.org/software/S0636)
- [LiteDuke (S0513) — malware](https://attack.mitre.org/software/S0513)

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

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [How SentinelOne Blocked APT29's CaptiveCrunch Campaign](https://sentinelone.com/blog/how-sentinelone-blocked-apt29-s-captivecrunch-campaign)
  SentinelOne — 2026-10-16 — tags: apt
