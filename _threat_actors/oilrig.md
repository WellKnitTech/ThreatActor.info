---
layout: threat_actor
title: "OilRig"
aliases: ["Twisted Kitten", "Cobalt Gypsy", "Crambus", "Helix Kitten", "APT 34", "APT34", "IRN2", "ATK40", "G0049", "Evasive Serpens", "Hazel Sandstorm", "EUROPIUM", "TA452", "Earth Simnavaz", "OilRig"]
description: "OilRig is an Iranian threat group operating primarily in the Middle East by targeting organizations in this region that are in a variety of different industries; however, this group has occasionally ta"
permalink: /oilrig/
---

## Introduction
OilRig is an Iranian threat group operating primarily in the Middle East by targeting organizations in this region that are in a variety of different industries; however, this group has occasionally targeted organizations outside of the Middle East as well. It also appears OilRig carries out supply chain attacks, where the threat group leverages the trust relationship between organizations to attack their primary targets. OilRig is an active and organized threat group, which is evident based on their systematic targeting of specific organizations that appear to be carefully chosen for strategic purposes. Attacks attributed to this group primarily rely on social engineering to exploit the human rather than software vulnerabilities; however, on occasion this group has used recently patched vulnerabilities in the delivery phase of their attacks. The lack of software vulnerability exploitation does not necessarily suggest a lack of sophistication, as OilRig has shown maturity in other aspects of their operations. Such maturities involve: -Organized evasion testing used the during development of their tools. -Use of custom DNS Tunneling protocols for command and control (C2) and data exfiltration. -Custom web-shells and backdoors used to persistently access servers. OilRig relies on stolen account credentials for lateral movement. After OilRig gains access to a system, they use credential dumping tools, such as Mimikatz, to steal credentials to accounts logged into the compromised system. The group uses these credentials to access and to move laterally to other systems on the network. After obtaining credentials from a system, operators in this group prefer to use tools other than their backdoors to access the compromised systems, such as remote desktop and putty. OilRig also uses phishing sites to harvest credentials to individuals at targeted organizations to gain access to internet accessible resources, such as Outlook Web Access. Since at least 2014, an Iranian threat group tracked by FireEye as APT34 has conducted reconnaissance aligned with the strategic interests of Iran. The group conducts operations primarily in the Middle East, targeting financial, government, energy, chemical, telecommunications and other industries. Repeated targeting of Middle Eastern financial, energy and government organizations leads FireEye to assess that those sectors are a primary concern of APT34. The use of infrastructure tied to Iranian operations, timing and alignment with the national interests of Iran also lead FireEye to assess that APT34 acts on behalf of the Iranian government.

## Activities and Tactics
**Targeted Sectors**: Chemical, Energy, Engineering, Finance, Government, Administration, Telecoms, Other, Government, Private sector, Civil society
**Country of Origin**: 🇮🇷 Iran
**Risk Level**: High
**Incident Type**: Espionage
**Suspected Victims**: Israel, Kuwait, United States, Turkey, Saudi Arabia, Qatar, Lebanon, Middle East

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **{"name" => "Backdoor.Oldrea"}**
- **{"name" => "RemoteCMD"}**
- **{"name" => "Remote Utilities"}**
- **{"name" => "RemotePC"}**
- **{"name" => "DesktopNow"}**
- **{"name" => "Xploit"}**

## Attribution and Evidence
**Country of Origin**: Iran
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

