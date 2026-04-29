---
layout: threat_actor
title: "APT34"
aliases: ["APT34", "COBALT GYPSY", "Crambus", "Earth Simnavaz", "EUROPIUM", "Evasive Serpens", "Hazel Sandstorm", "Helix Kitten", "IRN2", "ITG13", "OilRig", "TA452"]
description: "OilRig is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of sectors, including financial, government, "
permalink: /apt34/
---

## Introduction
OilRig is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of sectors, including financial, government, energy, chemical, and telecommunications. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. The group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests. [FireEye APT34 Dec 2017](https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html) [Palo Alto OilRig April 2017](http://researchcenter.paloaltonetworks.com/2017/04/unit42-oilrig-actors-provide-glimpse-development-testing-efforts/) [ClearSky OilRig Jan 2017](http://www.clearskysec.com/oilrig/) [Palo Alto OilRig May 2016](http://researchcenter.paloaltonetworks.com/2016/05/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/) [Palo Alto OilRig Oct 2016](http://researchcenter.paloaltonetworks.com/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/) [Unit42 OilRig Playbook 2023](https://pan-unit42.github.io/playbook_viewer/?pb=evasive-serpens) [Unit 42 QUADAGENT July 2018](https://researchcenter.paloaltonetworks.com/2018/07/unit42-oilrig-targets-technology-service-provider-government-agency-quadagent/)

## Activities and Tactics
**Targeted Sectors**: Energy, Government, Telecommunications

**Country of Origin**: 🇮🇷 Iran

**Risk Level**: High

**First Seen**: 2014

**Last Activity**: 2024


## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Enterprise ATT&CK techniques below are drawn from the merged [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) dataset for MITRE group G0049 (YAML `ttps` empty).*

- [T1003.001 LSASS Memory](/techniques/T1003.001/)
- [T1003.004 LSA Secrets](/techniques/T1003.004/)
- [T1003.005 Cached Domain Credentials](/techniques/T1003.005/)
- [T1007 System Service Discovery](/techniques/T1007/)
- [T1008 Fallback Channels](/techniques/T1008/)
- [T1012 Query Registry](/techniques/T1012/)
- [T1016 System Network Configuration Discovery](/techniques/T1016/)
- [T1021.001 Remote Desktop Protocol](/techniques/T1021.001/)
- [T1021.004 SSH](/techniques/T1021.004/)
- [T1027 Obfuscated Files or Information](/techniques/T1027/)
- [T1027.005 Indicator Removal from Tools](/techniques/T1027.005/)
- [T1033 System Owner/User Discovery](/techniques/T1033/)
- [T1036 Masquerading](/techniques/T1036/)
- [T1043](https://attack.mitre.org/techniques/T1043/)
- [T1046 Network Service Discovery](/techniques/T1046/)
- [T1047 Windows Management Instrumentation](/techniques/T1047/)
- [T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol](/techniques/T1048.003/)
- [T1049 System Network Connections Discovery](/techniques/T1049/)
- [T1053.005 Scheduled Task](/techniques/T1053.005/)
- [T1056.001 Keylogging](/techniques/T1056.001/)
- [T1057 Process Discovery](/techniques/T1057/)
- [T1059 Command and Scripting Interpreter](/techniques/T1059/)
- [T1059.001 PowerShell](/techniques/T1059.001/)
- [T1059.003 Windows Command Shell](/techniques/T1059.003/)
- [T1059.005 Visual Basic](/techniques/T1059.005/)
- [T1069.001 Local Groups](/techniques/T1069.001/)
- [T1069.002 Domain Groups](/techniques/T1069.002/)
- [T1070.004 File Deletion](/techniques/T1070.004/)
- [T1071.001 Web Protocols](/techniques/T1071.001/)
- [T1071.004 DNS](/techniques/T1071.004/)
- [T1078 Valid Accounts](/techniques/T1078/)
- [T1082 System Information Discovery](/techniques/T1082/)
- [T1087.001 Local Account](/techniques/T1087.001/)
- [T1087.002 Domain Account](/techniques/T1087.002/)
- [T1094](https://attack.mitre.org/techniques/T1094/)
- [T1105 Ingress Tool Transfer](/techniques/T1105/)
- [T1110 Brute Force](/techniques/T1110/)
- [T1113 Screen Capture](/techniques/T1113/)
- [T1119 Automated Collection](/techniques/T1119/)
- [T1120 Peripheral Device Discovery](/techniques/T1120/)
- [T1133 External Remote Services](/techniques/T1133/)
- [T1137.004 Outlook Home Page](/techniques/T1137.004/)
- [T1140 Deobfuscate/Decode Files or Information](/techniques/T1140/)
- [T1201 Password Policy Discovery](/techniques/T1201/)
- [T1204.001 Malicious Link](/techniques/T1204.001/)
- [T1204.002 Malicious File](/techniques/T1204.002/)
- [T1218.001 Compiled HTML File](/techniques/T1218.001/)
- [T1497.001 System Checks](/techniques/T1497.001/)
- [T1505.003 Web Shell](/techniques/T1505.003/)
- [T1552.001 Credentials In Files](/techniques/T1552.001/)
- [T1555 Credentials from Password Stores](/techniques/T1555/)
- [T1555.003 Credentials from Web Browsers](/techniques/T1555.003/)
- [T1555.004 Windows Credential Manager](/techniques/T1555.004/)
- [T1566.001 Spearphishing Attachment](/techniques/T1566.001/)
- [T1566.002 Spearphishing Link](/techniques/T1566.002/)
- [T1566.003 Spearphishing via Service](/techniques/T1566.003/)
- [T1572 Protocol Tunneling](/techniques/T1572/)
- [T1573.002 Asymmetric Cryptography](/techniques/T1573.002/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
*Information pending cataloguing.*

## Attribution and Evidence
**Country of Origin**: Iran
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0049)
   MITRE ATT&CK entry
[2] [FireEye APT34 Dec 2017](https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html)
[3] [Palo Alto OilRig April 2017](http://researchcenter.paloaltonetworks.com/2017/04/unit42-oilrig-actors-provide-glimpse-development-testing-efforts/)
[4] [ClearSky OilRig Jan 2017](http://www.clearskysec.com/oilrig/)
[5] [Palo Alto OilRig May 2016](http://researchcenter.paloaltonetworks.com/2016/05/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/)
[6] [Palo Alto OilRig Oct 2016](http://researchcenter.paloaltonetworks.com/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/)
[7] [Unit42 OilRig Playbook 2023](https://pan-unit42.github.io/playbook_viewer/?pb=evasive-serpens)
[8] [Unit 42 QUADAGENT July 2018](https://researchcenter.paloaltonetworks.com/2018/07/unit42-oilrig-targets-technology-service-provider-government-agency-quadagent/)

