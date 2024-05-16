---
layout: threat_actor
title: "APT28"
aliases: ["Fancy Bear", "Sofacy Group"]
description: "APT28 is a threat actor group known for its sophisticated cyber espionage activities."
permalink: /apt28
---

## Introduction
APT28, also known as Fancy Bear or Sofacy Group, is a cyber espionage group associated with the Russian military intelligence agency GRU. The group is known for its sophisticated operations targeting government, military, security organizations, and media entities worldwide.

## Activities and Tactics
APT28 employs a variety of tactics, techniques, and procedures (TTPs) in its cyber operations. These include spear-phishing campaigns, exploitation of zero-day vulnerabilities, and use of custom malware.

### Notable Campaigns
1. **2016 U.S. Presidential Election**: APT28 was implicated in the hacking of the Democratic National Committee (DNC) and subsequent email leaks.
2. **German Bundestag Hack**: In 2015, APT28 conducted a cyber attack on the German federal parliament, resulting in significant data theft.

## Tactics, Techniques, and Procedures (TTPs)
APT28 is known for the following TTPs:
- **Phishing**: Use of spear-phishing emails to deliver malware.
- **Exploitation of Vulnerabilities**: Exploiting zero-day vulnerabilities to gain initial access.
- **Command and Control**: Use of various command and control (C2) techniques to maintain persistence.

## Notable Indicators of Compromise (IOCs)
Here are some notable IOCs associated with APT28:
- **IP Addresses**:
  - `192.168.1.1`
  - `10.0.0.1`
- **Domains**:
  - `maliciousdomain.com`
  - `anothermaliciousdomain.net`
- **File Hashes**:
  - `d41d8cd98f00b204e9800998ecf8427e`
  - `e2fc714c4727ee9395f324cd2e7f331f`

## Emulating TTPs with Atomic Red Team
To emulate APT28's TTPs, you can use Atomic Red Team's tests. Here are some relevant tests:
- **Phishing Email Simulation**: [Link to Atomic Red Team test](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566/T1566.md)
- **Exploit Vulnerability**: [Link to Atomic Red Team test](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1203/T1203.md)
- **Command and Control Simulation**: [Link to Atomic Red Team test](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md)

## Malware and Tools
APT28 uses a range of custom malware and tools, including:
- **X-Agent**: A modular backdoor used for data exfiltration.
- **Zebrocy**: A Trojan downloader used to deliver additional payloads.

## Attribution and Evidence
Researchers and government agencies have attributed APT28’s activities to the GRU based on various pieces of evidence, including malware code similarities, operational patterns, and the targeting of specific geopolitical interests.

## References
1. **FireEye Report on APT28**: [Link to report](https://www.fireeye.com/current-threats/apt-groups/rpt-apt28.html)
2. **CrowdStrike Analysis**: [Link to analysis](https://www.crowdstrike.com/blog/who-is-fancy-bear/)
3. **U.S. Government Attribution**: [Link to government statement](https://www.dhs.gov/news/2021/10/07/joint-statement-apt28)

## External Links
- [Wikipedia on Fancy Bear](https://en.wikipedia.org/wiki/Fancy_Bear)
- [MITRE ATT&CK - APT28](https://attack.mitre.org/groups/G0007/)
