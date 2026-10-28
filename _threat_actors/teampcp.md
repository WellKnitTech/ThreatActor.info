---
layout: threat_actor
title: "TeamPCP"
aliases: ["Altered Spider","CanisterWorm","DeadCatx3","PCPCat","PCPcat","SHADOW-WATER-058","ShellForce","Storm-2999","TeamPCP","UNC6780"]
description: "TeamPCP is a threat actor that has executed a coordinated series of supply chain attacks, compromising widely-used open source tools such as Trivy, KICS, and LiteLLM to deploy credential-stealing malwa"
permalink: /teampcp/
---

## Introduction
TeamPCP is a threat actor that has executed a coordinated series of supply chain attacks, compromising widely-used open source tools such as Trivy, KICS, and LiteLLM to deploy credential-stealing malware. They employed techniques like credential harvesting, lateral movement within Kubernetes environments, and audio steganography to evade detection. The group has demonstrated the ability to leverage stolen credentials to propagate attacks across multiple ecosystems, including npm and PyPI, using a self-propagating worm known as CanisterWorm. Their operations have included the use of AES-256 encryption and RSA-4096 for exfiltration of sensitive data.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
- [T1027.003 Steganography](https://attack.mitre.org/techniques/T1027/003)
- [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005)
- [T1543.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002)
- [T1555.006 Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006)
- [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001)
- [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528)
- [T1059.006 Python](https://attack.mitre.org/techniques/T1059/006)
- [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)
- [T1552.004 Private Keys](https://attack.mitre.org/techniques/T1552/004)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
- [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078)
- [T1587.001 Malware](https://attack.mitre.org/techniques/T1587/001)
- [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006)
- [T1195.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001)
- [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098)
- [T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001)
- [T1684.001 Impersonation](https://attack.mitre.org/techniques/T1684/001)
- [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)
- [T1546.016 Installer Packages](https://attack.mitre.org/techniques/T1546/016)
- [T1564.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001)
- [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485)
- [T1683.001 Written Content](https://attack.mitre.org/techniques/T1683/001)
- [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)
- [T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007)
- [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002)
- [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005)
- [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657)
- [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610)
- [T1059.013 Container CLI/API](https://attack.mitre.org/techniques/T1059/013)
- [T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004)
- [T1583.004 Server](https://attack.mitre.org/techniques/T1583/004)
- [T1608.001 Upload Malware](https://attack.mitre.org/techniques/T1608/001)
- [T1677 Poisoned Pipeline Execution](https://attack.mitre.org/techniques/T1677)
- [T1583 Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)
- [T1176.002 IDE Extensions](https://attack.mitre.org/techniques/T1176/002)

### ATT&CK technique IDs (denormalized)

- [T1005](https://attack.mitre.org/techniques/T1005/)
- [T1027.003](https://attack.mitre.org/techniques/T1027/003/)
- [T1036.005](https://attack.mitre.org/techniques/T1036/005/)
- [T1059.004](https://attack.mitre.org/techniques/T1059/004/)
- [T1059.006](https://attack.mitre.org/techniques/T1059/006/)
- [T1059.007](https://attack.mitre.org/techniques/T1059/007/)
- [T1059.013](https://attack.mitre.org/techniques/T1059/013/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [T1098](https://attack.mitre.org/techniques/T1098/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1176.002](https://attack.mitre.org/techniques/T1176/002/)
- [T1190](https://attack.mitre.org/techniques/T1190/)
- [T1195.001](https://attack.mitre.org/techniques/T1195/001/)
- [T1485](https://attack.mitre.org/techniques/T1485/)
- [T1486](https://attack.mitre.org/techniques/T1486/)
- [T1528](https://attack.mitre.org/techniques/T1528/)
- [T1543.002](https://attack.mitre.org/techniques/T1543/002/)
- [T1546.016](https://attack.mitre.org/techniques/T1546/016/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [T1550.001](https://attack.mitre.org/techniques/T1550/001/)
- [T1552.004](https://attack.mitre.org/techniques/T1552/004/)
- [T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [T1555.006](https://attack.mitre.org/techniques/T1555/006/)
- [T1564.001](https://attack.mitre.org/techniques/T1564/001/)
- [T1583](https://attack.mitre.org/techniques/T1583/)
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/)
- [T1583.004](https://attack.mitre.org/techniques/T1583/004/)
- [T1583.006](https://attack.mitre.org/techniques/T1583/006/)
- [T1585.001](https://attack.mitre.org/techniques/T1585/001/)
- [T1587.001](https://attack.mitre.org/techniques/T1587/001/)
- [T1608.001](https://attack.mitre.org/techniques/T1608/001/)
- [T1610](https://attack.mitre.org/techniques/T1610/)
- [T1657](https://attack.mitre.org/techniques/T1657/)
- [T1677](https://attack.mitre.org/techniques/T1677/)
- [T1683.001](https://attack.mitre.org/techniques/T1683/001/)
- [T1684.001](https://attack.mitre.org/techniques/T1684/001/)

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **GraphicBooting**
- **CrossRat**

### MITRE ATT&CK Software
- [CanisterWorm (S9042) — malware](https://attack.mitre.org/software/S9042)
- [Mini Shai-Hulud (S9043) — malware](https://attack.mitre.org/software/S9043)
- [TeamPCP Cloud Stealer (S9041) — malware](https://attack.mitre.org/software/S9041)

## Attribution and Evidence
*Information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G1056)
   MITRE ATT&CK entry

