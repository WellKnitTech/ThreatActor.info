---
layout: threat_actor
title: "Fog"
aliases: ["FOG","Fog"]
description: "Fog is a sophisticated ransomware strain first observed in April–May 2024, initially targeting U.S. educational institutions before expanding into sectors such as government, business services, finance"
permalink: /fog/
---

## Introduction
Fog is a sophisticated ransomware strain first observed in April–May 2024, initially targeting U.S. educational institutions before expanding into sectors such as government, business services, finance, and manufacturing. The group conducts fast, double-extortion attacks: they exploit compromised VPN credentials or known vulnerabilities, deploy encryption (notably using extensions like .fog, .FLOCKED), and exfiltrate data prior to encryption to maximize victim pressure. Fog is associated with other prolific actors—such as Akira and Conti—through shared tooling, infrastructure timelines, and even cryptocurrency wallets.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Network Edge | SonicWall | SonicOS SSL-VPN | CVE-2024-40766 |
| Applications | Veeam | Backup & Replication | CVE-2024-40711 |
| Microsoft Products | Windows | Active Directory | CVE-2021-42278, CVE-2021-42287 |
| Microsoft Products | Windows | NetLogon | CVE-2020-1472 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| Credential Theft | DonPAPI, Veeam-Get-Creds |
| Discovery | Advanced Port Scanner, SharpShares, SoftPerfect NetScan |
| LOLBAS | PsExec |
| Networking | Powercat, Proxychains |
| OffSec | Certipy, Impacket, Metasploit, NetExec, Orpheus, Sliver, Zer0dump |
| RMM Tools | AnyDesk |

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

