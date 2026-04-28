---
layout: threat_actor
title: "Alpha Spider"
aliases: ["ALPHV Ransomware Group", "Alpha Spider"]
description: "ALPHA SPIDER is a threat actor known for developing and operating the Alphv ransomware as a service. They have been observed using novel offensive techniques, such as exploiting software vulnerabilitie"
permalink: /alpha-spider/
---

## Introduction
ALPHA SPIDER is a threat actor known for developing and operating the Alphv ransomware as a service. They have been observed using novel offensive techniques, such as exploiting software vulnerabilities and leveraging legitimate administration tools for malicious activities. ALPHA SPIDER affiliates have demonstrated persistence in exfiltrating data and have shown the ability to bypass security measures like DNS-based filtering and multifactor authentication. Despite lacking specific operational security measures, defenders have opportunities to detect and respond to ALPHA SPIDER's operations effectively.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| Group Profile, Virtualization | Citrix | NetScaler ADC & Gateway | CVE-2023-4966 |
| Applications, Group Profile | ConnectWise | ScreenConnect | CVE-2024-1708, CVE-2024-1709 |
| Group Profile | Linux System Utilities | Polkit pkexec | CVE-2021-4034 |
| Microsoft Products | MS Server Products | Exchange On-Prem | CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 |
| Group Profile, Network Edge | Pulse Secure / Ivanti | Ivanti EPM Cloud Services Appliance (CSA) | CVE-2021-44529 |
| Group Profile, Network Edge | SonicWall | SMA 100 | CVE-2019-7481 |
| Linux Components | System Utilities | Polkit pkexec | CVE-2021-4034 |
| Group Profile, Virtualization | VMware | vSphere Client | CVE-2021-21972 |
| Applications | Veritas | Veritas Backup Exec | CVE-2021-27876 |
| Applications | Veritas | Veritas Backup Exec | CVE-2021-27877 |
| Applications | Veritas | Veritas Backup Exec | CVE-2021-27878 |
| Microsoft Products | Windows | Secondary Logon Service | CVE-2016-0099 |
| Group Profile | Windows & MS Server Products | Exchange On-Prem | CVE-2021-31207, CVE-2021-34473, CVE-2021-34523 |
| Group Profile | Windows & MS Server Products | Secondary Logon Service | CVE-2016-0099 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Offence**
- **Xploit**

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

