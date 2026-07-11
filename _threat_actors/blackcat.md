---
layout: threat_actor
title: "BlackCat"
aliases: ["ALPHV","Noberus","BlackCat"]
description: "BlackCat (ALPHV) is ransomware written in Rust. The ransomware makes heavy use of plaintext JSON configuration files to specify the ransomware functionality. BlackCat has many advanced capabilities lik"
permalink: /blackcat/
---

## Introduction
BlackCat (ALPHV) is ransomware written in Rust. The ransomware makes heavy use of plaintext JSON configuration files to specify the ransomware functionality. BlackCat has many advanced capabilities like escalating privileges and bypassing UAC make use of AES and ChaCha20 or Salsa encryption, may use the Restart Manager, can delete volume shadow copies, can enumerate disk volumes and network shares automatically, and may kill specific processes and services. The ransomware exists for both Windows, Linux, and ESXi systems. Multiple extortion techniques are used by the BlackCat gang, such as exfiltrating victim data before the ransomware deployment, threats to release data if the ransomw is not paid, and distributed denial-of-service (DDoS) attacks.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No separately curated network indicators or file hashes are listed for this actor. Known exploited vulnerabilities appear in the **CISA Known Exploited Vulnerabilities (KEV)** section below.*

## Malware and Tools
- **BlackEnergy**: 
- **BLACKCOFFEE**: 
- **Blackshades**: 
- **BlackNix**: 
- **Windows Remote Desktop**: 
- **BlackHole**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [Ransomware Negotiator Gets 70 Months in Prison for Aiding BlackCat Attacks](https://thehackernews.com/2026/07/ransomware-negotiator-gets-70-months-in.html)
  The Hacker News - 2026-07-10T
- [Former ransomware negotiator gets 4 years for BlackCat attacks](https://www.bleepingcomputer.com/news/security/us-ransomware-negotiator-gets-4-years-in-prison-for-blackcat-attacks/)
  BleepingComputer - 2026-07-10T

## CISA Known Exploited Vulnerabilities (KEV)
*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*

| CVE ID | Vendor | Product | Date Added |
|-------|-------|--------|----------|
| CVE-2021-27876 | Veritas | Backup Exec Agent | 2023-04-07 |
| CVE-2021-27877 | Veritas | Backup Exec Agent | 2023-04-07 |
| CVE-2021-27878 | Veritas | Backup Exec Agent | 2023-04-07 |
| CVE-2022-24521 | Microsoft | Windows | 2022-04-13 |
| CVE-2016-0099 | Microsoft | Windows | 2022-03-03 |

