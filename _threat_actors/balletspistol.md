---
layout: threat_actor
title: "Balletspistol"
aliases: ["Balletspistol"]
description: "BalletsPistol is a Python-based ransomware strain distributed via GitHub. An investigative report from June 2025 reveals its delivery through a malicious ISO file hosted on a now‑removed public GitHub "
permalink: /balletspistol/
---

## Introduction
BalletsPistol is a Python-based ransomware strain distributed via GitHub. An investigative report from June 2025 reveals its delivery through a malicious ISO file hosted on a now‑removed public GitHub repository tinextacyber.com+1 . The infection chain begins when the ISO (named Invoice.iso) is downloaded and mounted, revealing a batch script (MAIN.BAT) and supporting components—including a password-protected ZIP and shortcut (.lnk) for execution. The malware performs privilege escalation (via UAC bypass using fodhelper.exe), persistence via registry and scheduled tasks, and then extracts an executable from the ZIP to commence the main payload. This binary encrypts user files with a hybrid AES + RSA scheme, adding the .iDCVObno extension to encrypted files; it also drops ransom notes (RESTORE-MY-FILES.TXT or .HTA) and changes the victim’s wallpaper.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
*Information pending cataloguing.*

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

