---
layout: threat_actor
title: "GhostAction"
aliases: ["GhostAction"]
description: "Software supply chain campaign and its unnamed operator, first reported by GitGuardian in September 2025: malicious GitHub Actions workflows named \"Github Actions Security\" injected into compromised re"
permalink: /ghostaction/
---

## Introduction
Software supply chain campaign and its unnamed operator, first reported by GitGuardian in September 2025: malicious GitHub Actions workflows named "Github Actions Security" injected into compromised repositories exfiltrated CI/CD secrets, with 3,325 secrets stolen from 817 repositories. In October 2026 OpenSourceMalware reported a renewed wave and a second stage that no longer needs a CI runner: a .vscode/tasks.json launcher with a folderOpen trigger runs a Node.js credential stealer disguised as public/fonts/fa-solid-400.woff2, installs a cron job polling the operator's server, and is backed by a fallback workflow. OpenSourceMalware calls this stage a copycat of the DPRK PolinRider technique rather than an extension of it, and ties it to GhostAction through shared server infrastructure. A phishing kit on the lookalike domain my-github.com, harvesting credentials and silently authorizing an OAuth application with repo and workflow scopes, was reported on the same infrastructure.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Back Orifice**: 
- **Back Orifice 2000**: 
- **Ghost**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

## Recent News
*Latest articles from security news feeds mentioning this actor.*

- [GhostAction Hacking Wave Fizzles, but Attackers Lurk on in GitHub](https://www.darkreading.com/application-security/ghostaction-hacking-wave-fizzles-attackers-github)
  DarkReading — 2026-10-28

