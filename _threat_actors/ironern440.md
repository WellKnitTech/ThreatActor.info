---
layout: threat_actor
title: "IronErn440"
aliases: ["IronErn440"]
description: "IronErn440 is a threat actor tracked by Oligo Security for orchestrating the ShadowRay 2.0 campaign, an evolution of attacks since September 2023 exploiting CVE-2023-48022, a missing authentication fla"
permalink: /ironern440/
---

## Introduction
IronErn440 is a threat actor tracked by Oligo Security for orchestrating the ShadowRay 2.0 campaign, an evolution of attacks since September 2023 exploiting CVE-2023-48022, a missing authentication flaw in the Ray AI framework's Job Submission API. The actor submits malicious jobs to exposed Ray clusters (port 8265), deploying multi-stage Bash/Python payloads via GitHub/GitLab repositories like "ironern440-group" and "thisisforwork440-ops" to propagate worm-like, hijack NVIDIA GPUs for XMRig cryptomining, pivot laterally, create reverse shells, kill competing miners, limit CPU to 60%, and persist via cron jobs pulling updates every 15 minutes. Additional capabilities include DDoS via sockstress on port 3333 (targeting mining pools), region-specific malware (e.g., China checks), LLM-generated payloads, and use of tools like interact.sh for scanning over 230,500 public Ray servers; mitigations involve firewalling, authorization, and Anyscale's port checker.

## Activities and Tactics
*Information pending cataloguing.*

### Notable Campaigns
*Information pending cataloguing.*

### Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*This section is pending cataloguing. Check upstream sources for current IOCs.*

### IP Addresses
*Pending*

### File Hashes
*Pending*

### Domains
*Pending*

## Malware and Tools
- **China Chopper**: 
- **Miner-C**: 
- **Xploit**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

