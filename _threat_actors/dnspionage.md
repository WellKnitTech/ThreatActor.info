---
layout: threat_actor
title: "DNSpionage"
aliases: ["COBALT EDGEWATER", "DNSpionage"]
description: "Cisco Talos recently discovered a new campaign targeting Lebanon and the United Arab Emirates (UAE) affecting .gov domains, as well as a private Lebanese airline company. Based on our research, it's cl"
permalink: /dnspionage/
---

## Introduction
Cisco Talos recently discovered a new campaign targeting Lebanon and the United Arab Emirates (UAE) affecting .gov domains, as well as a private Lebanese airline company. Based on our research, it's clear that this adversary spent time understanding the victims' network infrastructure in order to remain under the radar and act as inconspicuous as possible during their attacks. Based on this actor's infrastructure and TTPs, we haven't been able to connect them with any other campaign or actor that's been observed recently. This particular campaign utilizes two fake, malicious websites containing job postings that are used to compromise targets via malicious Microsoft Office documents with embedded macros. The malware utilized by this actor, which we are calling "DNSpionage," supports HTTP and DNS communication with the attackers. In a separate campaign, the attackers used the same IP to redirect the DNS of legitimate .gov and private company domains. During each DNS compromise, the actor carefully generated Let's Encrypt certificates for the redirected domains. These certificates provide X.509 certificates for TLS free of charge to the user. We don't know at this time if the DNS redirections were successful. In this post, we will break down the attackers' methods and show how they used malicious documents to attempt to trick users into opening malicious websites that are disguised as "help wanted" sites for job seekers. Additionally, we will describe the malicious DNS redirection and the timeline of the events.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **name**: 
- **name**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

