---
layout: threat_actor
title: "SWEED"
aliases: ["SWEED","Sweed"]
description: "Cisco Talos recently identified a large number of ongoing malware distribution campaigns linked to a threat actor we're calling \"SWEED,\" including such notable malware as Formbook, Lokibot and Agent Te"
permalink: /sweed/
---

## Introduction
Cisco Talos recently identified a large number of ongoing malware distribution campaigns linked to a threat actor we're calling "SWEED," including such notable malware as Formbook, Lokibot and Agent Tesla. Based on our research, SWEED — which has been operating since at least 2017 — primarily targets their victims with stealers and remote access trojans. SWEED remains consistent across most of their campaigns in their use of spear-phishing emails with malicious attachments. While these campaigns have featured a myriad of different types of malicious documents, the actor primarily tries to infect its victims with a packed version of Agent Tesla — an information stealer that's been around since at least 2014. The version of Agent Tesla that SWEED is using differs slightly from what we've seen in the past in the way that it is packed, as well as how it infects the system. In this post, we'll run down each campaign we're able to connect to SWEED, and talk about some of the actor's tactics, techniques and procedures (TTPs).

## Activities and Tactics
**Country of Origin**: 🏳️ ["[Unknown]"]





## Notable Campaigns
- **2017**
- **2018-01**
- **2018-04**
- **2018-05**
- **2019**
- **Beginning in 2019**
- **In April 2018**
- **In May 2018**
- **In early 2018**
- **One of the earliest SWEED campaigns Talos identified dates back to 2017. In this attack**
- **SWEED began making use of a previously disclosed Office exploit. One of the documents featured in these email campaigns was notable because it was a PowerPoint document (PPXS). Code contained inside one of the slides triggers an exploit for CVE-2017-8759**
- **Steganography**
- **a remote code execution bug in Microsoft Office that is commonly observed being leveraged in malicious documents used in commodity malware distribution.**
- **a remote code execution vulnerability in Microsoft .NET framework.**
- **and then attached those ZIPs to emails. The attachments usually had file names similar to “Java_Updater.zip” or “P-O of Jun2017.zip”.**
- **campaigns being conducted by SWEED began leveraging another vulnerability in Microsoft Office: CVE-2017-11882**
- **https://blog.talosintelligence.com/2019/07/sweed-agent-tesla.html**
- **the JAR was directly attached to emails and used file names such as “Order_2018.jar”. The purpose of the JAR was to obtain information about the infected system and facilitate the download of a packed version of Agent Tesla.**
- **the actors placed droppers inside of ZIP archives**
- **the campaigns associated with SWEED began leveraging malicious Office macros. As with previous attacks**
- **they are leveraging spear-phishing emails and malicious attachments to initiate the infection process.**
- **we observed that SWEED began leveraging Java-based droppers. Similar to previous campaigns**

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **Agent.btz**
- **Trojan.Karagany**
- **RemoteCMD**
- **Trojan.Mebromi**
- **Remote Utilities**
- **RemotePC**
- **CrossRat**
- **Agent Tesla**: 
- **Formbook**: 
- **LokiBot**: 
- **RDP**: 

## Attribution and Evidence
**Country of Origin**: ["[Unknown]"]
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

