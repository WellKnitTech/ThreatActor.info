---
layout: threat_actor
title: "Operation PseudoManuscrypt"
aliases: ["Operation PseudoManuscrypt"]
description: "(Kaspersky) In June 2021, Kaspersky ICS CERT experts identified malware whose loader has some similarities to the Manuscrypt malware, which is part of the 'Lazarus Group, Hidden Cobra, Labyrinth Cholli"
permalink: /operation-pseudomanuscrypt/
---

## Introduction
(Kaspersky) In June 2021, Kaspersky ICS CERT experts identified malware whose loader has some similarities to the Manuscrypt malware, which is part of the 'Lazarus Group, Hidden Cobra, Labyrinth Chollima' APT group’s arsenal. In 2020, the group used Manuscrypt in attacks on defense enterprises in different countries. These attacks are described in the report “Lazarus targets defense industry with ThreatNeedle”. Curiously, the data exfiltration channel of the malware uses an implementation of the KCP protocol that has previously been seen in the wild only as part of the 'APT 41' group’s toolset. We dubbed the newly-identified malware PseudoManuscrypt. The PseudoManuscrypt loader makes its way onto user systems via a MaaS platform that distributes malware in pirated software installer archives. One specific case of the PseudoManuscrypt downloader’s distribution is its installation via the Glupteba botnet (whose main installer is also distributed via the pirated software installer distribution platform). This means that the malware distribution tactics used by the threat actor behind PseudoManuscrypt demonstrate no particular targeting. During the period from January 20 to November 10, 2021, Kaspersky products blocked PseudoManuscrypt on more than 35,000 computers in 195 countries of the world. Such a large number of attacked systems is not characteristic of the Lazarus group or APT attacks as a whole. Targets of PseudoManuscrypt attacks include a significant number of industrial and government organizations, including enterprises in the military-industrial complex and research laboratories.

## Activities and Tactics
**Country of Origin**: 🇨🇳 ["China"]





## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **PseudoManuscrypt**
- **PseudoManuscrypt**: 

## Attribution and Evidence
**Country of Origin**: ["China"]
*Additional attribution information pending cataloguing.*

## References
*References pending cataloguing.*

