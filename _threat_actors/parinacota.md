---
layout: threat_actor
title: "PARINACOTA"
aliases: ["Wine Tempest", "PARINACOTA"]
description: "One actor that has emerged in this trend of human-operated attacks is an active, highly adaptive group that frequently drops Wadhrama as payload.  PARINACOTA impacts three to four organizations every w"
permalink: /parinacota/
---

## Introduction
One actor that has emerged in this trend of human-operated attacks is an active, highly adaptive group that frequently drops Wadhrama as payload.
 PARINACOTA impacts three to four organizations every week and appears quite resourceful: during the 18 months that we have been monitoring it, we have observed the group change tactics to match its needs and use compromised machines for various purposes, including cryptocurrency mining, sending spam emails, or proxying for other attacks. The group’s goals and payloads have shifted over time, influenced by the type of compromised infrastructure, but in recent months, they have mostly deployed the Wadhrama ransomware.
The group most often employs a smash-and-grab method, whereby they attempt to infiltrate a machine in a network and proceed with subsequent ransom in less than an hour. There are outlier campaigns in which they attempt reconnaissance and lateral movement, typically when they land on a machine and network that allows them to quickly and easily move throughout the environment.
PARINACOTA’s attacks typically brute forces their way into servers that have Remote Desktop Protocol (RDP) exposed to the internet, with the goal of moving laterally inside a network or performing further brute-force activities against targets outside the network. This allows the group to expand compromised infrastructure under their control. Frequently, the group targets built-in local administrator accounts or a list of common account names. In other instances, the group targets Active Directory (AD) accounts that they compromised or have prior knowledge of, such as service accounts of known vendors.
The group adopted the RDP brute force technique that the older ransomware called Samas (also known as SamSam) infamously used. Other malware families like GandCrab, MegaCortext, LockerGoga, Hermes, and RobbinHood have also used this method in targeted ransomware attacks. PARINACOTA, however, has also been observed to adapt to any path of least resistance they can utilize. For instance, they sometimes discover unpatched systems and use disclosed vulnerabilities to gain initial access or elevate privileges.

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
*Information pending cataloguing.*

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*
