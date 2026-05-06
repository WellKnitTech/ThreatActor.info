---
layout: threat_actor
title: "Yashma"
aliases: ["Yashma"]
description: "Cisco Talos has identified a new, previously unknown threat actor of Vietnamese origin conducting a ransomware operation that began at least on June 4, 2023.  The ongoing attack utilizes a variant of t"
permalink: /yashma/
---

## Introduction
Cisco Talos has identified a new, previously unknown threat actor of Vietnamese origin conducting a ransomware operation that began at least on June 4, 2023. The ongoing attack utilizes a variant of the Yashma Ransomware, likely targeting multiple geographical areas and mimicking the characteristics of WannaCry. The threat actor uses an unusual technique to deliver the ransom note, as instead of embedding the ransom note strings in the binary, the actor downloads the ransom note from a GitHub repository controlled by ,the actor by executing an embedded batch file. Talos stated that this threat actor targets victims in English-speaking countries, Bulgaria, China, and Vietnam, as the GitHub account of the actor "nguyenvientphat" contains ransomware notes written in the languages of these countries. The presence of the ransom note may indicate that the actor intends to expand its geographical area of operation. The company also stated that the threat actor may have Vietnamese origin because the GitHub account name and email contact in the ransom notes fake the name of a legitimate organization. The ransom note also asks victims to contact between 19:00 and 23:00 UTC +07:00, coinciding with the Vietnam time zone. A difference was also identified in the Vietnamese language ransom note, as it begins with "Sorry, your file is encrypted!" compared to the other notes that state "Oops, your files are encrypted!". By saying "sorry," the threat actor may intend to show greater sensitivity to victims in Vietnam, indicating that the attackers themselves are Vietnamese. Talos further mentioned that the threat actor started the campaign around June 4, 2023, as they joined GitHub and created a public repository called "Ransomware." In the repository, the threat actor added text files of ransom notes in five languages: English, Bulgarian, Vietnamese, simplified Chinese, and traditional Chinese. The note presents the email address "nguyenvietphat[.]n@gmail[.]com," for victims to contact them. At the time of analysis, no Bitcoin was observed in the wallet, and the ransom note did not specify an amount, indicating that the ransomware operation could still be in its early stages. The threat actor deployed a variant of the Yashma ransomware, which they compiled on June 4, 2023. It is worth noting that Yashma is a 32-bit executable written in .NET and a renamed version of the Chaos Ransomware V5, which appeared in May 2022. In the variant, most of Yashma's features remained unchanged and were described by BlackBerry security researchers, with some notable modifications. The ransomware stores the ransom note text as strings in the binary, but this Yashma variant executes an embedded batch file, which contains the commands to download the ransom note from the actor-controlled GitHub repository. This modification avoids endpoint detection solutions and antivirus software, which typically detect embedded ransom note strings in the binary. Previous versions of Yashma established persistence on the victim's machine in the Run registry key and by dropping a Windows shortcut file pointing to the executable path of the ransomware in the startup folder. The identified variant also established persistence in the Run registry key. However, it was modified to create a ".url" favorites file in the startup folder pointing to the executable located in "%AppData%\Roaming\svchost.exe." Additionally, the threat actor chose to maintain Yashma's anti-recovery capability in this variant. After encrypting a file, the ransomware wipes the content of the original unencrypted files, writes a single "?" character, and then deletes the file. This technique makes it more difficult for incident responders and forensic analysts to recover deleted files from the victim's hard drive.

## Activities and Tactics
*Information pending cataloguing.*

## Notable Campaigns
*Information pending cataloguing.*

## Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
- **BlackEnergy**: 
- **China Chopper**: 
- **Unknown Logger**: 
- **Chaos**: 
- **BLACKCOFFEE**: 
- **Blackshades**: 
- **BlackNix**: 
- **Batch NET**: 
- **Virus RAT**: 
- **Windows Remote Desktop**: 

## Attribution and Evidence
*Information pending cataloguing.*

## References
*References pending cataloguing.*

