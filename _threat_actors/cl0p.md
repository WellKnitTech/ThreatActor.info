---
layout: threat_actor
title: "Cl0p"
aliases: ["CHIMBORAZO", "Clop", "Hive0065", "Spandex Tempest", "TA505"]
description: "TA505 is a cyber criminal group that has been active since at least 2014. TA505 is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaign"
permalink: /cl0p/
---

## Introduction
TA505 is a cyber criminal group that has been active since at least 2014. TA505 is known for frequently changing malware, driving global trends in criminal malware distribution, and ransomware campaigns involving Clop.

## Activities and Tactics
**Targeted Sectors**: Technology, Healthcare, Financial, Government

**Country of Origin**: 🇷🇺 Russia

**Risk Level**: Critical

**First Seen**: 2019

**Last Activity**: 2025


## Notable Campaigns
### MOVEit Transfer campaign timeline
Curated Intelligence MOVEit Transfer Tracking tracks 74 public events for the 2023 MOVEit Transfer hacking campaign attributed to CL0P/Lace Tempest.

| Date | Type | Event | Source |
|---|---|---|---|
| 2023-05-31 | Resource | Initial Vendor Advisory, IOCs | [community.progress.com](https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023) |
| 2023-06-01 | Resource | IOCs, Sigma & YARA Rules by Nextron Systems | [twitter.com/cyb3rops](https://twitter.com/cyb3rops/status/1664306595432394752) |
| 2023-06-01 | Capabilities | Rapid7 Observed Exploitation of Critical MOVEit Transfer Vulnerability since 27th Mary 2023, IOCs | [rapid7.com](https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/) |
| 2023-06-01 | Infrastructure | GreyNoise has observed scanning activity for the login page of MOVEit Transfer located at /human.aspx as early as March 3rd, 2023 | [greynoise.io](https://www.greynoise.io/blog/progress-moveit-transfer-critical-vulnerability) |
| 2023-06-01 | Resource | CrowdStrike shared FQL rules | [r/crowdstrike](https://www.reddit.com/r/crowdstrike/comments/13xujxt/20230601_situational_awareness_active_intrusion/) |
| 2023-06-01 | Capabilities | Huntress analysis of the MOVEit Transfer vulnerability, IOCs | [huntress.com](https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response) |
| 2023-06-01 | Capabilities | TrustedSec MOVEit Transfer campaign analysis, IOCs | [trustedsec.com](https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/) |
| 2023-06-02 | Resource | YARA rules for the Web Shell | [github.com/AhmetPayaslioglu](https://github.com/AhmetPayaslioglu/YaraRules/blob/main/MOVEit_Transfer_Critical_Vulnerability.yara) |
| 2023-06-02 | Resource | Sigma rule for MOVEit exploitation | [github.com/tsale](https://github.com/tsale/Sigma_rules/blob/main/Threat%20Hunting%20Queries/MOVEit_exploitation.yml) |
| 2023-06-02 | Resource | MOVEit Web Shell Checker | [github.com/ZephrFish](https://github.com/ZephrFish/MoveIT-WebShellCheck) |
| 2023-06-02 | Information | CVE-2023-34362 in MOVEit Transfer added to the NIST National Vulnerability Database | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2023-34362) |
| 2023-06-02 | Capabilities | Mandiant campaign analysis, IOCs, YARA rules | [mandiant.com](https://www.mandiant.com/resources/blog/zero-day-moveit-data-theft) |
| 2023-06-02 | Information | CVE-2023-34362 in MOVEit Transfer added to the CISA Known Exploited Vulnerability (KEV) Database | [cisa.gov](https://www.cisa.gov/news-events/alerts/2023/06/02/cisa-adds-one-known-exploited-vulnerability-catalog) |
| 2023-06-02 | Adversary | Microsoft formally attributed the MOVEit Transfer campaign to the threat group called CL0P (aka Lace Tempest, FIN11, TA505) | [twitter.com/MsftSecIntel](https://twitter.com/MsftSecIntel/status/1665537730946670595) |
| 2023-06-02 | Victim | The University of Rochester mentions a "data breach, which resulted from a software vulnerability in a product provided by a third-party file transfer company, has affected the University and approximately 2,500 organizations worldwide." | [rochester.edu](https://www.rochester.edu/data-security/) |
| 2023-06-05 | Resource | Identifying Data Exfiltration in MOVEit Transfer Investigations | [crowdstrike.com](https://www.crowdstrike.com/blog/identifying-data-exfiltration-in-moveit-transfer-investigations/) |
| 2023-06-05 | Victim | Austrian Financial Market Authority (FMA) files stolen from MOVEit software | [ots.at](https://www.ots.at/presseaussendung/OTS_20230605_OTS0139/finanzmarktaufsichtsbehoerde-fma-von-moveit-hacker-angriff-betroffen?app=1) |
| 2023-06-05 | Victim | Zellis' MOVEit Transfer breached, impacting British Airways, BBC, Boots, and Aer Lingus, potentially others | [therecord.media](https://therecord.media/bbc-british-airways-hit-by-zellis-zero-day) |
| 2023-06-05 | Adversary | Clop ransomware claims responsibility for MOVEit extortion attacks via a ransom note on their leak site | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/clop-ransomware-claims-responsibility-for-moveit-extortion-attacks/) |
| 2023-06-06 | Victim | University of Rochester and the Government of Nova Scotia are the first known MoveIT victims in North America | [therecord.media](https://therecord.media/rochester-university-nova-scotia-move-it-victims) |
| 2023-06-06 | Capabilities | Unit42's analysis of MOVEit attacks, also observed attacks starting on 27 May, additional IOCs | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/threat-brief-moveit-cve-2023-34362/) |
| 2023-06-07 | Adversary | Clop ransomware tells those affected to email them before 14 June or stolen data will be published | [BBC](https://www.bbc.com/news/technology-65829726) |
| 2023-06-07 | Victim | BORN Ontario announces MOVEit breach | [bornontario.ca](https://www.bornontario.ca/en/news/cybersecurity-incident-moveit.aspx) |
| 2023-06-07 | Adversary/Capabilities | FBI & CISA joint advisory on CL0P, details about other TA505 campaigns, and other incidents such as the GoAnywhere attacks, IOCs, YARAs | [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) |
| 2023-06-07 | Victim/Capabilities | SentinelOne's campaign analysis, hunting queries, IOCs | [sentinelone.com](https://www.sentinelone.com/blog/moveit-transfer-exploited-to-drop-file-stealing-sql-shell/) |
| 2023-06-07 | Victim | Extreme Networks declares having learned that their instance of MOVEit Transfer tool was impacted by a malicious act | [computerweekly.com](https://www.computerweekly.com/news/366539753/Extreme-Networks-emerges-as-victim-of-Clop-MOVEit-attack) |
| 2023-06-08 | Capabilities | Kroll's Timeline of the campaign (dating it back to 2021), IOCs | [kroll.com](https://www.kroll.com/en/insights/publications/cyber/clop-ransomware-moveit-transfer-vulnerability-cve-2023-34362) |
| 2023-06-08 | Victim | Synlad issues a press release acknowledging being a victim of Cl0p's MOVEit campaign | [synlab.fr](https://www.synlab.fr/acutalites/news/cybersecurite-communique-de-synlab-france/) |
| 2023-06-09 | Resource | Progress Software issues a new patch covering new vulnerabilities (CVE-2023-35036) | [progress.com](https://www.progress.com/security/moveit-transfer-and-moveit-cloud-vulnerability) |
| 2023-06-09 | Victim | Illinois government among victims of global ransomware attack | [chicagotribune.com](https://www.chicagotribune.com/politics/ct-illinois-government-ransomware-attack-20230609-anvuvxf6lbdubev4xkgpyt3upe-story.html) |
| 2023-06-09 | Victim | Minnesota Department of Education hit by cybersecurity attack | [cbsnews.com](https://www.cbsnews.com/minnesota/news/minnesota-department-of-education-hit-by-cybersecurity-attack-95000-students-data-breached/) |
| 2023-06-09 | Victim | HSE states no more than 20 people's data breached in cyber-attack | [hse.ie](https://www.hse.ie/eng/services/news/media/pressrel/hse-statement1.html) |
| 2023-06-09 | Capabilities | Horizon3AI's analysis of the MOVEit Transfer campaign, accompanied by a Proof-of-Concept (PoC) for CVE-2023-34363, and IOCs | [horizon3.ai](https://www.horizon3.ai/moveit-transfer-cve-2023-34362-deep-dive-and-indicators-of-compromise/) |
| 2023-06-09 | Victim | Landal informs guests about a data breach (MOVEit) | [landal.com](https://newsroom.landal.com/landal-informeert-gasten-over-mogelijk-datalek/) |
| 2023-06-12 | Victim | Ofcom (the UK’s communications regulator) and Ernst & Young (EY), one of the 'Big 4' accounting firms | [bbc.co.uk](https://www.bbc.co.uk/news/technology-65877210) |
| 2023-06-13 | Victim | Transport for London (TfL) is warning 13,000 staff - half its entire workforce - that their details have been stolen by CL0P, via following the Zellis payroll outsourcer MOVEit Transfer hack | [twitter.com/gazthejourno](https://twitter.com/gazthejourno/status/1668594412782252038) |
| 2023-06-13 | Victim | Prudential Assurance Malaysia Berhad (PAMB) and Prudential BSN Takaful Berhad (PruBSN) can confirm that we are among many companies around the world that have been affected by the global MOVEit data-theft attack | [prudential.com.my](https://www.prudential.com.my/en/our-company-newsroom/announcements/moveit-cyber-security-incident/) |
| 2023-06-13 | Victim | State of Missouri Issues Statement on Recent Global Cyberattack | [oa.mo.gov](https://oa.mo.gov/commissioners-office/news/state-missouri-issues-statement-recent-global-cyberattack) |
| 2023-06-14 | Victim | Victims Listed on CL0P's leak site: 1st Source Bank, Datasite LLC, First National Bankers Bankshares Inc (FNBB), Green Shield (health services organization in Canada, only payer-provider in Canada), Heidelberger, Leggett & Platt, National Student Clearinghouse, ÖKK Kranken- und Unfallversicherungen AG, Putnam Investments, United HealthCare Services Inc, Shell, and the University of Georgia | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/14%20June%20Leaks.png) |
| 2023-06-14 | Victim | Johns Hopkins University | [Baltimore Sun](https://web.archive.org/web/20230615154230/https://www.baltimoresun.com/maryland/baltimore-city/bs-md-ci-johns-hopkins-hospital-university-data-breach-20230615-jzew75i24ffynivcenegtc3dda-story.html) |
| 2023-06-15 | Victim | Victims added to CL0P's leak site: healthequity[.]com, synlab[.]fr, cuanswers[.]com, navaxx[.]lu, delawarelife[.]com, 316fiduciaries[.]com, enzo[.]com, careservicesllc[.]com, genericon[.]at, brault[.]us, aplusfcu[.]org, barharbor[.]bank, powerfi[.]org, eastwestbank[.]com | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/15%20June%20Leaks.png) |
| 2023-06-15 | Victim | BleepingComputer receives PR communications from victims of CL0P | [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/clop-ransomware-gang-starts-extorting-moveit-data-theft-victims/) |
| 2023-06-15 | Victim | US Department of Energy: Oak Ridge Associated Universities and Waste Isolation Pilot Plant (New Mexico) announce MOVEit breaches | [federalnewsnetwork.com](https://federalnewsnetwork.com/cybersecurity/2023/06/energy-department-among-several-federal-agencies-hit-by-moveit-breach/) |
| 2023-06-15 | Resource | Progress Software issues an advisory of a 3rd vulnerability (No CVE or patch) | [progress.com](https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-15June2023) |
| 2023-06-15 | Victim | Louisiana Office of Motor Vehicles | [la.gov](https://nextsteps.la.gov) |
| 2023-06-16 | Resource | Progress Software issues fix of 3rd vulnerability (No CVE) | [progress.com](https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-15June2023) |
| 2023-06-16 | Victim | Oregon Department of Transportation (ODOT) announces MOVEit breach | [oregon.gov](https://web.archive.org/web/20230616150508/https://www.oregon.gov/odot/DMV/Pages/Data_Breach.aspx) |
| 2023-06-16 | Victim | marti[.]com (Marti Group, Switzerland, Construction), pragroup[.]no (PRA Group, Norway, Finance (Debt)), columbiabank[.]com / umpquabank[.]com (Umpqua Bank, USA, Finance), umsystem[.]edu (University Of Missouri System, USA, Education, icsystem[.]com (IC System, USA, Finance (Debt)), arburg[.]com (ARBURG, Germany, Manufacturing (Plastics processing machines)), bostonglobe[.]com (Boston Globe, USA, Newspaper), cncbinternational[.]com (China CITIC Bank International Limited, Hong Kong, Finance), stiwa[.]com (Stiwa Group, Austria, Automation), cegedim[.]com (Cegedim, France, Tech/outsourcing services), aon[.]com (Aon PLC, Ireland, Professional Services), nuance[.]com (Nuance, USA, AI Tech) | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/16%20June%20Leaks.png) |
| 2023-06-16 | Adversary | CL0P claims on their leak site they "deleted all government data," are "only financial motivated [sic]," and, "do not care anything about politicis [sic]" | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/16%20June%20CL0P%20statement.png) |
| 2023-06-16 | Capabilities | CrowdStrike reports on a second critical MOVEit vulnerability (CVE-2023-35708) being exploited in the wild | [r/crowdstrike](https://www.reddit.com/r/crowdstrike/comments/14av35u/20230616_situational_awareness_second_critical/) |
| 2023-06-19 | Victim | palig.com (Panamerican), gesa.com (Gesa - USA - Finance (Credit Union)), telos.com (Telos - USA - Cyber Security), scu.edu (Santa Clara University - USA), skillsoft.com (Skillsoft - USA - Training programs), creelighting.com (IDEAL Industries Inc), nortonlifelock.com (Norton), stockmanbank.com (Stockman Bank - Montana, USA - Finance), baesman.com (Customer Relationship Management (CRM) software - USA), emsshi.com (Electronic Management Support and Services, Inc. - Hawaii, USA), cbeservices.com (CBE Services - Australia - Construction), zurich.com.br (Zurich Seguros - Brazil - Insurance) | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/19%20June%20Leaks.png) |
| 2023-06-21 | Victim | Cegedim didn't find any sign of compromise until June 9th, when they discovered new IOCs | [lemagit.fr](https://www.lemagit.fr/actualites/366542375/Campagne-MOVEit-Cl0p-commence-a-divulguer-les-donnees-volees-a-Cegedim) |
| 2023-06-21 | Adversary | CL0P wrote a statement saying the BBC is spreading propaganda for their own interest. They also claim they have deleted data from "30 companies that are government" and reasserted they are all about business and not politics. | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/21%20June%20CL0P%20statement.png) |
| 2023-06-23 | Victim | andesaservices.com (Andesa Services, Insurance, US), sony.com (Sony, Technology/Media, Japan), ey.com (Ernst & Young, Consulting, UK), pwc.com (PricewaterhouseCoopers, Consulting, UK), guscanada.ca (Global University Systems (GUS) Canada, Education, Canada) | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/23%20June%20Leaks.png) |
| 2023-06-23 | Victim | Harris Health System | [abc13.com](https://abc13.com/moveit-breach-harris-health-system-cyberattack-houston-patient-info-exposed/13419649/) |
| 2023-06-23 | Victim | NYC DoE | [ny.chalkbeat.org](https://ny.chalkbeat.org/2023/6/23/23772027/nyc-student-data-breach-security-moveit-department-education-hack) |
| 2023-06-26 | Victim | Wilton Reassurance Company | [apps.web.maine.gov](https://apps.web.maine.gov/online/aeviewer/ME/40/f74d0aa0-eb90-46c1-8093-58aabe65a9d6.shtml) |
| 2023-06-27 | Victim | MSAMLIN[.]COM, WERUM[.]COM, SE[.]COM (Schneider Electric), SIEMENS-ENERGY[.]COM, UCLA[.]EDU (University of California, Los Angeles), ABBVIE[.]COM, PROSKAUER[.]COM, KIRKLAND[.]COM (KIRKLAND & ELLIS LLP), KOTAKLIFE[.]COM, STARMOUNTLIFE[.]COM, JACKSON[.]COM, CARESOURCE[.]COM, SAPIENS[.]COM, ENSTARGROUP[.]COM, COGNIZANT[.]COM, DELTADENTAL[.]COM, CPIAI[.]COM, DARLINGCONSULTING[.]COM | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/27%20June%20Leaks.png) |
| 2023-06-27 | Victim | Allegiant Air discloses exposure to MOVEit breach on 1 June 2023 | [twitter.com/_bettercyber_](https://twitter.com/_bettercyber_/status/1673660038324318211) |
| 2023-06-28 | Victim | Bloomberg reports that US Department of Health and Human Services (HHS) is impacted by the MOVEit breach due to a third-party incident. Records from more than 15 million compromised. | [bloomberg.com](https://www.bloomberg.com/news/articles/2023-06-28/us-health-department-ensnared-by-moveit-hacking-campaign#xj4y7vzkg) |
| 2023-06-29 | Victim | KLGATES[.]COM, CITYNATIONAL[.]COM, HARRINGTONCOMPANY[.]COM, SOVOS[.]COM, RHENUS[.]GROUP, VERICAST[.]COM, IRONBOW[.]COM, DIGITALINSIGHT[.]COM, FISGLOBAL[.]COM, HORNBECKOFFSHORE[.]COM, CLICKSGROUP[.]CO[.]ZA, TRELLISWARE[.]COM, ENCORECAPITAL[.]COM | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/29%20June%20Leaks.png) |
| 2023-07-04 | Information | Infosecurity Magazine Podcast on the CL0P campaign | [infosecurity-magazine.com](https://www.infosecurity-magazine.com/podcasts/infosec-mag-pod-july-2023/) |
| 2023-07-06 | Information | Progress Software has released a Service Pack to address three newly disclosed vulnerabilities (CVE-2023-36934, CVE-2023-36932, CVE-2023-36933) in MOVEit Transfer | [community.progress.com](https://community.progress.com/s/article/MOVEit-Transfer-Service-Pack-July-2023) |
| 2023-07-07 | Information | Huntress' Joe Slowik blogs about Reflecting on the MOVEit Exploitation | [huntress.com](https://www.huntress.com/blog/move-it-on-over-reflecting-on-the-moveit-exploitation) |
| 2023-07-10 | Victim | DURR[.]COM, BARRICK[.]COM, BRADYID[.]COM, TDECU[.]ORG, UNITEDREGIONAL[.]ORG, KYBURZDRUCK[.]CH, CIENA[.]COM, NORGREN[.]COM, MERATIVE[.]COM, QUORUMFCU[.]ORG, TRANSPERFECT[.]COM, NEWERATECH[.]COM, BANKWITHUNITED[.]COM, CADENCEBANK[.]COM, WOLTERSKLUWER[.]COM, NETSCOUT[.]COM, PAYCOR[.]COM, ENERGYTRANSFER[.]COM, DELARUE[.]COM, TDAMERITRADE[.]COM, L8SOLUTIONS[.]CO[.]UK, UOFLHEALTH[.]ORG, KERNAGENCY[.]COM, FISCDP[.]COM, MARYKAY[.]COM, CYTOMX[.]COM, USG[.]EDU, AMERICANNATIONAL[.]COM, BCDTRAVEL[.]COM, AUTOZONE[.]COM, CROWE[.]COM | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/1st%20Week%20July%20Leaks.png) |
| 2023-07-10 | Victim | Deutsche Bank, Postbank, Comdirect, ING via Majorel | [handelsblatt.com](https://www.handelsblatt.com/finanzen/banken-versicherungen/banken/hackerangriff-datenleck-trifft-auch-kunden-der-direktbanken-ing-und-comdirect/29249908.html) |
| 2023-07-10 | Adversary | CL0P writes about an exchange they had with TD Ameritrade. The victim seemingly tried to negotiate with CL0P and offered $4 million USD to pay the ransom. The initial ransom demand is currently unknown, but likely higher. CL0P confirms that they stole the data from a "file transfer" server (MOVEit) and claims to have stolen "262gb + archives". | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/CL0P%20TD%20Ameritrade%20Dispute.png) |
| 2023-07-10 | Capabilities | Sophos analyzes CL0P's 2023 data extortion campaigns targeting GoAnywhere, PaperCut, and MOVEit servers | [news.sophos.com](https://news.sophos.com/en-us/2023/07/10/clop-at-the-top/) |
| 2023-07-11 | Victim | RADISSONHOTELSAMERICAS[.]COM, WESTAT[.]COM, JPRMP[.]COM, FMFCU[.]ORG, JHU[.]EDU, VISIONWARE[.]CA, UMASSMED[.]EDU, VRM[.]DE, SMA[.]DE, RICOHACUMEN[.]COM, EMERSON[.]COM, TOMTOM[.]COM, BAM[.]COM[.]GT, PIONEERELECTRONICS[.]COM, RITEAID[.]COM, ARVATO[.]COM, SCCU[.]COM, AGILYSYS[.]COM, KALEAERO[.]COM, CONSOLENERGY[.]COM | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/11%20July%20Leaks.png) |
| 2023-07-12 | Victim | RADIUSGS[.]COM, CLEARESULT[.]COM, HONEYWELL[.]COM, NASCO[.]COM, JACKENTERTAINMENT[.]COM, AINT[.]COM, AMCTHEATRES[.]COM, SLB[.]COM, GRIPA[.]ORG | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/12%20July%20Leaks.png) |
| 2023-07-12 | Victim | Tennet | [security.nl](https://www.security.nl/posting/803144/TenneT+slachtoffer+van+datalek+na+aanval+op+MOVEit+Transfer-server) |
| 2023-07-14 | Victim | Jones Lang LaSalle (JLL) Human Resources | [twitter.com](https://twitter.com/BrettCallow/status/1679521710155116544) |
| 2023-07-19 | Victim | Updated Additional Victims: PAYCOM[.]COM, MOTHERSON[.]COM, ASPENTECH[.]COM, DISCOVERY[.]COM, SHUTTERFLY[.]COM, ROCHESTER[.]EDU, YAKULT[.]COM[.]PH, UFCU[.]ORG, VOSS[.]NET, JTI[.]COM, REPSOLSINOPECUK[.]COM, PINNACLETPA[.]COM, ARIETISHEALTH[.]COM, SCHNABEL-ENG[.]COM, MYCWT[.]COM, HESS[.]COM, PRGX[.]COM, GRACE[.]COM, NOTABLEFRONTIER[.]COM, TJX[.]COM, VITESCO-TECHNOLOGIES[.]COM, VALMET[.]COM, FMGL[.]COM[.]AU, DESMI[.]COM, CFINS[.]COM, COMPUCOM[.]COM, SIERRAWIRELESS[.]COM, RCI[.]COM, AA[.]COM, JONASFITNESS[.]COM, COMREG[.]IE, SMC3[.]COM, ITT[.]COM, ALLEGIANTAIR[.]COM, OFCOM[.]ORG[.]UK, ESTEELAUDER[.]COM, BLUEFIN[.]COM, VENTIVTECH[.]COM, DMA[.]US, PWCCLINETSANDDOCUMENTS[.]COM | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/3rd%20Week%20July%20Leaks.png) |
| 2023-07-19 | Victim | CL0P created a dedicated domain to publish the data they claim they stole from the PwC MOVEit server | [CL0P Data Leak Site](https://github.com/curated-intel/MOVEit-Transfer/blob/main/Images/PwC%20Leak%20Domain.png) |

## Tactics, Techniques, and Procedures (TTPs)
### Ransomware Vulnerability Matrix observations

| Category | Vendor | Product | CVEs |
|---|---|---|---|
| File Transfer Servers, Group Profile | Accellion | Accellion File Transfer Appliance | CVE-2021-27101, CVE-2021-27102, CVE-2021-27103, CVE-2021-27104 |
| File Transfer Servers, Group Profile | Cleo | Cleo VLTrader, Harmony, LexiCom | CVE-2024-55956 |
| File Transfer Servers, Group Profile | Fortra | GoAnywhere Managed File Transfer | CVE-2023-0669 |
| Applications, Group Profile | Oracle | E-Business | CVE-2025-61882 |
| Group Profile | PaperCut | PaperCut Application Server | CVE-2023-27350, CVE-2023-27351 |
| File Transfer Servers, Group Profile | Progress Software | MOVEit | CVE-2023-34362 |
| File Transfer Servers, Group Profile | SolarWinds | SolarWinds Serv-U FTP | CVE-2021-35211 |
| Applications | SysAid | SysAid On-Prem | CVE-2023-47246 |

## Notable Indicators of Compromise (IOCs)
*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*

## Malware and Tools
### Ransomware Tool Matrix observations

| Category | Observed tools |
|---|---|
| OffSec | Cobalt Strike, PowerShell Empire, TinyMet |

## Attribution and Evidence
**Country of Origin**: Russia
*Additional attribution information pending cataloguing.*

## References
[1] [MITRE ATT&CK](https://attack.mitre.org/groups/G0092)
   MITRE ATT&CK entry

