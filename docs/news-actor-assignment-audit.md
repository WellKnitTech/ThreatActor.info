# News actor↔article assignment audit (PR #167)

- Corpus: **596** archived items (2026-08 … 2026-10)
- Assignments audited: **114**
- Keep: **84**
- Remove: **30**
- After applying audit + canonical remaps: **84** assignments
- Keep-set equality: missing=0 extra=0

## Removed assignments

| Actor | Date | Source | Matched alias | Title | Reason |
|---|---|---|---|---|---|
| APT41 | 2026-09-22 | The Hacker News | `anonymous` | WordPress Comment2Shell Flaw Can Turn Anonymous Comment XSS Into RCE via Admin Session | APT41 alias "Anonymous" collided with "Anonymous Comment" (WordPress XSS) |
| Apocalypse | 2026-08-29 | Wired | `apocalypse` | The Cybersecurity Apocalypse Is Coming in ‘Months,’ AI Giants Warn | metaphorical "Cybersecurity Apocalypse", not Apocalypse ransomware |
| Aurora | 2026-08-31 | The Hacker News | `aurora` | Aurora Ransomware Operators Use Cursor AI in Attacks Against 10 Targets | duplicate of Aurora Ransomware match; bare Aurora is too ambiguous |
| Bluesky | 2026-08-18 | TechCrunch | `bluesky` | Bluesky says its recent outage was caused by another DDoS attack | Bluesky social network outage/DDoS, not Bluesky ransomware |
| Brazilian | 2026-09-08 | DarkReading | `brazilian` | Cybercriminals Hack Brazilian Government Servers to Host Phishing Sites | nationality adjective ("Brazilian Government"), not a group named Brazilian |
| Defender | 2026-08-12 | BleepingComputer | `defender` | New Microsoft Defender 'ShieldBreak' zero-day grants SYSTEM privileges | Microsoft Defender product, not the ransomware actor |
| Defender | 2026-08-12 | The Hacker News | `defender` | ShieldBreak Zero-Day PoC Claims Microsoft Defender Patch Bypass With SYSTEM Access | Microsoft Defender product, not the ransomware actor |
| Defender | 2026-08-17 | BleepingComputer | `defender` | Microsoft working on Defender patch for ShieldBreak zero-day | Microsoft Defender product, not the ransomware actor |
| Defender | 2026-09-09 | BleepingComputer | `defender` | New Microsoft Defender 'ShieldCrash' zero-day grants SYSTEM access | Microsoft Defender product, not the ransomware actor |
| Defender | 2026-09-09 | The Hacker News | `defender` | Researcher Drops New Microsoft Defender PoC Showing ShieldBreak Patch Can Be Bypassed | Microsoft Defender product, not the ransomware actor |
| Defender | 2026-09-22 | BleepingComputer | `defender` | New Windows Defender zero-day blocks Microsoft antivirus updates | Microsoft Defender product, not the ransomware actor |
| Defender | 2026-09-22 | The Hacker News | `defender` | Researcher Drops BigDiskBuster Zero-Day PoC That Blocks Microsoft Defender Updates | Microsoft Defender product, not the ransomware actor |
| District | 2026-10-02 | BleepingComputer | `district` | Frontline Education breach exposes school district employee data | common noun ("school district"), not District ransomware |
| Eclipse | 2026-09-10 | DarkReading | `eclipse` | Nightmare-Eclipse Strikes Again With 'ShieldCrash' Windows Exploit | Nightmare-Eclipse exploit/research moniker, not Eclipse ransomware |
| Falcon | 2026-09-03 | The Hacker News | `falcon` | Researcher Releases FalconFlank PoC Showing Privilege Escalation in CrowdStrike Falcon | CrowdStrike Falcon product PoC, not the Falcon ransomware actor |
| Lazarus | 2026-08-12 | The Hacker News | `lazarus` | Lazarus Exploits Windows Zero-Day to Gain SYSTEM Access and Deploy Backdoor | curated name duplicate of Lazarus Group (canonical YAML actor) |
| Lazarus | 2026-08-12 | BleepingComputer | `lazarus` | Lazarus hackers exploited Windows zero-day to target defense firms | curated name duplicate of Lazarus Group (canonical YAML actor) |
| Lazarus | 2026-10-21 | BleepingComputer | `lazarus` | Lazarus hackers use post-quantum cryptography for malware delivery | curated name duplicate of Lazarus Group (canonical YAML actor) |
| Lazarus | 2026-10-27 | The Hacker News | `lazarus` | Lazarus Abuses South Korean Security Software to Deploy Malware Using Post-Quantum Encryption | curated name duplicate of Lazarus Group (canonical YAML actor) |
| Nightmare | 2026-09-10 | DarkReading | `nightmare` | Nightmare-Eclipse Strikes Again With 'ShieldCrash' Windows Exploit | idiom or exploit moniker, not Nightmare ransomware group |
| Nightmare | 2026-10-15 | Wired | `nightmare` | ‘Nightmare Scenario’: Zero-Click Spyware Is Infecting Phones via Targeted Ads | idiom or exploit moniker, not Nightmare ransomware group |
| Operation C-Major | 2026-09-18 | The Hacker News | `transparent tribe` | Transparent Tribe Deploys New Rust Backdoor Using Private GitHub Repositories for C2 | campaign-style record matched only via Transparent Tribe alias; article is about Transparent Tribe |
| Payload | 2026-08-26 | The Hacker News | `payload` | Critical Gitea RCE Actively Exploited as Reported Attack Drops Miner-Like Payload | generic malware term "payload", not a named actor |
| Payload | 2026-09-25 | The Hacker News | `payload` | PamStealer macOS Malware Adds Live C2 Payload Decryption and Multi-Layer Persistence | generic malware term "payload", not a named actor |
| Rhysida | 2026-08-31 | BleepingComputer | `rhysida` | Berlin confirms data theft after Rhysida ransomware attack claims | curated-name duplicate of YAML actor rhysida |
| Sanctions | 2026-08-25 | The Hacker News | `sanctions` | U.S. Sanctions Iran-Linked Hackers Behind Critical Infrastructure Breaches | U.S. government sanctions action, not an actor named Sanctions |
| Spring | 2026-08-31 | Unit 42 | `spring` | Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams | "Spring Ring" campaign/feature title; not about Spring ransomware group |
| Void Manticore | 2026-09-17 | The Hacker News | `handala hack` | Iran-Linked Handala Hack Tied to HEAVYGRAM Telegram Backdoor That Can Steal Passwords | Handala article; Void Manticore matched only via overlapping "Handala Hack" alias |
| cyclops | 2026-09-14 | DarkReading | `cyclops` | 'Sandworm' Chains Cisco Vulnerabilities to Deploy Cyclops Blink | Cyclops Blink malware name; article is about Sandworm, not Cyclops actor |
| hermes | 2026-09-28 | The Hacker News | `hermes` | Carbonato Botnet Compromises Docker Hosts to Deploy Telegram-Controlled Hermes AI Agent | Hermes AI Agent (tool/product), not Hermes ransomware |

## Kept assignments

| Actor | Date | Source | Matched alias | Title | Reason |
|---|---|---|---|---|---|
| APT28 | 2026-08-28 | The Hacker News | `apt28` | APT28-Linked HOOKEDGE Backdoor Targets European Government and Diplomatic Organizations | title/alias clearly refers to this threat actor |
| APT28 | 2026-10-20 | The Hacker News | `apt28` | Russian APT28 Breaches NATO Naval Shipbuilder in NATO Country, Deploys New Reflective Loader | title/alias clearly refers to this threat actor |
| APT29 | 2026-10-16 | SentinelOne | `apt29` | How SentinelOne Blocked APT29's CaptiveCrunch Campaign | title/alias clearly refers to this threat actor |
| APT41 | 2026-10-22 | Securelist | `apt41` | How APT41 revived the BlackLotus bootkit to attack diplomatic organizations in Central Asia | title names APT41 |
| Aurora Ransomware | 2026-08-31 | The Hacker News | `aurora ransomware` | Aurora Ransomware Operators Use Cursor AI in Attacks Against 10 Targets | title names Aurora Ransomware |
| Callisto | 2026-09-29 | The Hacker News | `star blizzard` | Russia's Star Blizzard Targets 100+ Organizations With Fake Event Invites to Deliver Backdoor | borderline: Callisto catalog aliases include Star Blizzard (same cluster) |
| Callisto | 2026-09-30 | DarkReading | `star blizzard` | Russia's Star Blizzard Ditches ClickFix to Widen Phishing Net | borderline: Callisto catalog aliases include Star Blizzard (same cluster) |
| Caramel Tsunami | 2026-10-15 | The Hacker News | `candiru` | Citizen Lab Traces Zero-Click Candiru Spyware Infections at Al Jazeera to Targeted Online Ads | Candiru is a catalog alias of Caramel Tsunami |
| Caramel Tsunami | 2026-10-16 | BleepingComputer | `candiru` | Targeted ads installed Candiru spyware in zero-click attacks | Candiru is a catalog alias of Caramel Tsunami |
| Clop | 2026-08-17 | BleepingComputer | `clop ransomware` | Philips and GE investigating Clop ransomware data theft claims | title names Clop ransomware |
| Conti | 2026-09-11 | BleepingComputer | `conti ransomware` | Conti ransomware gang member sentenced to 4 years in prison | title/alias clearly refers to this threat actor |
| Dark Caracal | 2026-08-26 | DarkReading | `dark caracal` | Dark Caracal Adds New Malware to Cyber Espionage Arsenal | title/alias clearly refers to this threat actor |
| Deadeye Jackal | 2026-10-30 | The Record | `syrian electronic army` | Syrian Electronic Army hacker gets prison time for attacks on Western targets | title/alias clearly refers to this threat actor |
| Flax Typhoon | 2026-10-09 | The Hacker News | `flax typhoon` | Flax Typhoon Exploits Five Flaws as CISA Sets October 11 Deadline for Federal Agencies | title/alias clearly refers to this threat actor |
| GhostAction | 2026-10-19 | The Hacker News | `ghostaction` | GhostAction Attackers Plant Credential Stealer Disguised as Font in 94 GitHub Repositories | title/alias clearly refers to this threat actor |
| GhostAction | 2026-10-28 | DarkReading | `ghostaction` | GhostAction Hacking Wave Fizzles, but Attackers Lurk on in GitHub | title/alias clearly refers to this threat actor |
| GhostEmperor | 2026-09-17 | DarkReading | `famoussparrow` | China's FamousSparrow APT Spies on US Politics in Latin America | borderline: catalog lists FamousSparrow as alias of this actor; title is about FamousSparrow |
| GhostEmperor | 2026-09-17 | The Hacker News | `famoussparrow` | China-Aligned FamousSparrow Deploys SparroWocky Backdoor Across Latin America | borderline: catalog lists FamousSparrow as alias of this actor; title is about FamousSparrow |
| Handala | 2026-09-17 | The Hacker News | `handala` | Iran-Linked Handala Hack Tied to HEAVYGRAM Telegram Backdoor That Can Steal Passwords | title/alias clearly refers to this threat actor |
| INC Ransom | 2026-09-23 | Beazley Security Labs Articles | `inc ransomware` | An INC Ransomware Affiliate’s BYOVD Buffet | title/alias clearly refers to this threat actor |
| INC Ransom | 2026-10-20 | The Hacker News | `inc ransomware` | Qilin and INC Ransomware Groups Exploit Palo Alto Networks Flaw to Bypass MFA | title/alias clearly refers to this threat actor |
| JadePuffer | 2026-09-28 | The Hacker News | `jadepuffer` | JADEPUFFER-Linked Attackers Used Compromised Service Principals to Delete Azure Resources | title/alias clearly refers to this threat actor |
| Killsec | 2026-10-01 | DarkReading | `killsec` | Alleged KillSec Ransomware Mastermind a 16-Year-Old | title/alias clearly refers to this threat actor |
| Killsec | 2026-10-01 | The Hacker News | `killsec` | Police Arrest 16-Year-Old Suspected of Running KillSec, Seize Ransomware Leak Site and Servers | title/alias clearly refers to this threat actor |
| Killsec | 2026-10-01 | BleepingComputer | `killsec` | Police dismantle KillSec ransomware gang allegedly led by 16-year-old | title/alias clearly refers to this threat actor |
| Lazarus Group | 2026-08-12 | The Hacker News | `lazarus` | Lazarus Exploits Windows Zero-Day to Gain SYSTEM Access and Deploy Backdoor | title/alias clearly refers to this threat actor |
| Lazarus Group | 2026-08-12 | BleepingComputer | `lazarus` | Lazarus hackers exploited Windows zero-day to target defense firms | title/alias clearly refers to this threat actor |
| Lazarus Group | 2026-10-21 | BleepingComputer | `lazarus` | Lazarus hackers use post-quantum cryptography for malware delivery | title/alias clearly refers to this threat actor |
| Lazarus Group | 2026-10-27 | The Hacker News | `lazarus` | Lazarus Abuses South Korean Security Software to Deploy Malware Using Post-Quantum Encryption | title/alias clearly refers to this threat actor |
| Luna Moth | 2026-10-09 | Check Point | `luna moth` | How Luna Moth Runs Data Extortion Like a Business | title/alias clearly refers to this threat actor |
| Medusa | 2026-08-19 | BleepingComputer | `medusa ransomware` | CISA: Medusa ransomware hit over 500 critical infrastructure orgs | title/alias clearly refers to this threat actor |
| Mustang Panda | 2026-08-14 | The Hacker News | `mustang panda` | Mustang Panda Adds Signed Windows Rootkit to CoolClient Backdoor for Stealth | title/alias clearly refers to this threat actor |
| Nefilim | 2026-10-28 | BleepingComputer | `nefilim` | Nefilim and Hive ransomware affiliate gets 70 months in prison | title/alias clearly refers to this threat actor |
| Qilin | 2026-09-11 | The Hacker News | `qilin ransomware` | Cisco FMC Flaws Exploited to Steal Credentials and Deploy Qilin Ransomware | title/alias clearly refers to this threat actor |
| Qilin | 2026-10-09 | BleepingComputer | `qilin ransomware` | Germany arrests alleged core Qilin ransomware member after extradition | title/alias clearly refers to this threat actor |
| REF7707 | 2026-08-13 | DarkReading | `jewelbug` | 'Jewelbug' APT Balances State Espionage & Cryptocurrency Theft | Jewelbug is a catalog alias of REF7707 |
| Ryuk ransomware | 2026-09-23 | BleepingComputer | `ryuk ransomware` | Ryuk ransomware member sentenced to 24 months in prison | title/alias clearly refers to this threat actor |
| SALTY SPIDER | 2026-09-02 | The Hacker News | `sality` | Authorities Turn Sality's P2P Network Against Itself, Cutting Off New Malware Payloads | Sality is a catalog alias of SALTY SPIDER (same botnet family) |
| SALTY SPIDER | 2026-09-02 | BleepingComputer | `sality` | Sality botnet infrastructure dismantled in joint global takedown | Sality is a catalog alias of SALTY SPIDER (same botnet family) |
| SafePay | 2026-10-21 | BleepingComputer | `safepay ransomware` | CISA: SafePay ransomware hit over 600 critical infrastructure orgs | title/alias clearly refers to this threat actor |
| Salt Typhoon | 2026-09-17 | DarkReading | `famoussparrow` | China's FamousSparrow APT Spies on US Politics in Latin America | borderline: catalog lists FamousSparrow as alias of this actor; title is about FamousSparrow |
| Salt Typhoon | 2026-09-17 | The Hacker News | `famoussparrow` | China-Aligned FamousSparrow Deploys SparroWocky Backdoor Across Latin America | borderline: catalog lists FamousSparrow as alias of this actor; title is about FamousSparrow |
| Sandworm | 2026-08-11 | BleepingComputer | `sandworm` | Sandworm hackers target IT pros with trojanized WireGuard VPN client | title/alias clearly refers to this threat actor |
| Sandworm | 2026-09-14 | DarkReading | `sandworm` | 'Sandworm' Chains Cisco Vulnerabilities to Deploy Cyclops Blink | title/alias clearly refers to this threat actor |
| Sandworm Team | 2026-08-11 | BleepingComputer | `sandworm` | Sandworm hackers target IT pros with trojanized WireGuard VPN client | borderline: dual catalog entry (Sandworm Team) for Sandworm-named articles |
| Sandworm Team | 2026-09-14 | DarkReading | `sandworm` | 'Sandworm' Chains Cisco Vulnerabilities to Deploy Cyclops Blink | borderline: dual catalog entry (Sandworm Team) for Sandworm-named articles |
| ShinyHunters | 2026-08-24 | BleepingComputer | `shinyhunters` | ReliaQuest confirms failed data-theft attack after ShinyHunters breach | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-08-28 | BleepingComputer | `shinyhunters` | McKesson discloses breach after ShinyHunters claims patient data theft | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-03 | DarkReading | `shinyhunters` | What We Missed: Did ShinyHunters 'Breach' ReliaQuest? | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-08 | BleepingComputer | `shinyhunters` | ShinyHunters hackers claim breach of Florida "DAVID" DMV database | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-19 | BleepingComputer | `shinyhunters` | ShinyHunters hacks Clop leak site, threatens to extort ransomware gang | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-22 | TechCrunch | `shinyhunters` | Hacking group ShinyHunters claims it breached the FBI, stole agents’ and applicants’ data | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-22 | BleepingComputer | `shinyhunters` | ShinyHunters claims FBI hack, data theft in PeopleSoft zero-day breach | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-23 | The Hacker News | `shinyhunters` | ShinyHunters Claims FBI Breach, Says It Stole Data on Agents and Job Applicants | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-28 | KrebsOnSecurity | `shiny hunters` | Dutch Police Arrest ‘Reformed’ Hacker in Shiny Hunters Investigation | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-28 | BleepingComputer | `shinyhunters` | Dutch police confirm arrest in ShinyHunters hacking investigation | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-09-29 | TechCrunch | `shinyhunters` | Dutch police arrest ShinyHunters hacker accused of planning two murders | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-10-03 | BleepingComputer | `shinyhunters` | ShinyHunters hacker reportedly detained in Jordan, aiding FBI | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-10-06 | The Hacker News | `shinyhunters` | FBI Removes Accenture Contractor After Patch Failure Led to ShinyHunters Breach | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-10-09 | BleepingComputer | `shinyhunters` | FBI arrests another suspected ShinyHunters hacker after agency breach | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-10-10 | BleepingComputer | `shinyhunters` | Cyber exec arrested in case allegedly tied to ShinyHunters hackers | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-10-19 | KrebsOnSecurity | `shinyhunters` | Feds Suspect Ransom Negotiator Ran ShinyHunters Extortion Site | title/alias clearly refers to this threat actor |
| ShinyHunters | 2026-10-28 | The Hacker News | `shinyhunters` | ShinyHunters-Exploited Oracle PeopleSoft Zero-Day Turns Out to Be Three Chained Flaws | title/alias clearly refers to this threat actor |
| SideCopy | 2026-09-22 | The Hacker News | `sidecopy` | SideCopy Broadens India Targeting to Academia With ReverseRAT Spear-Phishing | title/alias clearly refers to this threat actor |
| Star Blizzard | 2026-09-29 | The Hacker News | `star blizzard` | Russia's Star Blizzard Targets 100+ Organizations With Fake Event Invites to Deliver Backdoor | title/alias clearly refers to this threat actor |
| Star Blizzard | 2026-09-30 | DarkReading | `star blizzard` | Russia's Star Blizzard Ditches ClickFix to Widen Phishing Net | title/alias clearly refers to this threat actor |
| Storm-0940 | 2026-10-22 | DarkReading | `storm-0940` | Microsoft Links Storm-0940 to ConnectWise Supply Chain Attack | title/alias clearly refers to this threat actor |
| TA419 | 2026-10-04 | The Hacker News | `ta419` | China-Aligned TA419 Targets U.S. AI Policy Experts With Microsoft AitM Phishing | title/alias clearly refers to this threat actor |
| TeamPCP | 2026-08-27 | The Hacker News | `teampcp` | Alleged TeamPCP Hackers Charged in Australia Over Major Supply Chain Attacks | title/alias clearly refers to this threat actor |
| TeamPCP | 2026-08-27 | BleepingComputer | `teampcp` | Australia arrests alleged TeamPCP hackers behind supply-chain attacks | title/alias clearly refers to this threat actor |
| TeamPCP | 2026-08-27 | KrebsOnSecurity | `teampcp` | Two Alleged ‘TeamPCP’ Hackers Arrested in Australia | title/alias clearly refers to this threat actor |
| TeamPCP | 2026-08-28 | Ars Technica | `teampcp` | Authorities arrest 2 alleged members of prolific hacking group TeamPCP | title/alias clearly refers to this threat actor |
| TraderTraitor | 2026-09-21 | The Hacker News | `jade sleet` | Jade Sleet Linked to Indian IT Provider Breach With FLATROOF and ROOFDECK Backdoors | Jade Sleet is a catalog alias of TraderTraitor |
| Transparent Tribe | 2026-09-18 | The Hacker News | `transparent tribe` | Transparent Tribe Deploys New Rust Backdoor Using Private GitHub Repositories for C2 | title/alias clearly refers to this threat actor |
| UAC-0099 | 2026-09-01 | The Hacker News | `uac-0099` | Russia-Aligned UAC-0099 Plants Nuclear Weapon Prompt in Malware to Disrupt AI Analysis | title/alias clearly refers to this threat actor |
| UNC1549 | 2026-08-26 | The Hacker News | `nimbus manticore` | Nimbus Manticore Expands Toolset With TWOSTROKE-Like Backdoor and SSH Tunneler | Nimbus Manticore is a catalog alias of UNC1549 |
| UNC3569 | 2026-09-11 | The Hacker News | `unc3569` | China-Linked UNC3569 Exploited Sogou Input Method Flaw to Deploy GRAYRABBIT Backdoor | title/alias clearly refers to this threat actor |
| Volt Typhoon | 2026-10-28 | The Hacker News | `volt typhoon` | Volt Typhoon Used Covert Silent Train Network in Four Zero-Day Exploitation Campaigns | title/alias clearly refers to this threat actor |
| Volt Typhoon | 2026-10-28 | BleepingComputer | `volt typhoon` | Volt Typhoon hides zero-day attacks using 'Silent Train' framework | title/alias clearly refers to this threat actor |
| WageMole | 2026-09-19 | BleepingComputer | `waterplum` | North Korean WaterPlum hackers infected 30,000 devices worldwide | WaterPlum is a catalog alias of WageMole |
| Warlock | 2026-10-01 | DarkReading | `warlock` | Warlock Ransomware Hits Large Spanish, Portuguese Orgs | title/alias clearly refers to this threat actor |
| Warlock | 2026-10-02 | BleepingComputer | `warlock` | Warlock ransomware breach SharePoint in water, telecom operator attacks | title/alias clearly refers to this threat actor |
| Warlock | 2026-10-03 | The Hacker News | `warlock` | Warlock Exploits SharePoint Flaws to Disable Security Tools and Deploy Ransomware | title/alias clearly refers to this threat actor |
| rhysida | 2026-08-31 | BleepingComputer | `rhysida` | Berlin confirms data theft after Rhysida ransomware attack claims | title names Rhysida ransomware |

## Matcher rules added from failures

1. **Ambiguous stoplist expansion** — never index: `defender`, `payload`, `falcon`, `bluesky`, `brazilian`, `district`, `sanctions`, `apocalypse`, `spring`, `hermes`, `cyclops`, `eclipse`, `nightmare`, `aurora`, `anonymous`.
2. **Curated → YAML canonical names** — `Lazarus`→`Lazarus Group`, `Clop`→`Cl0p`, `Rhysida`→`rhysida`.
3. **Operation-style actors** — names matching `/\AOperation\b/i` require their own primary name in the title.
4. **Foreign-primary containment** — if an alias properly contains another actor primary (e.g. `handala hack` contains `handala`), require the matched actor primary in the title. Exact shared aliases remain allowed.

## Borderline keeps

- FamousSparrow → GhostEmperor and Salt Typhoon (catalog alias overlap)
- Star Blizzard → Callisto (shared cluster alias)
- Sality → SALTY SPIDER; Candiru → Caramel Tsunami; WaterPlum → WageMole; Jade Sleet → TraderTraitor; Jewelbug → REF7707; Nimbus Manticore → UNC1549
- Sandworm Team dual catalog entry on Sandworm-titled articles
