---
layout: default
title: Source Attribution
permalink: /attribution/
---

# Source Attribution

ThreatActor.info is a research index built from public, attributed sources plus analyst-reviewed enrichment. This page summarizes the source families used by the site, how we use them, and where source-specific attribution appears.

## How attribution is handled

- Actor and malware pages show a **Source Attribution** panel when structured source metadata is available.
- Actor pages also list additional provenance sources when a profile combines multiple datasets.
- Imported records keep source names, upstream URLs, retrieval timestamps, license fields when available, and source-specific attribution text in `_data/actors/*.yml`.
- Linked reports, advisories, articles, and external research remain owned by their original publishers.
- The site is for educational and research purposes only; verify source material independently before relying on it.

## Source inventory

| Source | How it is used | Attribution and license notes |
|--------|----------------|-------------------------------|
| [MITRE ATT&CK](https://attack.mitre.org/) ([STIX data](https://github.com/mitre-attack/attack-stix-data)) | Group descriptions; ATT&CK IDs; technique/tactic/campaign/mitigation/software pages and actor relationships (`ttps`, `software`, `campaigns`). | MITRE permission notice appears on affected pages and in structured actor metadata for records imported from STIX. |
| [MISP Galaxy](https://github.com/MISP/misp-galaxy) | Threat actor identities, aliases, descriptions, references, and relationship context. | Imported MISP Galaxy records are marked as sourced from the MISP Galaxy threat-actor cluster and treated as CC0 licensed where that source metadata is present. |
| [RansomLook](https://www.ransomlook.io/) and [RansomLook repository](https://github.com/RansomLook/RansomLook) | Ransomware group names, aliases, descriptions, and reference-backed enrichment. | RansomLook-derived data is attributed as RansomLook and marked CC BY 4.0 with the Creative Commons license URL in structured source metadata. |
| [Malpedia by Fraunhofer FKIE](https://malpedia.caad.fkie.fraunhofer.de/) | Malware-family metadata and actor relationship enrichment. | Malpedia-derived metadata is attributed to Malpedia/Fraunhofer FKIE and carries the Malpedia legal URL and CC BY-NC-SA 3.0 license metadata when imported. |
| [ETDA / ThaiCERT Threat Group Cards](https://apt.etda.or.th/) | Threat group cards, aliases, malware, operations, and timeline hints. | Imported ETDA/ThaiCERT data is attributed as derived from the public Threat Group Cards and adapted for research enrichment. |
| [tropChaud Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) | Offline snapshot under `data/imports/categorized-adversary-ttps/`; merged MITRE group–technique links with ETDA pivot metadata (victim industry/country, motivation). Powers `/api/categorized_*` JSON and `/categorized-adversary-ttps/`. | MIT-licensed dataset; upstream merges **MITRE ATT&CK** (see MITRE permission notice) and **ETDA Threat Group Cards** (copyright ETDA as cited upstream). Attribution text appears on the pivots page and matching actor panels. |
| [APTnotes](https://github.com/aptnotes/data) | Report-index provenance, source links, and chronology hints. | APTnotes is used as a report index; copyright in linked reports remains with the original publishers. |
| [APT Groups & Operations](https://apt.threattracking.com/) | Alias, operation, malware, and report crosswalk enrichment. | The public spreadsheet is attributed as a secondary research aid and crosswalk, not as a sole authoritative source. |
| [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/KEV) | Known-exploited vulnerability context linked to selected actor pages. | CISA KEV is attributed as a public government catalog; KEV entries are treated as vulnerability context, not as standalone actor attribution. |
| [BushidoToken Breach Report Collection](https://github.com/BushidoUK/Breach-Report-Collection) | Reviewed breach-report links for existing actors. | The collection is attributed as a report index; linked reports remain owned by their original publishers. |
| [BushidoUK Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) | Reviewed ransomware tradecraft and tool observations for existing actors. | The matrix is attributed as a secondary ransomware tradecraft reference, not sole attribution evidence. |
| [BushidoUK Ransomware Vulnerability Matrix](https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix) | Reviewed CVE and exploitation observations for existing ransomware actors. | The matrix is attributed as a secondary exploitation reference, not sole attribution evidence. |
| [BushidoUK Russian APT Tool Matrix](https://github.com/BushidoUK/Russian-APT-Tool-Matrix) | Reviewed Russian APT tool observations for existing actors. | The matrix is attributed as a secondary Russian APT tradecraft reference, not sole attribution evidence. |
| [Curated Intelligence MOVEit Transfer Tracking](https://github.com/curated-intel/MOVEit-Transfer) | CL0P/MOVEit campaign event timeline enrichment. | The tracking repository is attributed for event collection; linked reports remain owned by their original publishers. |
| [BreachHQ Threat Actors](https://breach-hq.com/threat-actors) | Snapshot-backed secondary actor index used for reviewed name/alias matching and cross-source triage. | BreachHQ data is attributed to Beyond Identity; this project treats it as a secondary reference index and preserves source provenance rather than sole attribution evidence. |
| [EternalLiberty](https://github.com/StrangerealIntel/EternalLiberty) | Alias cross-reference enrichment. | EternalLiberty is attributed as a secondary alias crosswalk, not a sole authoritative source. |
| Analyst notes and manual entries | Temporary coverage for subjects not yet covered by automated public sources. | Manual entries are labeled as analyst notes or manual curation and should be superseded when a reviewed automated source becomes available. |
| Security news and reference fetchers | Optional article/reference discovery utilities, including MISP references and security news feeds. | These utilities collect links and summaries for review; source publishers retain ownership of their articles and reports. |

## Operational controls

- Importers fetch snapshots into local cache paths and apply reviewed mappings before changing canonical actor YAML.
- Importers avoid build-time network dependencies; generated pages and APIs are deterministic from committed content.
- Source-specific provenance is preserved under each actor's `provenance` block when enrichment comes from multiple sources.
- Volatile infrastructure and raw leak-site material are not automatically imported.

For implementation details, see the [importer documentation](/docs/importers.html), [data flow notes](/docs/data-flows.html), and [schema documentation](/docs/schema.html).
