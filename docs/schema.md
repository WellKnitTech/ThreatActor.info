# ThreatActor.info YAML Schema

This document describes the schema for `_data/actors/*.yml` - the single source of truth for all threat actor data.

## Overview

```yaml
- name: "APT28"
  aliases: ["Fancy Bear", "Sofacy Group"]
  url: "/apt28"
  description: "APT28 is a Russian cyber espionage group..."
  country: "Russia"
  sector_focus: ["Government", "Defense"]
  first_seen: "2007"
  last_activity: "2024"
  last_updated: "2026-04-27"
  risk_level: "High"
  source_name: "MITRE ATT&CK"
  source_attribution: "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
  
  # Extended fields (optional)
  campaigns:
  ttps:
  iocs:
  malware:
  references:
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Primary name of the threat actor |
| `aliases` | Array | Known aliases for this actor |
| `url` | String | URL slug for the page (e.g., "/apt28") |
| `description` | String | Brief description (max 200 chars for front matter) |

## Classification Fields

| Field | Type | Description | Example |
|------|------|-------------|---------|
| `country` | String | Country of origin | "Russia", "China", "Iran" |
| `risk_level` | String | Risk assessment | "Critical", "High", "Medium", "Low" |
| `sector_focus` | Array | Target sectors | ["Government", "Defense", "Healthcare"] |
| `first_seen` | String | Year first observed | "2007" |
| `last_activity` | String | Year last observed | "2024" |
| `last_updated` | String | Optional editorial review/update date in YYYY-MM-DD format | "2026-04-27" |

## Extended Fields

### campaigns

Named campaigns with dates and descriptions.

```yaml
campaigns:
  - name: "Democratic National Committee Hack"
    date: "2016"
    description: "Infiltration of the DNC and release of stolen emails"
    target_sectors: ["Government", "Politics"]
  - name: "German Parliament Attack"
    date: "2015"
    description: "Cyber attack on the German Bundestag"
```

### ttps

MITRE ATT&CK technique mappings.

```yaml
ttps:
  - technique_id: "T1566.001"
    technique_name: "Spearphishing Attachment"
    description: "Use of targeted email campaigns with malicious attachments"
  - technique_id: "T1059.001"
    technique_name: "PowerShell"
    description: "Use of PowerShell for execution"
```

### iocs

Indicators of Compromise.

```yaml
iocs:
  ips:
    - "45.32.22.62"
    - "45.17.43.250"
  md5_hashes:
    - "0777EA1D01DAD6DC261A6B602205E2C8"
  sha256_hashes:
    - "e1d8f6d72a43b21a0b0c5f46307d02f2e9a59d3522827b0e7b768135ed3a92c1"
  domains:
    - "api-metrics-collector.com"
  urls:
    - "https://malicious-site.com/payload.exe"
```

### malware

Associated malware families and tools.

```yaml
malware:
  - name: "X-Agent"
    description: "Custom backdoor used for data exfiltration"
  - name: "X-Tunnel"
    description: "Custom tunneling tool for C2 communication"
```

### references

External source links.

```yaml
references:
  - url: "https://attack.mitre.org/groups/G0007/"
    title: "MITRE ATT&CK - APT28"
    source: "MITRE"
    date: "2024"
```

## Threat actor Markdown: IOC extraction (`generate-indexes`)

[`scripts/generate-indexes.rb`](../scripts/generate-indexes.rb) builds IOC indexes from **`_threat_actors/*.md`**, not from YAML `iocs:` alone.

Requirements:

| Requirement | Detail |
|-------------|--------|
| Section heading | Exact text **`## Notable Indicators of Compromise (IOCs)`** (level 2). Other headings are ignored by the extractor. |
| List shape | Indicators as **bullet lines** (`-` or `*`). Lines that are not list items are not parsed as IOC rows. |
| Subsections | Optional **`### Category`** headings split IOCs into groups (display/grouping). |
| Skipped regions | Lists under headings skipped by the generator (e.g. **`Sources`**) are not extracted—avoid nesting IOC bullets only under those. |

Importer-generated content should mirror this structure when **`generate-pages.rb`** emits IOC sections so downstream **`ioc_lookup.json`**, IOC shards, and IOC hubs populate.

## Source Attribution Fields

Every actor should make its source lineage clear enough for readers and maintainers to verify origin, licensing, and review context.

| Field | Type | Description |
|-------|------|-------------|
| `source_name` | String | Primary structured source for the actor identity or the latest importer that owns the actor record |
| `source_attribution` | String | Required attribution or usage statement displayed on the actor page |
| `source_record_url` | String | Optional upstream record URL for the exact actor profile |
| `source_license` | String | Optional license name when the source publishes one |
| `source_license_url` | String | Optional URL for the source license or terms |

### provenance

Use `provenance` for additional source-specific data that supplements the primary actor record. Each nested source key should preserve enough metadata to audit where the imported observations came from.

```yaml
provenance:
  ransomware_tool_matrix:
    source_name: "BushidoUK Ransomware Tool Matrix"
    source_repository: "https://github.com/BushidoUK/Ransomware-Tool-Matrix"
    source_dataset_url: "https://api.github.com/repos/BushidoUK/Ransomware-Tool-Matrix/git/trees/main?recursive=1"
    source_attribution: "Tool observations were reviewed from the BushidoUK Ransomware Tool Matrix..."
    source_retrieved_at: "2026-04-28T01:51:36Z"
    source_files: ["Tools/Offsec.md"]
```

Recommended nested attribution fields:

| Field | Type | Description |
|-------|------|-------------|
| `source_name` | String | Human-readable source name when the key is not self-explanatory |
| `source_repository` | String | Repository or publisher landing page |
| `source_dataset_url` | String | Exact snapshot, raw data, API, or dataset URL used by the importer |
| `source_record_url` | String | Exact upstream actor, malware, campaign, or report-index record URL |
| `source_attribution` | String | Source-specific attribution text for supplemental observations |
| `source_license` | String | License name when distinct from the primary actor source |
| `source_license_url` | String | License or terms URL |
| `source_retrieved_at` | String | UTC retrieval timestamp for the source snapshot |
| `source_files` | Array | Source files consulted inside a repository snapshot |

The public site renders top-level attribution and visible nested provenance entries. Keep `source_attribution` factual and specific: name the upstream source, link or name the publisher, state whether the data is used as identity data, a report index, or secondary enrichment, and preserve source license requirements.

## Importers

### MITRE ATT&CK

```bash
# Preview import
ruby scripts/import-mitre.rb

# Apply import
ruby scripts/import-mitre.rb --write
```

The MITRE importer fetches from:
- https://github.com/mitre-attack/attack-stix-data

### Page Generator

```bash
# Generate all pages from YAML
ruby scripts/generate-pages.rb

# Preview without writing
ruby scripts/generate-pages.rb --dry-run

# Force regenerate all (overwrite enriched)
ruby scripts/generate-pages.rb --force
```

The generator:
- Reads `_data/actors/*.yml`
- Creates `_threat_actors/*.md` for each actor
- Preserves manually-enriched pages (detected by content markers)

## Best Practices

1. **Edit YAML, not MD files** - The MD files are regenerated
2. **Use the generator** - Don't manually edit pages
3. **Add attribution** - Include source links, license fields, and provenance for verification
4. **Keep descriptions brief** - Max 200 chars for front matter
5. **Validate after changes** - Run `ruby scripts/validate-content.rb`

## Validation

```bash
# Validate content
ruby scripts/validate-content.rb

# Full validation
bash scripts/validate.sh
```