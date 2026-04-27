# Importers

This repository supports source importers that update `_data/actors/*.yml` and regenerate `_threat_actors/*.md` without introducing build-time network dependencies.

## RansomLook Importer

`scripts/import-ransomlook.rb` is the first importer.

It is designed for automated snapshot + apply flow:

1. Fetch a local snapshot from RansomLook.
2. Review or apply the snapshot to the repo.

Reviewed name and rename handling lives in `data/imports/ransomlook/mapping_overrides.yml`.

### Why this workflow exists

- Jekyll builds must stay offline and deterministic.
- Canonical repo inputs remain `_data/actors/*.yml` and `_threat_actors/*.md`.
- Imported metadata is snapshot-backed, attribution-preserving, and intended for deterministic regeneration of all actor pages.

## Automation Policy

- Treat importer snapshots in `data/imports/*` as the operational cache layer.
- Regenerate pages with `ruby scripts/generate-pages.rb --force` after source updates.
- Regenerate APIs with `ruby scripts/generate-indexes.rb` in the same run.
- Use `ruby scripts/evaluate-source-deltas.rb` to enforce update thresholds before publishing large changes.

## Commands

Fetch a public snapshot:

```bash
ruby scripts/import-ransomlook.rb fetch --output data/imports/ransomlook/2026-04-25 --limit 25
```

Fetch a full groups export when you have a RansomLook API key:

```bash
RANSOMLOOK_API_KEY="YOUR_API_KEY" ruby scripts/import-ransomlook.rb fetch --export --output data/imports/ransomlook/2026-04-25
```

Preview what a snapshot would do:

```bash
ruby scripts/import-ransomlook.rb plan --snapshot data/imports/ransomlook/2026-04-25
```

Use a custom override file if needed:

```bash
ruby scripts/import-ransomlook.rb plan --snapshot data/imports/ransomlook/2026-04-25 --overrides data/imports/ransomlook/mapping_overrides.yml
```

Apply the snapshot:

```bash
ruby scripts/import-ransomlook.rb import --snapshot data/imports/ransomlook/2026-04-25
```

Write a machine-readable review report:

```bash
ruby scripts/import-ransomlook.rb plan --snapshot data/imports/ransomlook/2026-04-25 --report-json tmp/ransomlook-report.json
```

## MISP Galaxy Importer

`scripts/import-misp-galaxy.rb` imports threat actor data from the MISP Galaxy threat-actor cluster.

Source: https://github.com/MISP/misp-galaxy (Apache 2.0 / CC0 licensed)

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-misp-galaxy.rb fetch --output data/imports/misp-galaxy/2026-04-26
```

Preview changes:

```bash
ruby scripts/import-misp-galaxy.rb plan --snapshot data/imports/misp-galaxy/2026-04-26
```

Apply import:

```bash
ruby scripts/import-misp-galaxy.rb import --snapshot data/imports/misp-galaxy/2026-04-26
```

Limit to specific actors:

```bash
ruby scripts/import-misp-galaxy.rb plan --snapshot data/imports/misp-galaxy/2026-04-26 --actor APT1 --actor APT28
```

Only create new actors:

```bash
ruby scripts/import-misp-galaxy.rb import --snapshot data/imports/misp-galaxy/2026-04-26 --new-only
```

### Field mapping

| MISP Galaxy Field | Our Schema Field | Notes |
|-----------------|----------------|-------|
| `value` | `name` | Primary actor name |
| `meta.synonyms` | `aliases` | Combined with primary name |
| `description` | `description` | Full description |
| `meta.country` | `country` | ISO 3166-1 alpha-2 mapping |
| `meta.cfr-suspected-state-sponsor` | `country` | Fallback when no country code |
| `meta.targeted-sector` | `sector_focus` | Direct mapping |
| `meta.cfr-target-category` | `sector_focus` | Combined with targeted-sector |
| `meta.attribution-confidence` | `risk_level` | 50+ = High, 70+ = Critical |
| `meta.refs` | `References` section | List of source URLs |
| `uuid` | `provenance` | Source record ID |

### Safe defaults

- `--new-only` skips existing actors (recommended for initial imports)
- Protected fields (name, aliases, description) are only updated with `--force`
- Additive updates for existing actors (new aliases merged)
- Page files are only created for new actors

## What the importer updates

- Creates or updates actor metadata in `_data/actors/*.yml`
- Creates new actor pages in `_threat_actors/*.md`
- Synchronizes front matter on updated pages

It does not automatically import volatile IOCs, leak-site mirrors, or other fast-changing infrastructure into the IOC pipeline.

## Attribution

MISP Galaxy is dual-licensed under Apache 2.0 and CC0 1.0.

The importer preserves and emits attribution using the pattern:

`Contains data derived from MISP Galaxy, used under Apache 2.0 / CC0. Source: https://github.com/MISP/misp-galaxy`

Imported records preserve provenance fields such as:
- `provenance.misp_galaxy.source_retrieved_at`
- `provenance.misp_galaxy.source_record_id`
- `provenance.misp_galaxy.source_dataset_url`

## Malpedia Importer

`scripts/import-malpedia.rb` adds Malpedia as a reviewed enrichment source for existing actors.

Source: https://malpedia.caad.fkie.fraunhofer.de/

### Why this importer is conservative

- Malpedia is strongest as a malware-and-actor relationship source, not a canonical actor-identity source.
- Malpedia content is published under `CC BY-NC-SA 3.0`, which is more restrictive than this repository.
- To avoid licensing and attribution drift, this importer does not create new actors or import narrative descriptions.
- It only enriches existing actors with additive metadata such as aliases, country, sectors, suspected victims, incident type, malware-family names, and provenance.

Reviewed matching overrides live in `data/imports/malpedia/mapping_overrides.yml`.

### Commands

Fetch a snapshot with per-actor detail payloads:

```bash
ruby scripts/import-malpedia.rb fetch --output data/imports/malpedia/2026-04-26 --limit 25
```

Fetch only actor metadata without per-actor family detail payloads:

```bash
ruby scripts/import-malpedia.rb fetch --no-details --output data/imports/malpedia/2026-04-26
```

Preview how a snapshot would enrich existing actors:

```bash
ruby scripts/import-malpedia.rb plan --snapshot data/imports/malpedia/2026-04-26
```

Restrict to a specific actor or Malpedia actor ID:

```bash
ruby scripts/import-malpedia.rb plan --snapshot data/imports/malpedia/2026-04-26 --actor muddywater
```

Apply the reviewed enrichment:

```bash
ruby scripts/import-malpedia.rb import --snapshot data/imports/malpedia/2026-04-26
```

Write a machine-readable review report:

```bash
ruby scripts/import-malpedia.rb plan --snapshot data/imports/malpedia/2026-04-26 --report-json tmp/malpedia-report.json
```

### Field mapping

| Malpedia Field | Our Schema Field | Notes |
|----------------|------------------|-------|
| `value` | actor matching only | Used to match an existing actor; not auto-created as a new page |
| `meta.synonyms` | `aliases` | Additive merge only |
| `meta.country` | `country` | ISO 3166-1 alpha-2 mapping |
| `meta.cfr-suspected-state-sponsor` | `country` | Fallback when no country code exists |
| `meta.targeted-sector` | `sector_focus` | Additive merge |
| `meta.cfr-target-category` | `sector_focus` | Additive merge |
| `meta.cfr-suspected-victims` | `targeted_victims` | Additive merge |
| `meta.cfr-type-of-incident` | `incident_type` | Used when present |
| `meta.refs` | review/report only | Preserved in snapshot and report for manual curation |
| `families.*.common_name` | `malware` | Imported only from actor detail snapshots |
| `uuid` / actor ID | `provenance.malpedia.*` | Source record tracking |

### Guardrails

- No new actor creation from Malpedia alone.
- No description import from Malpedia text.
- No `risk_level`, `first_seen`, or `last_activity` mapping.
- Malware-family links are treated as supporting enrichment, not canonical actor identity.
- Matching overrides should be reviewed before applying broad updates.

### Attribution

The importer preserves source attribution using the pattern:

`Contains metadata derived from Malpedia by Fraunhofer FKIE. Source: https://malpedia.caad.fkie.fraunhofer.de/`

Imported provenance fields include:
- `provenance.malpedia.source_retrieved_at`
- `provenance.malpedia.source_record_id`
- `provenance.malpedia.source_uuid`
- `provenance.malpedia.source_dataset_url`
- `provenance.malpedia.source_record_url`

## APTnotes Importer

`scripts/import-aptnotes.rb` adds APTnotes as a reviewed report-index source for existing actors.

Source: https://github.com/aptnotes/data

### Why this importer is conservative

- APTnotes is a bibliography of public reporting, not a canonical actor dataset.
- It is useful for discovery, chronology hints, and reference curation, but not for authoritative actor descriptions.
- To avoid low-confidence narrative imports, this importer only enriches existing actors with report-count provenance, source diversity, and early/late report-year hints.

Reviewed matching overrides live in `data/imports/aptnotes/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-aptnotes.rb fetch --output data/imports/aptnotes/2026-04-26
```

Preview how APTnotes records would match existing actors:

```bash
ruby scripts/import-aptnotes.rb plan --snapshot data/imports/aptnotes/2026-04-26
```

Restrict to a specific actor:

```bash
ruby scripts/import-aptnotes.rb plan --snapshot data/imports/aptnotes/2026-04-26 --actor APT28
```

Apply the reviewed enrichment:

```bash
ruby scripts/import-aptnotes.rb import --snapshot data/imports/aptnotes/2026-04-26
```

Write a machine-readable review report:

```bash
ruby scripts/import-aptnotes.rb plan --snapshot data/imports/aptnotes/2026-04-26 --report-json tmp/aptnotes-report.json
```

### Field mapping

| APTnotes Field | Our Schema Field | Notes |
|----------------|------------------|-------|
| `Title` / `Filename` | actor matching only | Used to suggest a report-to-actor match |
| `Source` | `provenance.aptnotes.sources` | Unique publisher/source list |
| `Year` | `provenance.aptnotes.earliest_report_year` / `latest_report_year` | Also fills `first_seen` / `last_activity` only when blank |
| `Link` | `provenance.aptnotes.sample_links` | Stored as sample evidence links |
| `SHA-1` | review/report only | Used for deterministic report identity |

### Guardrails

- No new actor creation from APTnotes alone.
- No description import from report titles.
- No automatic page-reference injection into markdown.
- Ambiguous multi-actor report matches stay review-only.

### Attribution

The importer preserves source attribution using the pattern:

`References were identified in part via APTnotes (https://github.com/aptnotes/data), which is used here as a report index. Copyright in linked reports remains with the original publishers.`

Imported provenance fields include:
- `provenance.aptnotes.source_retrieved_at`
- `provenance.aptnotes.source_dataset_url`
- `provenance.aptnotes.report_count`
- `provenance.aptnotes.earliest_report_year`
- `provenance.aptnotes.latest_report_year`

## APT Groups & Operations Importer

`scripts/import-apt-groups-operations.rb` adds the public APT Groups & Operations spreadsheet as a reviewed crosswalk source for existing actors.

Source: https://apt.threattracking.com/

### Why this importer is conservative

- The spreadsheet is best treated as a secondary research aid, not a sole authoritative source.
- It is strongest for alias crosswalks, MITRE group ID hints, operation labels, and malware/toolset names.
- To avoid polluting canonical content, this importer only performs additive updates for existing actors.

Reviewed matching overrides live in `data/imports/apt-groups-operations/mapping_overrides.yml`.

### Commands

Fetch the default country tabs:

```bash
ruby scripts/import-apt-groups-operations.rb fetch --output data/imports/apt-groups-operations/2026-04-26
```

Fetch only specific tabs:

```bash
ruby scripts/import-apt-groups-operations.rb fetch --output data/imports/apt-groups-operations/2026-04-26 --tab russia --tab china
```

Preview additive enrichments:

```bash
ruby scripts/import-apt-groups-operations.rb plan --snapshot data/imports/apt-groups-operations/2026-04-26
```

Apply the reviewed enrichment:

```bash
ruby scripts/import-apt-groups-operations.rb import --snapshot data/imports/apt-groups-operations/2026-04-26
```

Write a machine-readable review report:

```bash
ruby scripts/import-apt-groups-operations.rb plan --snapshot data/imports/apt-groups-operations/2026-04-26 --report-json tmp/apt-groups-operations-report.json
```

### Field mapping

| Spreadsheet Field | Our Schema Field | Notes |
|-------------------|------------------|-------|
| `Common Name` + `Other Name *` | `aliases` | Additive merge only |
| tab country | `country` | Used only when actor country is blank |
| `MITRE ATT&CK` | `external_id` | Used only when there is exactly one ID and the field is blank |
| `Operation *` | `operations` | Additive merge of operation labels |
| `Toolset / Malware` | `malware` | Parsed into additive malware names |
| `Link *` | `provenance.apt_groups_operations.source_links` | Supporting evidence links |

### Guardrails

- No new actor creation from the spreadsheet alone.
- No description import from `Targets`, `Modus Operandi`, or `Comment`.
- No alias promotion for dropped/known-bad labels in `alias_drop_list`.
- Ambiguous matches stay review-only.

### Attribution

The importer preserves source attribution using the pattern:

`Alias and operation cross-reference data were reviewed from the public APT Groups & Operations spreadsheet (https://apt.threattracking.com/). The spreadsheet is used here as a secondary research aid and crosswalk, not as a sole authoritative source.`

Imported provenance fields include:
- `provenance.apt_groups_operations.source_retrieved_at`
- `provenance.apt_groups_operations.source_dataset_url`
- `provenance.apt_groups_operations.sheet_id`
- `provenance.apt_groups_operations.tab_name`
- `provenance.apt_groups_operations.matched_mitre_ids`

## ETDA / ThaiCERT Threat Group Cards Importer

`scripts/import-etda-thaicert.rb` adds ETDA/ThaiCERT Threat Group Cards as a reviewed threat-group enrichment source.

Source: https://apt.etda.or.th/

### Why this importer is conservative

- ETDA/ThaiCERT cards are high-value reference content but still require normalization and local curation.
- Matching across multiple public naming conventions can collide; ambiguous matches are review-only.
- By default, existing curated name/description fields are protected and only updated with `--force`.

Reviewed matching overrides live in `data/imports/etda-thaicert/mapping_overrides.yml`.

### Commands

Fetch a snapshot from ETDA (with mirror fallback):

```bash
ruby scripts/import-etda-thaicert.rb fetch --output data/imports/etda-thaicert/2026-04-27
```

Fetch from a custom endpoint:

```bash
ruby scripts/import-etda-thaicert.rb fetch --source-url "https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&j=1" --output data/imports/etda-thaicert/2026-04-27
```

Preview changes:

```bash
ruby scripts/import-etda-thaicert.rb plan --snapshot data/imports/etda-thaicert/2026-04-27
```

Restrict to a specific actor:

```bash
ruby scripts/import-etda-thaicert.rb plan --snapshot data/imports/etda-thaicert/2026-04-27 --actor APT28
```

Apply import:

```bash
ruby scripts/import-etda-thaicert.rb import --snapshot data/imports/etda-thaicert/2026-04-27
```

Only create new actors:

```bash
ruby scripts/import-etda-thaicert.rb import --snapshot data/imports/etda-thaicert/2026-04-27 --new-only
```

Allow protected-field overwrite when explicitly needed:

```bash
ruby scripts/import-etda-thaicert.rb import --snapshot data/imports/etda-thaicert/2026-04-27 --force
```

Write a machine-readable review report:

```bash
ruby scripts/import-etda-thaicert.rb plan --snapshot data/imports/etda-thaicert/2026-04-27 --report-json tmp/etda-thaicert-report.json
```

### Field mapping

| ETDA/ThaiCERT Field (normalized) | Our Schema Field | Notes |
|----------------------------------|------------------|-------|
| `name` / `group_name` / `title` | `name` + matching keys | Used for matching and new actor identity |
| `aliases` / `synonyms` | `aliases` | Additive merge only |
| `description` / `summary` / `about` | `description` | Protected on existing actors unless `--force` |
| `country` / `origin_country` / `state_sponsor` | `country` | Used when actor country is blank (or override) |
| `sector_focus` / `targets` | `sector_focus` | Additive merge |
| `operations` / `campaigns` | `operations` | Additive merge |
| `malware` / `tools` / `toolset` | `malware` | Additive merge as malware names |
| `first_seen` | `first_seen` | Imported when valid year and target is blank |
| `last_activity` / `updated` | `last_activity` | Imported when newer year |
| MITRE IDs in source text | `provenance.etda_thaicert.mitre_*` | Stored as provenance hints for later curation |

### Guardrails

- Ambiguous multi-match records are reported as `review` and never auto-applied.
- `excluded_group_keys` and `alias_drop_list` suppress low-quality rows/aliases.
- Volatile IOC content is intentionally not auto-imported into actor pages.
- Page synchronization updates front matter for existing files and only creates full markdown files for new actors.

### Attribution

The importer preserves source attribution using the pattern:

`Contains data derived from ETDA/ThaiCERT Threat Group Cards (https://apt.etda.or.th/), adapted with attribution for research and enrichment.`

Imported provenance fields include:
- `provenance.etda_thaicert.source_retrieved_at`
- `provenance.etda_thaicert.source_dataset_url`
- `provenance.etda_thaicert.source_record_id`
- `provenance.etda_thaicert.source_record_url`
- `provenance.etda_thaicert.mitre_group_ids`
- `provenance.etda_thaicert.mitre_technique_ids`
