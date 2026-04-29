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
- Run public, machine-consumable source imports through `ruby scripts/import-automated-sources.rb`; analyst notes are intentionally excluded from this runner.
- Regenerate pages with `ruby scripts/generate-pages.rb --force` after source updates.
- Regenerate APIs with `ruby scripts/generate-indexes.rb` in the same run.
- Prefer **structured IOCs** under **`iocs:`** in `_data/actors/*.yml` (plus legacy top-level IOC lists where applicable); [`scripts/ioc_yaml_reader.rb`](../scripts/ioc_yaml_reader.rb) merges them for **`generate-indexes.rb`** and **`generate-pages.rb`** so `/api/iocs.json` and actor **`ioc_count`** stay aligned with YAML without duplicating Markdown-only pipelines.
- Use `ruby scripts/evaluate-source-deltas.rb` to enforce update thresholds before publishing large changes.
- See `docs/data-flows.md` for the source-of-truth map and the analyst-note supersession policy.

## MITRE ATT&CK STIX Importer

`scripts/import-mitre.rb` imports [MITRE ATT&CK](https://attack.mitre.org) STIX 2.1 bundles from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

It uses the same **fetch → plan → import** snapshot workflow as other automated importers. Snapshots are stored under `data/imports/mitre-attack/<YYYY-MM-DD>/` with a `manifest.yml` listing downloaded bundle URLs (Enterprise, Mobile, and ICS by default). The manifest records a parsed **`attack_version`** per domain (from the STIX `x-mitre-collection` object) so imports and indexes agree on the ATT&CK release.

### ATT&CK version pinning and `data/mitre-cache/`

- **`--version X.Y`** on `fetch` selects versioned bundle filenames from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (for example `enterprise-attack-19.0.json`). Omitting it uses the repo’s default/latest filenames.
- **`data/mitre-cache/`** (gitignored) holds local copies: `<domain>-attack-<version>.json` plus **`active.yml`**, which points each framework (`enterprise`, `mobile`, `ics`) at the active file and version.
- **`--write-active`** (default on fetch/import) copies snapshot bundles into `data/mitre-cache/` and refreshes `active.yml`. Use **`--no-write-active`** when you want a snapshot-only run without touching the cache.
- **`scripts/generate-indexes.rb`** resolves bundles in order: newest importer snapshot manifest → `active.yml` → optional network download. Regenerate `_data/generated/attack_version.json` and MITRE indexes after changing the active release.
- Actor YAML updated by import includes **`provenance.mitre.attack_version`** (and versioned **`source_dataset_url`**) for traceability.

### Commands

Fetch the latest unversioned bundles (or use `--version 19.0` to pin to a specific ATT&CK release file name):

```bash
ruby scripts/import-mitre.rb fetch --output data/imports/mitre-attack/$(date -I)
```

Preview:

```bash
ruby scripts/import-mitre.rb plan --snapshot data/imports/mitre-attack/2026-04-28 --report-json tmp/mitre-attack-report.json
```

Apply (updates actor YAML, writes collection pages, refreshes references cache):

```bash
ruby scripts/import-mitre.rb import --snapshot data/imports/mitre-attack/2026-04-28 --report-json tmp/mitre-attack-import.json
```

After import, regenerate pages and indexes:

```bash
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb
ruby scripts/validate-content.rb
```

### What gets imported

- **Groups** (`intrusion-set`): merged into `_data/actors/*.yml` with `ttps`, `software`, and `campaigns` arrays derived from STIX relationships; provenance in `provenance.mitre`.
- **First-class Jekyll collections** (markdown under `_techniques/`, `_tactics/`, `_campaigns/`, `_mitigations/`, plus MITRE **software** under `_malware/` with `mitre_id: S####` when matched or created).
- Revoked/deprecated STIX objects are skipped unless `--include-revoked` is passed.

### Attribution

Per MITRE permission notice used throughout the site:

`© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.`

### Offline bundles and `generate-indexes`

Bundles under **`data/mitre-cache/`** (gitignored local cache) and dated **`data/imports/mitre-attack/<date>/`** snapshots are what allow **`ruby scripts/generate-indexes.rb`** to populate **`technique_tactics.json`**, **`attack_version.json`**, and tactic-aware **`actors_by_tactic.json`** without brittle failures. See [Offline MITRE bundles](offline-mitre-bundles.md) for resolver order, CI implications, and how to **refresh MITRE stubs** and actor **`ttps`** via `import-mitre.rb import`.

### Stub vs imported MITRE collection pages

- **Index-time stubs (`generate-indexes.rb`).** When ATT&CK STIX bundles are resolved (snapshot cache or network), index generation merges STIX descriptions into technique/tactic metadata and can **create or refresh stub markdown** under `_techniques/` and `_tactics/` so pages show a **Description** section and tactic links without running the full importer. Pages that still carry the generated stub marker get rewritten when resolver-backed descriptions become available; analyst-edited pages without that marker are left unchanged.

- **Full import (`import-mitre.rb import`).** For complete collection pages—description plus structured sections such as sub-techniques, mitigations, and groups lists—run **`ruby scripts/import-mitre.rb import --snapshot …`** as above, then **`ruby scripts/generate-indexes.rb`**. That path uses `MitreEntityWriters` and replaces technique/tactic files with the richer layout defined for this site.

## Categorized Adversary TTPs snapshot

The dataset from [tropChaud/Categorized-Adversary-TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs) (MIT license) is vendored as JSON under [`data/imports/categorized-adversary-ttps/`](https://github.com/tropChaud/Categorized-Adversary-TTPs). It merges MITRE ATT&CK group-to-technique relationships with ETDA/ThaiCERT Threat Group Card metadata (victim industries/countries, motivations).

There is no separate fetch-only importer script; refresh is a manual snapshot replace plus regeneration.

### Refresh workflow

1. Download the latest JSON using the curl command in `data/imports/categorized-adversary-ttps/README.md`.
2. Update `data/imports/categorized-adversary-ttps/manifest.yml` (`retrieved_at`, optional upstream commit reference).
3. Regenerate indexes:

```bash
ruby scripts/generate-indexes.rb
ruby scripts/validate-content.rb
```

Outputs include `_data/generated/categorized_adversary_by_group.json`, pivot histograms (`categorized_pivot_by_*.json`), `categorized_adversary_meta.json`, and optional `categorized_adversary_ttps` on `/api/threat-actors.json` rows when actor YAML `mitre_id` / `external_id` matches a `G####` group present in the snapshot.

### Attribution

Upstream credits MITRE ATT&CK and ETDA Threat Group Cards; this site lists the merged dataset on [Source Attribution](/attribution/) with license metadata recorded in `manifest.yml`.

## BushidoToken Breach Report Collection Importer

`scripts/import-bushido-breach-reports.rb` adds reviewed breach-report links from the BushidoToken Breach Report Collection to existing actors.

Source: https://github.com/BushidoUK/Breach-Report-Collection

### Why this importer is conservative

- The collection is a report index, not a canonical actor dataset.
- Imports only enrich existing actors; they do not create new actors.
- Unknown, generic, ambiguous, and unresolved adversary labels stay in the reviewed skip list.
- Matched rows add provenance to `_data/actors/*.yml` and article links to each actor page's `References` section.

Reviewed mappings live in `data/imports/bushido-breach-reports/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-bushido-breach-reports.rb fetch --output data/imports/bushido-breach-reports/2026-04-28
```

Preview reviewed matches:

```bash
ruby scripts/import-bushido-breach-reports.rb plan --snapshot data/imports/bushido-breach-reports/2026-04-28
```

Apply the enrichment:

```bash
ruby scripts/import-bushido-breach-reports.rb import --snapshot data/imports/bushido-breach-reports/2026-04-28
```

Write a machine-readable review report:

```bash
ruby scripts/import-bushido-breach-reports.rb plan --snapshot data/imports/bushido-breach-reports/2026-04-28 --report-json tmp/bushido-breach-reports.json
```

### Field mapping

| Bushido Field | Our Schema Field | Notes |
|---------------|------------------|-------|
| `Organization` | `provenance.bushido_breach_reports.reports[].organization` and References title | Breached entity named by the source row |
| `Breach Date` | `provenance.bushido_breach_reports.reports[].breach_date` and References title | Month/year text from the source |
| `Adversary` | actor matching and `adversary_label` | Preserved as source label, including qualifiers such as ransomware/APT |
| primary `Source` links | actor page `References` and provenance `links` | Archive links are kept separately in provenance |

### Attribution

The importer preserves source attribution using the pattern:

`References were identified via the BushidoToken Breach Report Collection (https://github.com/BushidoUK/Breach-Report-Collection), which is used here as a report index. Copyright in linked reports remains with the original publishers.`

## Ransomware Tool Matrix Importer

`scripts/import-ransomware-tool-matrix.rb` enriches existing ransomware actors with reviewed tool observations from the BushidoUK Ransomware Tool Matrix.

Source: https://github.com/BushidoUK/Ransomware-Tool-Matrix

### Why this importer is conservative

- The matrix is a secondary tradecraft reference, not canonical actor identity data.
- Imports only update existing actors; they do not create new actors.
- Tools are stored in provenance and rendered as grouped observations on actor pages, not as volatile IOCs.
- Ambiguous source labels, unmatched labels, and alias collisions stay review-only unless mapped in overrides.

Reviewed mappings live in `data/imports/ransomware-tool-matrix/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-ransomware-tool-matrix.rb fetch --output data/imports/ransomware-tool-matrix/2026-04-28
```

Preview reviewed matches:

```bash
ruby scripts/import-ransomware-tool-matrix.rb plan --snapshot data/imports/ransomware-tool-matrix/2026-04-28
```

Apply the enrichment:

```bash
ruby scripts/import-ransomware-tool-matrix.rb import --snapshot data/imports/ransomware-tool-matrix/2026-04-28
```

Write a machine-readable review report:

```bash
ruby scripts/import-ransomware-tool-matrix.rb plan --snapshot data/imports/ransomware-tool-matrix/2026-04-28 --report-json tmp/ransomware-tool-matrix-report.json
```

### Field mapping

| Matrix Field | Our Schema Field | Notes |
|--------------|------------------|-------|
| Tool category tables | `provenance.ransomware_tool_matrix.tools_by_category` | Stable grouped tool observations by actor |
| Group profile tool tables | `provenance.ransomware_tool_matrix.tools_by_category` | Merged with category table observations |
| Group profile sources / ThreatIntel report links | `provenance.ransomware_tool_matrix.references` | Supporting report links for analyst review |
| Community report incident summaries | `provenance.ransomware_tool_matrix.community_reports` | Victim sector/country/time only; no victim names or volatile IOCs |
| `*` / `+` actor markers | `provenance.ransomware_tool_matrix.actor_roles` | Preserves IAB, affiliate, and suspected state-sponsored labels |

### Attribution

The importer preserves source attribution using the pattern:

`Tool observations were reviewed from the BushidoUK Ransomware Tool Matrix (https://github.com/BushidoUK/Ransomware-Tool-Matrix). The matrix is used here as a secondary ransomware tradecraft reference, not as sole attribution evidence.`

## Ransomware Vulnerability Matrix Importer

`scripts/import-ransomware-vulnerability-matrix.rb` enriches existing ransomware actors with reviewed CVE observations from the BushidoUK Ransomware Vulnerability Matrix.

Source: https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix

### Why this importer is conservative

- The matrix is a secondary exploitation reference, not canonical actor identity data.
- Imports only update existing actors; they do not create new actors.
- CVEs are stored in provenance and rendered as grouped exploitation observations, not as CISA KEV assertions or volatile IOCs.
- Ambiguous source labels, unmatched labels, and alias collisions stay review-only unless mapped in overrides.

Reviewed mappings live in `data/imports/ransomware-vulnerability-matrix/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-ransomware-vulnerability-matrix.rb fetch --output data/imports/ransomware-vulnerability-matrix/2026-04-28
```

Preview reviewed matches:

```bash
ruby scripts/import-ransomware-vulnerability-matrix.rb plan --snapshot data/imports/ransomware-vulnerability-matrix/2026-04-28
```

Apply the enrichment:

```bash
ruby scripts/import-ransomware-vulnerability-matrix.rb import --snapshot data/imports/ransomware-vulnerability-matrix/2026-04-28
```

Write a machine-readable review report:

```bash
ruby scripts/import-ransomware-vulnerability-matrix.rb plan --snapshot data/imports/ransomware-vulnerability-matrix/2026-04-28 --report-json tmp/ransomware-vulnerability-matrix-report.json
```

### Field mapping

| Matrix Field | Our Schema Field | Notes |
|--------------|------------------|-------|
| Vulnerability category tables | `provenance.ransomware_vulnerability_matrix.vulnerabilities_by_category` | Stable grouped CVE observations by actor |
| Group profile vulnerability tables | `provenance.ransomware_vulnerability_matrix.vulnerabilities_by_category` | Merged with category table observations |
| Group profile source tables / row links | `provenance.ransomware_vulnerability_matrix.references` | Supporting report links for analyst review |
| `*` / `+` actor markers | `provenance.ransomware_vulnerability_matrix.actor_roles` | Preserves IAB, affiliate, and suspected state-sponsored labels |

### Attribution

The importer preserves source attribution using the pattern:

`Vulnerability observations were reviewed from the BushidoUK Ransomware Vulnerability Matrix (https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix). The matrix is used here as a secondary ransomware exploitation reference, not as sole attribution evidence.`

## Russian APT Tool Matrix Importer

`scripts/import-russian-apt-tool-matrix.rb` enriches existing Russian APT actors with reviewed tool observations from the BushidoUK Russian APT Tool Matrix.

Source: https://github.com/BushidoUK/Russian-APT-Tool-Matrix

### Why this importer is conservative

- The matrix is a secondary tradecraft reference, not canonical actor identity data.
- Imports only update existing actors; they do not create new actors.
- Tools are stored in provenance and rendered as grouped observations on actor pages, not as volatile IOCs.
- Compound labels and alias collisions require reviewed mappings before import.

Reviewed mappings live in `data/imports/russian-apt-tool-matrix/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-russian-apt-tool-matrix.rb fetch --output data/imports/russian-apt-tool-matrix/2026-04-28
```

Preview reviewed matches:

```bash
ruby scripts/import-russian-apt-tool-matrix.rb plan --snapshot data/imports/russian-apt-tool-matrix/2026-04-28
```

Apply the enrichment:

```bash
ruby scripts/import-russian-apt-tool-matrix.rb import --snapshot data/imports/russian-apt-tool-matrix/2026-04-28
```

Write a machine-readable review report:

```bash
ruby scripts/import-russian-apt-tool-matrix.rb plan --snapshot data/imports/russian-apt-tool-matrix/2026-04-28 --report-json tmp/russian-apt-tool-matrix-report.json
```

### Field mapping

| Matrix Field | Our Schema Field | Notes |
|--------------|------------------|-------|
| Tool category tables | `provenance.russian_apt_tool_matrix.tools_by_category` | Stable grouped tool observations by actor |
| Group profile tool tables | `provenance.russian_apt_tool_matrix.tools_by_category` | Merged with category table observations |
| Group profile sources / ThreatIntelligence report links | `provenance.russian_apt_tool_matrix.references` | Supporting report links for analyst review |
| Compound actor labels | `match_overrides` entries | Fan out reviewed references to each existing actor when appropriate |

### Attribution

The importer preserves source attribution using the pattern:

`Tool observations were reviewed from the BushidoUK Russian APT Tool Matrix (https://github.com/BushidoUK/Russian-APT-Tool-Matrix). The matrix is used here as a secondary Russian APT tradecraft reference, not as sole attribution evidence.`

## Microsoft Threat Actor List Importer

`scripts/import-microsoft-threat-actor-list.rb` adds Microsoft's public threat actor naming list as a recurring import source for existing-actor alias and origin-category enrichment.

Source: https://download.microsoft.com/download/4/5/2/45208247-c1e9-432d-a9a2-1554d81074d9/microsoft-threat-actor-list.xlsx

### Import scope

- Microsoft publishes and regularly updates this workbook for public use; imports preserve source attribution and importer provenance.
- The workbook contains actor name, origin/category, and other names only; it has no narrative descriptions, references per actor, IOCs, malware, or TTPs.
- Imports only update existing actors; they do not create new actors.
- Ambiguous vendor-name collisions stay review-only unless mapped in overrides.

Reviewed mappings live in `data/imports/microsoft-threat-actor-list/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-microsoft-threat-actor-list.rb fetch --output data/imports/microsoft-threat-actor-list/2026-04-28
```

Preview additive enrichments:

```bash
ruby scripts/import-microsoft-threat-actor-list.rb plan --snapshot data/imports/microsoft-threat-actor-list/2026-04-28
```

Apply enrichments:

```bash
ruby scripts/import-microsoft-threat-actor-list.rb import --snapshot data/imports/microsoft-threat-actor-list/2026-04-28
```

Write a machine-readable review report:

```bash
ruby scripts/import-microsoft-threat-actor-list.rb plan --snapshot data/imports/microsoft-threat-actor-list/2026-04-28 --report-json tmp/microsoft-threat-actor-list-report.json
```

### Field mapping

| Workbook Field | Our Schema Field | Notes |
|----------------|------------------|-------|
| `Threat actor name` | `aliases` and `provenance.microsoft_threat_actor_list.microsoft_name` | Additive alias only; does not rename the actor |
| `Other names` | `aliases` | Additive merge only |
| `Origin/Threat actor category` country token | `country` | Used only when actor country is blank, with optional overrides |
| `Origin/Threat actor category` non-country tokens | `provenance.microsoft_threat_actor_list.categories` | Preserved as source context, not promoted to incident type or risk |

### Guardrails

- No new actor creation from the Microsoft list alone.
- No description, risk-level, malware, TTP, campaign, or IOC import.
- No automatic Microsoft primary-name takeover.
- This importer is documented as a reviewed source and is intentionally not part of the default automated import runner until licensing/reuse terms are explicit.

### Attribution

The importer preserves source attribution using the pattern:

`Alias cross-reference data was reviewed from the Microsoft Threat Actor List. The spreadsheet is used here as a secondary vendor naming crosswalk, not as a sole authoritative source.`

## Curated Intelligence MOVEit Transfer Importer

`scripts/import-curated-intel-moveit-transfer.rb` enriches the existing Cl0p actor with campaign timeline events from the Curated Intelligence MOVEit Transfer tracking repository.

Source: https://github.com/curated-intel/MOVEit-Transfer

### Why this importer is scoped to Cl0p

- The source tracks a single campaign publicly attributed to CL0P/Lace Tempest.
- Imports preserve the full event table as provenance and render it as the Cl0p page's MOVEit Transfer campaign timeline.
- The importer keeps volatile leak-site infrastructure out of the IOC pipeline; leak-site screenshots remain source references only.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-curated-intel-moveit-transfer.rb fetch --output data/imports/curated-intel-moveit-transfer/2026-04-28
```

Preview the parsed events:

```bash
ruby scripts/import-curated-intel-moveit-transfer.rb plan --snapshot data/imports/curated-intel-moveit-transfer/2026-04-28
```

Apply the enrichment:

```bash
ruby scripts/import-curated-intel-moveit-transfer.rb import --snapshot data/imports/curated-intel-moveit-transfer/2026-04-28
```

### Field mapping

| Source Field | Our Schema Field | Notes |
|--------------|------------------|-------|
| `Publish Date` | `provenance.curated_intel_moveit_transfer.events[].publish_date` | Normalized to `YYYY-MM-DD` for 2023 campaign rows |
| `Type` | `provenance.curated_intel_moveit_transfer.events[].event_type` | Preserves combined labels such as `Adversary/Capabilities` |
| `Description` | `provenance.curated_intel_moveit_transfer.events[].description` | Markdown links are stripped from the description text |
| `Source` | `source_title` and `source_url` | Rendered as the table source link on the Cl0p page |

### Attribution

The importer preserves source attribution using the pattern:

`MOVEit Transfer campaign events were reviewed from the Curated Intelligence MOVEit Transfer tracking repository (https://github.com/curated-intel/MOVEit-Transfer). Linked reports remain owned by their original publishers.`

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

`scripts/import-misp-galaxy.rb` imports threat actor data from MISP Galaxy snapshots and can target one or more cluster files per run.

Source: https://github.com/MISP/misp-galaxy (Apache 2.0 / CC0 licensed)

Reviewed create/import decisions for the current focused cluster work live in `docs/misp-galaxy-triage.md`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-misp-galaxy.rb fetch --output data/imports/misp-galaxy/2026-04-26
```

Fetch only specific clusters:

```bash
ruby scripts/import-misp-galaxy.rb fetch \
  --output data/imports/misp-galaxy/2026-04-26 \
  --cluster threat-actor \
  --cluster 360net \
  --cluster microsoft-activity-group
```

Preview changes:

```bash
ruby scripts/import-misp-galaxy.rb plan --snapshot data/imports/misp-galaxy/2026-04-26
```

Preview only selected cluster files from a multi-cluster snapshot:

```bash
ruby scripts/import-misp-galaxy.rb plan \
  --snapshot data/imports/misp-galaxy/2026-04-26 \
  --cluster 360net \
  --cluster microsoft-activity-group
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

When multiple clusters are imported together, the importer deduplicates by normalized actor name and merges additive fields such as aliases, sectors, victims, malware names, references, and provenance cluster membership.

### Safe defaults

- `--new-only` skips existing actors (recommended for initial imports)
- Protected fields (name, aliases, description) are only updated with `--force`
- Additive updates for existing actors (new aliases merged)
- Snapshot directories now include `manifest.yml` plus one raw JSON file per fetched cluster for reproducibility
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

## EternalLiberty Importer

`scripts/import-eternal-liberty.rb` adds EternalLiberty as a reviewed alias crosswalk source for existing actors.

Source: https://github.com/StrangerealIntel/EternalLiberty

### Why this importer is conservative

- EternalLiberty is strongest as an alias cross-reference across vendor naming schemes, not as a canonical actor-identity source.
- The upstream dataset has `official_name`, `confidence`, `type`, `country`, and vendor-scoped alias records, but no narrative descriptions or primary-source citations per row.
- The upstream repository does not declare a license. EternalLiberty is the only approved no-upstream-license import exception; do not generalize this policy to other sources.
- To avoid attribution and identity drift, this importer only enriches existing actors with additive aliases, blank-country fills, MITRE group ID hints, and provenance.

Reviewed matching overrides live in `data/imports/eternal-liberty/mapping_overrides.yml`.

### Commands

Fetch a snapshot:

```bash
ruby scripts/import-eternal-liberty.rb fetch --output data/imports/eternal-liberty/2026-04-28
```

Preview additive enrichments:

```bash
ruby scripts/import-eternal-liberty.rb plan --snapshot data/imports/eternal-liberty/2026-04-28
```

Restrict to a specific actor:

```bash
ruby scripts/import-eternal-liberty.rb plan --snapshot data/imports/eternal-liberty/2026-04-28 --actor APT28
```

Apply reviewed enrichments:

```bash
ruby scripts/import-eternal-liberty.rb import --snapshot data/imports/eternal-liberty/2026-04-28
```

Write a machine-readable review report:

```bash
ruby scripts/import-eternal-liberty.rb plan --snapshot data/imports/eternal-liberty/2026-04-28 --report-json tmp/eternal-liberty-report.json
```

### Field mapping

| EternalLiberty Field | Our Schema Field | Notes |
|----------------------|------------------|-------|
| `official_name` | actor matching only | Used for matching existing actors; not auto-created as a new actor |
| `alias[].name` | `aliases` | Additive merge only; slash-separated aliases are split |
| `alias[].entity` | `provenance.eternal_liberty.aliases_by_entity` | Preserves vendor/source context for review |
| MITRE-style `G####` aliases | `external_id` | Used only when exactly one MITRE ID exists and the field is blank |
| `country` | `country` | Used only when actor country is blank; `Unknown` and `Worldwide` are ignored |
| `confidence` / `type` | `provenance.eternal_liberty.*` | Stored as source context, not promoted to risk or incident type |

### Guardrails

- No new actor creation from EternalLiberty alone.
- No description, risk-level, incident-type, campaign, malware, or IOC import.
- Ambiguous multi-match records are reported as `review` and never auto-applied.
- `excluded_records`, `match_overrides`, `country_overrides`, and `alias_drop_list` support reviewed cleanup before broad imports.

### Attribution

The importer preserves source attribution using the pattern:

`Alias cross-reference data was reviewed from EternalLiberty (https://github.com/StrangerealIntel/EternalLiberty). EternalLiberty is used here as a secondary alias crosswalk, not as a sole authoritative source.`

Imported provenance fields include:
- `provenance.eternal_liberty.source_retrieved_at`
- `provenance.eternal_liberty.source_dataset_url`
- `provenance.eternal_liberty.source_version`
- `provenance.eternal_liberty.source_record_id`
- `provenance.eternal_liberty.license_status`
- `provenance.eternal_liberty.aliases_by_entity`

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

## Analyst Notes Importer

`scripts/import-analyst-notes.rb` adds manually curated analyst notes as an enrichment source for existing actors.

### Per-Actor Notes Files

Each threat actor gets their own analyst notes file in `_data/analyst_notes/`. This allows for granular, manual curation.

File naming convention: `_data/analyst_notes/{actor-slug}.yml`

For example:
- APT28 → `_data/analyst_notes/apt28.yml`
- Fancy Bear → `_data/analyst_notes/fancybear.yml`

### Commands

Initialize an empty analyst notes file for a specific actor:

```bash
ruby scripts/import-analyst-notes.rb init --actor APT28
```

Preview which analyst notes would be applied:

```bash
ruby scripts/import-analyst-notes.rb plan
```

Apply all analyst notes to actors:

```bash
ruby scripts/import-analyst-notes.rb import
```

### Structured Note Format

Each note file contains `note_blocks` with structured data that maps to specific TA page sections:

```yaml
actor_name: "APT28"
last_updated: "2026-04-27"
note_blocks:
  - type: targeted_countries
    values:
      - "Germany"
      - "United States"
      - "Ukraine"
  - type: operations
    values:
      - "Operation Olympic Destroyer"
      - "Operation GhostSecret"
  - type: malware
    values:
      - "Olympic Destroyer"
      - "Destructive wiper with GPS probing"
  - type: ips
    values:
      - "192.0.2.1 - C2 server"
      - "198.51.100.1 - Staging server"
  - type: hashes
    values:
      - "a1b2c3d4e5f6... - Destructive payload"
      - "6f7e8d9c0b1a... - Loader"
  - type: ttps
    values:
      - "T1047 - Windows Management Instrumentation"
      - "T1059 - Command and Scripting Interpreter"
  - type: cves
    values:
      - "CVE-2024-12345"
  - type: general
    content: |
      This actor has been observed conducting extensive reconnaissance
      against government ministries in NATO member states since 2024.
```

### Supported Note Types

| Note Type | Target Field | Description |
|-----------|-------------|-------------|
| `targeted_countries` | `targeted_victims` | Countries targeted by this actor |
| `targeted_sectors` | `sector_focus` | Sectors targeted by this actor |
| `operations` | `operations` | Named operations/campaigns |
| `malware` | `malware` | Malware names with descriptions |
| `tools` | `malware` | Tool names |
| `ttps` | `TTPS` | MITRE ATT&CK technique IDs |
| `cves` | `cisa_kev_cves` | Known exploited vulnerabilities |
| `urls` | `urls` | Malicious URLs |
| `domains` | `domains` | Malicious domains |
| `ips` | `ips` | IP addresses (C2, staging, etc.) |
| `hashes` | `hashes` | File hashes (MD5, SHA1, SHA256) |
| `campaigns` | `campaigns` | Named campaigns |
| `general` | `analyst_notes` | Free-form analysis text |

### How It Works

1. Analyst creates/edits a note file for the actor in `_data/analyst_notes/`
2. Each `note_block` has a `type` (required) and either `values` (array) or `content` (text)
3. During `import`, the structured values are split across the appropriate actor fields
4. Multiple entries of the same type are merged (additive)
5. Plain text notes go to `analyst_notes` field in the YAML

---

## Manual Threat Actor Creation

When an analyst discovers a threat actor not yet in any automated source, there are two methods to add it manually:

### Method 1: actor-creator.rb (CLI)

Create a new threat actor directly from command line:

```bash
# Simple creation
ruby scripts/actor-creator.rb new --name "APT29" --country "CN" --description "Chinese state-sponsored actor"

# Full options
ruby scripts/actor-creator.rb new \
  --name "APT29" \
  --country "CN" \
  --description "Chinese state-sponsored actor targeting government" \
  --alias "Barium" \
  --alias "APT-C3" \
  --url "/apt29" \
  --risk "High" \
  --sector "Government" \
  --sector "Defense" \
  --victim "United States" \
  --victim "Germany" \
  --first-seen 2020 \
  --last-active 2024 \
  --external-id "G0016"
```

This creates:
- `_data/actors/apt29.yml` - Actor YAML with `source_name: Manual Entry`
- `_threat_actors/apt29.md` - Template page

### Method 2: import-analyst-notes.rb new

Create a new actor and initialize analyst notes simultaneously:

```bash
ruby scripts/import-analyst-notes.rb new \
  --actor "NewActor" \
  --country "IR" \
  --description "New Iranian actor" \
  --url "/newactor"
```

This creates both the actor and the `_data/analyst_notes/newactor.yml` file ready for structured notes.

---

## How Manual Entries Merge with Automated Imports

Manual entries are designed to work cleanly when automated importers eventually find the same actor:

### Protection Rules

| Field | Behavior |
|-------|----------|
| `source_name` | Sticky - won't be overwritten |
| `source_attribution` | Sticky - won't be overwritten |
| `description` | Protected unless empty |
| `name`, `aliases`, `country` | Merged additively |

Importers check these conditions:
```ruby
# Only set source if empty
if existing_actor['source_name'].to_s.empty?
  updates['source_name'] = SOURCE_NAME
end
```

### Takeover Behavior

When an importer finds an existing manual entry (source_name is `'Manual Entry'` or `'Analyst Notes'`):

1. **Converts manual entry to analyst notes** - All original manual data (description, aliases, country, etc.) is preserved in the `analyst_notes` field
2. **Takes over** - The automated source becomes the new `source_name` and `source_attribution`
3. **Logs the takeover** - Shows `TAKEOVER: Converted manual entry 'X' to analyst notes`

This ensures:
- No data is lost - original manual notes preserved
- Automated attribution replaces manual
- Both sources are tracked in history

---

## Workflow Summary

| Scenario | Action |
|----------|--------|
| Add new TA from scratch | Use `actor-creator.rb new` |
| Add structured notes | Use `import-analyst-notes.rb init` + edit YAML |
| Enrich existing TA | Use `import-analyst-notes.rb import` |
| Automated source finds manual TA | Automatic conversion + takeover |
