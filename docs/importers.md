# Importers

This repository supports manual source importers that update `_data/threat_actors.yml` and `_threat_actors/*.md` without introducing build-time network dependencies.

## RansomLook Importer

`scripts/import-ransomlook.rb` is the first importer.

It is designed for two steps:

1. Fetch a local snapshot from RansomLook.
2. Review or apply the snapshot to the repo.

Reviewed name and rename handling lives in `data/imports/ransomlook/mapping_overrides.yml`.

### Why this workflow exists

- Jekyll builds must stay offline and deterministic.
- Canonical repo inputs remain `_data/threat_actors.yml` and `_threat_actors/*.md`.
- Imported metadata needs review, attribution, and safe handling before it becomes part of the site.

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

- Creates or updates actor metadata in `_data/threat_actors.yml`
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
