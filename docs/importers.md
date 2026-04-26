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

## What the importer updates

- Creates or updates actor metadata in `_data/threat_actors.yml`
- Creates new actor pages in `_threat_actors/*.md`
- Synchronizes front matter on updated pages

It does not automatically import volatile IOCs, leak-site mirrors, or other fast-changing infrastructure into the IOC pipeline.

## Attribution

RansomLook website content, API responses, and datasets are provided under CC BY 4.0.

The importer preserves and emits attribution using the pattern:

`Contains data derived from RansomLook, used under CC BY 4.0. Source: https://www.ransomlook.io/`

Imported records can also preserve provenance fields such as:

- `source_name`
- `source_attribution`
- `source_record_url`
- `source_license`
- `source_license_url`
- `provenance.source_dataset_url`
- `provenance.source_retrieved_at`
- `provenance.source_record_id`
- `provenance.source_transforms`

## Safe defaults

- Auto-create new pages only for high-confidence, non-excluded groups
- Auto-update existing actors only for additive alias and `last_activity` changes
- Skip or flag ambiguous matches for review
- Preserve curated markdown body content when updating existing actors
- Keep reviewed rename and alias exceptions in `data/imports/ransomlook/mapping_overrides.yml`

## Future automation direction

The importer is intentionally structured so it can evolve toward scheduled snapshot ingestion later.

Recommended future path:

1. Fetch RansomLook snapshots in CI or an external job.
2. Open review PRs from machine-generated snapshot reports.
3. Keep automatic writes limited to additive, high-confidence metadata.
4. Continue treating the repo YAML and Markdown as the source of truth.
