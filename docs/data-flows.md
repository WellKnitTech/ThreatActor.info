# Data Flow Assessment

This project is a static Jekyll knowledge base. Runtime pages and JSON APIs are deterministic outputs from committed source files, importer snapshots, and generation scripts.

## Current data flow

1. Automated source importers fetch operational snapshots into ignored `data/imports/<source>/<date>/` cache paths.
2. Importers read snapshots, apply committed mapping overrides, and update `_data/actors/*.yml`.
3. `scripts/generate-pages.rb --force` synchronizes `_threat_actors/*.md` from actor YAML while preserving enriched page content.
4. `scripts/generate-indexes.rb` reads actor YAML and actor pages, then regenerates `_data/generated/*.json`, `_malware/*.md`, `_malware/*.data.json`, and IOC shards.
5. Jekyll renders collection pages and API wrappers in `api/*.json` into `_site/`.
6. Validators check actor schema, page alignment, generated JSON parseability, malware links, IOC shards, and the final safe Jekyll build.

## Canonical source layers

| Layer | Canonical files | Owner |
|-------|-----------------|-------|
| Automated actor metadata | `_data/actors/*.yml` | Importers |
| Source mapping overrides | `data/imports/*/mapping_overrides.yml` | Analysts and importer owners |
| Analyst notes | `_data/analyst_notes/*.yml` and generated note sections in pages | Analysts |
| Threat actor pages | `_threat_actors/*.md` | Generators plus curated page enrichment |
| Malware pages | `_malware/*.md` and `_malware/*.data.json` | `scripts/generate-indexes.rb` |
| Static API data | `_data/generated/*.json` and `api/*.json` wrappers | Generators |

## Automated import sources

`scripts/import-automated-sources.rb` is the standard automated entry point. It runs only machine-consumable public sources and intentionally excludes analyst notes.

| Source key | Script | Role |
|------------|--------|------|
| `misp-galaxy` | `scripts/import-misp-galaxy.rb` | Canonical threat actor identities and references |
| `ransomlook` | `scripts/import-ransomlook.rb` | Ransomware group identities and attribution-backed enrichment |
| `etda-thaicert` | `scripts/import-etda-thaicert.rb` | Threat group cards, aliases, malware, operations, and timeline hints |
| `malpedia` | `scripts/import-malpedia.rb` | Malware-family and actor relationship enrichment for existing actors |
| `apt-groups-operations` | `scripts/import-apt-groups-operations.rb` | Alias, operation, and malware crosswalk enrichment |
| `aptnotes` | `scripts/import-aptnotes.rb` | Report-index provenance and chronology hints |

`scripts/import-cisa-kev.rb`, `scripts/import-mitre.rb`, `scripts/fetch-news.rb`, `scripts/fetch-misp-references.rb`, and `scripts/scrape-beazley.rb` are not part of the default automated import run. They should either be promoted into the standard runner after their review semantics match the snapshot/import/report pattern, or remain documented as one-off/manual utilities.

## Analyst note policy

Analyst notes are the only manual source. They exist to capture context before a public automated source contains the actor, malware, operation, or indicator.

- Analysts may create `_data/analyst_notes/*.yml` and generated actor pages for uncovered subjects.
- Analyst note imports must be additive and must not overwrite automated source identity, attribution, or provenance.
- When an automated source later matches the same actor, the automated record becomes primary. The previous analyst-created identity is preserved as `analyst_notes` and source fields move to the automated importer.
- When an automated source later matches malware named in analyst notes, the generated `_malware/<slug>.md` page and malware index become primary. Analyst text remains supporting context on the actor page.
- Manual actor creation is temporary coverage. It should use `source_name: "Analyst Notes"` or `source_name: "Manual Entry"` so automated importers can recognize takeover candidates.

## Supersession gaps to close

The repository already implements manual takeover in the RansomLook and ETDA importers. That behavior is not yet centralized across every importer.

Required follow-up engineering:

- Move manual-takeover behavior into shared importer utilities so MISP Galaxy, MITRE, Malpedia, APTnotes, and APT Groups & Operations follow the same actor supersession policy.
- Add field-level provenance for actor arrays such as `malware`, `operations`, `ttps`, and IOCs so generated malware pages can distinguish automated observations from analyst observations.
- Validate that actor YAML records with `source_name: "Analyst Notes"` are never left primary when provenance exists for an automated identity source.
- Remove or replace one-off import scripts that cannot produce snapshots, reports, and deterministic apply behavior.

## Operating workflow

Preview all automated sources without modifying actor data:

```bash
ruby scripts/import-automated-sources.rb
```

Apply all automated imports, regenerate pages and indexes, and validate content:

```bash
ruby scripts/import-automated-sources.rb --apply
```

Plan from already-fetched snapshots:

```bash
ruby scripts/import-automated-sources.rb --plan-only --date 2026-04-28
```

Run one source:

```bash
ruby scripts/import-automated-sources.rb --source malpedia --apply
```

Import analyst notes separately:

```bash
ruby scripts/import-analyst-notes.rb plan
ruby scripts/import-analyst-notes.rb import
```

## Assessment conclusion

The project has a strong deterministic build flow after source data lands in the repository, but import execution was operator-driven. The new automated import runner and scheduled workflow establish an automated path for public sources while preserving analyst notes as the only manual input. Supersession is partially implemented today and should be centralized next so every importer consistently promotes automated actor and malware observations over analyst-derived placeholders.
