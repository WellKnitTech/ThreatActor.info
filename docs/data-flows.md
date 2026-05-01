# Data Flow Assessment

This project is a static Jekyll knowledge base. Runtime pages and JSON APIs are deterministic outputs from committed source files, importer snapshots, and generation scripts.

For a concise maintainer checklist (commands, what to commit, and which workflows refresh what), see **[Keeping actor pages current](keeping-actor-pages-current.md)**.

## Current data flow

1. Automated source importers fetch operational snapshots into ignored `data/imports/<source>/<date>/` cache paths.
2. Importers read snapshots, apply committed mapping overrides, and update `_data/actors/*.yml`.
3. `scripts/generate-pages.rb --force` synchronizes `_threat_actors/*.md` from actor YAML while preserving enriched page content.
4. `scripts/generate-indexes.rb` reads actor YAML and actor pages, then regenerates `_data/generated/*.json`, `_malware/*.md`, `_malware/*.data.json`, optional MITRE collection pages under `_techniques/`, `_tactics/`, `_campaigns/`, and `_mitigations/`, IOC manifest (`ioc_types.json`), IOC summary (`ioc_summary.json`), per-type IOC shards with server-side grouping (`_data/generated/iocs_by_type/*.json` plus mirrored `api/iocs/by-type/` payloads), per-actor IOC shards (`_data/generated/iocs_by_actor/<slug>.json` plus mirrored `api/iocs/by-actor/<slug>.json`), and `malware_actor_lookup.json`. When no `_tactics/` pages exist, it can pull the Enterprise ATT&CK STIX bundle into `data/mitre-cache/` (first run with network) to emit full `techniques.json`, `technique_tactics.json`, `actors_by_tactic.json`, and stub `_tactics/*.md` pages.
5. Jekyll renders collection pages and API wrappers in `api/*.json` into `_site/`.
6. Validators check actor schema, page alignment, generated JSON parseability, malware links, IOC shards, and the final safe Jekyll build.

## Canonical source layers

| Layer | Canonical files | Owner |
|-------|-----------------|-------|
| Automated actor metadata | `_data/actors/*.yml` | Importers |
| Source mapping overrides | `data/imports/*/mapping_overrides.yml` | Analysts and importer owners |
| Analyst notes | `_data/analyst_notes/*.yml` and generated note sections in pages | Analysts |
| Threat actor pages | `_threat_actors/*.md` | Generators plus curated page enrichment |
| Malware pages | `_malware/*.md` and `_malware/*.data.json` | `scripts/generate-indexes.rb` and `scripts/import-mitre.rb` (MITRE software) |
| MITRE knowledge pages | `_techniques/`, `_tactics/`, `_campaigns/`, `_mitigations/` | `scripts/import-mitre.rb` |
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
| `mitre-attack` | `scripts/import-mitre.rb` | MITRE ATT&CK STIX groups, techniques, tactics, software, campaigns, and mitigations |

`scripts/import-microsoft-threat-actor-list.rb` follows the snapshot/import/report pattern and is part of the default automated import run. Microsoft publishes the workbook for regular public use, so we treat it as a normal recurring source while still preserving attribution and limiting imports to additive existing-actor enrichment.

`scripts/import-cisa-kev.rb`, `scripts/fetch-news.rb`, `scripts/fetch-misp-references.rb`, and `scripts/scrape-beazley.rb` are not part of the default automated import run. They should either be promoted into the standard runner after their review semantics match the snapshot/import/report pattern, or remain documented as one-off/manual utilities.

## Analyst note policy

Analyst notes are the only manual source. They exist to capture context before a public automated source contains the actor, malware, operation, or indicator.

- Analysts may create `_data/analyst_notes/*.yml` and generated actor pages for uncovered subjects.
- Analyst note imports must be additive and must not overwrite automated source identity, attribution, or provenance.
- When an automated source later matches the same actor, the automated record becomes primary. The previous analyst-created identity is preserved as `analyst_notes` and source fields move to the automated importer.
- When an automated source later matches malware named in analyst notes, the generated `_malware/<slug>.md` page and malware index become primary. Analyst text remains supporting context on the actor page.
- Manual actor creation is temporary coverage. It should use `source_name: "Analyst Notes"` or `source_name: "Manual Entry"` so automated importers can recognize takeover candidates.

## Supersession gaps to close

The repository already implements manual takeover in the RansomLook and ETDA importers. That behavior is not yet centralized across every importer.

**Living backlog:** Track IDs and scope in [supersession-backlog.md](supersession-backlog.md).

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
