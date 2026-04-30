[![Jekyll](https://img.shields.io/badge/Jekyll-4.4+-2e2642?style=flat&logo=jekyll)](https://jekyllrb.com)
[![Ruby](https://img.shields.io/badge/Ruby-3.2.5-CC342D?style=flat&logo=ruby)](https://www.ruby-lang.org)
[![License: Unlicense](https://img.shields.io/badge/License-Public%20Domain-success?style=flat)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-24292F?style=flat&logo=github)](https://wellknittech.github.io/ThreatActor.info/)

# ThreatActor.info

ThreatActor.info is a static Jekyll knowledge base for threat actors, campaigns, malware, indicators, and related intelligence artifacts. The repository stores canonical actor metadata in YAML, synchronizes actor pages from that data, and generates static JSON APIs for the site UI and downstream use.

Live site: https://wellknittech.github.io/ThreatActor.info/

## What the project does

- Maintains canonical actor records in `_data/actors/*.yml`
- Synchronizes actor pages in `_threat_actors/*.md`
- Generates static API artifacts in `_data/generated/*.json` and `api/*.json`
- Extracts malware, campaigns, ATT&CK mappings, references, and IOCs from actor content
- Supports repeatable snapshot-based imports from public intelligence sources
- Validates schema, page alignment, generated JSON, and safe Jekyll builds in CI

## Current repository state

- Jekyll static site with Ruby `3.2.5` and Bundler `2.5.10`
- `1062` actor YAML records currently committed under `_data/actors/`
- `271` malware pages currently committed under `_malware/`
- No Node, TypeScript, package manager, or conventional unit-test framework
- Validation is done through Ruby scripts plus `bundle exec jekyll build --safe`

## Repository layout

```text
_data/actors/              Canonical threat actor metadata
_data/generated/           Generated JSON artifacts used by the UI and API
_threat_actors/            Threat actor pages synchronized from YAML
_malware/                  Generated malware/tool pages and metadata
_layouts/                  Shared Jekyll layouts
_includes/                 Shared UI includes, including search/filter UI
api/                       Public static JSON API wrappers
assets/css/style.scss      Main stylesheet
scripts/                   Importers, generators, validators, and helpers
docs/                      Supporting docs for API, schema, and data flows
schemas/                   JSON schemas for generated artifacts
```

## Setup

Run from the repository root:

```bash
gem install bundler -v 2.5.10
bundle install
```

## Local development

Serve the site locally:

```bash
bundle exec jekyll serve
```

Build the site without serving:

```bash
bundle exec jekyll build --safe
```

## Core workflow

The normal data flow is:

1. Import or edit actor source data in `_data/actors/*.yml`
2. Synchronize pages with `ruby scripts/generate-pages.rb --force` when needed
3. Regenerate indexes with `ruby scripts/generate-indexes.rb`
4. Validate content with `ruby scripts/validate-content.rb`
5. Validate generated schemas with `ruby scripts/validate-json-schemas.rb`
6. Confirm the site builds with `bundle exec jekyll build --safe`

Useful commands:

```bash
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb
ruby scripts/validate-content.rb
ruby scripts/validate-json-schemas.rb
bash scripts/validate.sh
```

## Import workflows

The standard automated entry point is `scripts/import-automated-sources.rb`.

Preview automated imports without modifying actor data:

```bash
ruby scripts/import-automated-sources.rb
```

Apply automated imports, regenerate outputs, and validate content:

```bash
ruby scripts/import-automated-sources.rb --apply
```

Run one source only:

```bash
ruby scripts/import-automated-sources.rb --source malpedia --apply
```

Public snapshot-backed sources currently supported by the automated runner include:

- `misp-galaxy`
- `ransomlook`
- `etda-thaicert`
- `malpedia`
- `microsoft-threat-actor-list`
- `apt-groups-operations`
- `aptnotes`
- `ransomware-tool-matrix`
- `curated-intel-moveit-transfer`
- `ransomware-vulnerability-matrix`
- `russian-apt-tool-matrix`

Analyst notes are intentionally separate from the public automated runner:

```bash
ruby scripts/import-analyst-notes.rb plan
ruby scripts/import-analyst-notes.rb import
```

More importer details: `docs/importers.md`, `docs/data-flows.md`, `scripts/README.md`

## Static API

The site publishes static JSON under `api/`. Main endpoints include:

- `api/threat-actors.json`
- `api/recently-updated.json`
- `api/campaigns.json`
- `api/malware.json`
- `api/malware-index.json` (legacy: `api/malware_index.json`)
- `api/attack-mappings.json`
- `api/references.json`
- `api/iocs.json`
- `api/ioc-lookup.json`
- `api/ioc-types.json`
- `api/facets.json`

API details: `docs/api.md`

## Validation and CI

This repository does not use a conventional test suite. In practice, validation means:

- `ruby scripts/validate-content.rb`
- `ruby scripts/validate-json-schemas.rb`
- `bundle exec jekyll build --safe`

CI workflows also regenerate pages and indexes, parse built API JSON, and check for schema and content regressions.

## Editing rules for contributors

- Treat `_data/actors/*.yml` as the canonical actor metadata layer
- Keep the actor YAML `url`, page file path, and page `permalink` aligned
- Use double-quoted YAML strings to match the existing dataset
- Keep `aliases` and `sector_focus` inline unless a broader format change is required
- Do not edit generated output in `_site/`
- After content changes, run `ruby scripts/validate-content.rb`
- After layout, include, CSS, or config changes, run `bundle exec jekyll build --safe`

## Documentation map

- `docs/api.md` - static API endpoints and fields
- `docs/data-flows.md` - canonical source layers and importer flow
- `docs/importers.md` - importer-specific behavior and guardrails
- `docs/schema.md` - actor schema notes
- `scripts/README.md` - script quick reference and usage examples
- `AGENTS.md` - repository-specific guidance for coding agents

## Contributing

Contributions are welcome. For most changes:

1. Edit or import source data
2. Regenerate pages and indexes as needed
3. Run validation
4. Open a pull request with the changed source files and generated artifacts

If you are adding a new importer or changing source attribution behavior, also update the relevant docs in `docs/` and `scripts/README.md`.
