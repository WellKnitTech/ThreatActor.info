# AGENTS.md

Guidance for OpenCode sessions in this repository. Keep this file compact and repo-specific.

## Repo Shape

- This is a Ruby/Jekyll 4 static site. Use Ruby `3.2.5` from `.ruby-version` and Bundler `2.5.10` from `Gemfile.lock`.
- There is no Node toolchain, package manager, TypeScript, Makefile, Rakefile, RuboCop, or conventional unit-test suite.
- Canonical actor metadata is `_data/actors/*.yml`; actor pages in `_threat_actors/*.md` and public JSON under `_data/generated/*` plus `api/*` are regenerated from it.
- `scripts/generate-indexes.rb` also writes `_malware/`, MITRE-derived indexes/pages, IOC shards under `_data/generated/iocs_by_*`, mirrored `api/iocs/by-*`, and may use `data/mitre-cache/` or MITRE snapshots.
- Do not edit `_site/`; it is Jekyll build output.

## Commands

- Setup: `gem install bundler -v 2.5.10 && bundle install`
- Local server: `bundle exec jekyll serve`
- Focused content check: `ruby scripts/validate-content.rb`
- JSON schema check: `ruby scripts/validate-json-schemas.rb`
- Safe build: `bundle exec jekyll build --safe`
- Canonical CI-equivalent validation: `bash scripts/validate.sh`

`scripts/validate.sh` runs, in order: `generate-pages.rb --force`, `generate-indexes.rb`, JSON schema validation, content validation, `jekyll doctor` (warnings allowed), `jekyll build --safe`, then parses `_site/api/**/*.json`.

## Content Workflow

- After editing `_data/actors/*.yml`, run `ruby scripts/generate-pages.rb --force` then `ruby scripts/generate-indexes.rb` before validating.
- Commit actor YAML, matching `_threat_actors/*.md`, `_data/generated/*`, `api/*`, IOC shards, and `_malware/` together when generators change them.
- `generate-pages.rb` without `--force` can skip pages it considers manually enriched; CI and Pages use `--force`, so use `--force` locally after imports or YAML edits.
- There is no single-file test runner. The closest focused verification for content changes is `ruby scripts/validate-content.rb`; use `bash scripts/validate.sh` before PR-sized data or generator changes.

## Actor Data Rules

- Each `_data/actors/*.yml` record needs `name`, `aliases`, `description`, and `url`.
- Keep `_data/actors/<slug>.yml`, `_threat_actors/<slug>.md`, YAML `url: /<slug>`, and page `permalink: /<slug>/` synchronized.
- Actor page front matter must use `layout: threat_actor`, and `title` must match YAML `name`.
- Use double-quoted YAML strings and keep existing inline arrays such as `aliases` and `sector_focus` unless making a deliberate schema-wide change.
- Prefer structured IOCs under `iocs:` in actor YAML; `scripts/ioc_yaml_reader.rb` merges these with legacy IOC lists for page and API generation.

## Importers

- Standard public-source runner: `ruby scripts/import-automated-sources.rb` for preview, `ruby scripts/import-automated-sources.rb --apply` to import, regenerate, and validate content.
- Run one automated source with `ruby scripts/import-automated-sources.rb --source <source-key> --apply`.
- Analyst notes are intentionally separate: `ruby scripts/import-analyst-notes.rb plan` and `ruby scripts/import-analyst-notes.rb import`.
- Importer snapshots live under `data/imports/<source>/<date>/`; Jekyll builds must remain deterministic and not depend on live network fetches.
- When adding or renaming an importer source, update `docs/importers.md` and `/attribution/` in `attribution.md`, and preserve stable provenance/source URL fields in actor YAML.
- In `scripts/import-automated-sources.rb`, source priority is intentional: MITRE ATT&CK must remain priority `1`; lower priority runs first and priorities must be unique.

## MITRE And API Gotchas

- MITRE ATT&CK pages are generated/imported under `_techniques/`, `_tactics/`, `_campaigns/`, `_mitigations/`, and MITRE software entries in `_malware/`.
- `scripts/mitre/version_resolver.rb` resolves snapshots first, then `data/mitre-cache/active.yml`, then network fetch; see `docs/offline-mitre-bundles.md` before changing offline behavior.
- UI pages such as `ttps.html` and `categorized-adversary-ttps.html` consume generated `/api/*.json` payloads, including both hyphenated current paths and some legacy underscore paths. Preserve existing API aliases unless intentionally migrating clients.

## CI And Deploy

- `.github/workflows/validate.yml` runs `bash scripts/validate.sh` on pushes to `main`/`develop` and PRs to `main`.
- `.github/workflows/pages.yml` regenerates pages/indexes and builds with `bundle exec jekyll build --safe`; do not switch to `actions/jekyll-build-pages@v1` because it uses older GitHub Pages/Jekyll 3 dependencies that conflict with this Gemfile.
- Scheduled data workflows may push generated updates directly; do not assume weekly data refresh covers the same source set as `import-automated-sources.rb`.
