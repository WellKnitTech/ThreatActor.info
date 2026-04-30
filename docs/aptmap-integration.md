# APTmap integration status (automated source)

APTmap is integrated as a snapshot-based importer in the automated source pipeline (`fetch -> plan -> import`) rather than at Jekyll build time.

## Why this is the best approach in this repo

- The project already standardizes imports through standalone scripts and `data/imports/<source>/<date>/` snapshots.
- `scripts/import-automated-sources.rb` already orchestrates fetch/plan/import runs and optional regeneration/validation.
- CI already has workflows for scheduled imports plus validation, so APTmap can be slotted into a known path.

## Current implementation

1. **Importer script:** `scripts/import-aptmap.rb`
   - Commands: `fetch`, `plan`, `import` (same interface used by existing importers).
   - Snapshot output: `data/imports/aptmap/<YYYY-MM-DD>/`.
   - `fetch` captures:
     - `apt.json` (group metadata)
     - `apt_rel.json` (relationship graph)
     - a local `manifest.yml` with retrieval date, source URLs, and hash/checksum per file.

2. **Mapping/normalization layer**
   - Normalize APTmap actor rows into internal actor candidate objects:
     - `name`, `aliases`, `description`, `url`
     - optional `country`, `motivation`, `sector_focus`, `first_seen`
   - Prefer conservative writes: only update fields known to map cleanly.
   - Maintain `data/imports/aptmap/mapping_overrides.yml` for rename/merge overrides (same pattern as other source imports).

3. **Merge strategy (safety-first)**
   - `plan` should emit categorized diffs:
     - `new_actors`
     - `updated_fields`
     - `possible_matches`
     - `conflicts`
   - `import` should default to:
     - create new actor YAML + page only for high-confidence unique matches
     - update existing actors only for non-destructive metadata additions
     - never delete actor files automatically.

4. **Provenance and attribution**
   - Stamp updated/new actor YAML with `provenance` entries for:
     - source name `aptmap`
     - source dataset URL
     - retrieval date
   - Add/confirm attribution copy in `/attribution/` and importer docs.

5. **Automated runner integration**
   - `scripts/import-automated-sources.rb` includes a `Source.new` entry for `aptmap`:
     - `key: 'aptmap'`
     - `script: 'scripts/import-aptmap.rb'`
     - `snapshot_root: 'data/imports/aptmap'`
     - report file names aligned with existing convention.

6. **Workflow integration**
   - Include `aptmap` in `.github/workflows/import-sources.yml` via the automated runner (no one-off workflow needed).
   - Let existing regeneration/validation run unchanged (`generate-pages`, `generate-indexes`, `validate-content`).

## Data quality controls to implement

- **Alias collision protection:** if APTmap alias collides with existing actor names, require manual override.
- **URL slug policy:** generate stable slugs and do not rename existing actor slugs automatically.
- **Field confidence tiers:**
  - High confidence: name/aliases for matching.
  - Medium: geography/motivation/sector.
  - Low/no auto-write: highly interpretive narrative content.
- **Hard fail conditions:** malformed JSON, missing required keys, duplicate generated URLs.

## Operational notes

- `import` currently performs the same planning pass as `plan` (no actor file writes yet), which keeps APTmap safe to run on schedule while matching quality is reviewed.
- `--report-json` now creates parent directories automatically, so paths like `tmp/aptmap-report.json` work without pre-creating `tmp/`.

## Acceptance criteria

- `ruby scripts/import-aptmap.rb fetch --output data/imports/aptmap/<date>` succeeds.
- `plan` generates machine-readable report JSON with deterministic counts.
- `import` leaves repository in a state where:
  - `ruby scripts/validate-content.rb` passes.
  - `bundle exec jekyll build --safe` passes.
- Automated runner can execute APTmap alongside existing sources without custom workflow branching.

## Verification snapshot

The importer was verified against a live snapshot at `data/imports/aptmap/2026-04-30` using:

```bash
ruby scripts/import-aptmap.rb fetch --output data/imports/aptmap/2026-04-30
ruby scripts/import-aptmap.rb plan --snapshot data/imports/aptmap/2026-04-30 --report-json tmp/aptmap-report.json
ruby scripts/import-aptmap.rb import --snapshot data/imports/aptmap/2026-04-30 --report-json tmp/aptmap-import-report.json
```
