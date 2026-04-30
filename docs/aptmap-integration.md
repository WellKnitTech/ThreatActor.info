# APTmap integration plan (automated source)

## Recommendation

The best fit is to integrate **APTmap** as a new snapshot-based importer wired into the existing automated importer pipeline (`fetch -> plan -> import`) rather than reading it at Jekyll build time.

This keeps behavior consistent with current source automation, avoids introducing build-time network dependency, and preserves analyst review checkpoints.

## Why this is the best approach in this repo

- The project already standardizes imports through standalone scripts and `data/imports/<source>/<date>/` snapshots.
- `scripts/import-automated-sources.rb` already orchestrates fetch/plan/import runs and optional regeneration/validation.
- CI already has workflows for scheduled imports plus validation, so APTmap can be slotted into a known path.

## Proposed architecture

1. **New importer script:** `scripts/import-aptmap.rb`
   - Commands: `fetch`, `plan`, `import` (same interface used by existing importers).
   - Snapshot output: `data/imports/aptmap/<YYYY-MM-DD>/`.
   - Fetch should capture:
     - `apt.json` (group metadata)
     - `apt_rel.json` (relationship graph)
     - optional versioned snapshot files if present (for reproducibility)
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
   - Add a `Source.new` entry for `aptmap` in `scripts/import-automated-sources.rb`:
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

## Minimal rollout plan

1. Implement `fetch` only + snapshot manifest and checksums.
2. Implement `plan` report and validate on several snapshots.
3. Implement constrained `import` for new actors only.
4. Enable updates to existing actors behind explicit flag after confidence review.
5. Add to automated source schedule.

## Acceptance criteria

- `ruby scripts/import-aptmap.rb fetch --output data/imports/aptmap/<date>` succeeds.
- `plan` generates machine-readable report JSON with deterministic counts.
- `import` leaves repository in a state where:
  - `ruby scripts/validate-content.rb` passes.
  - `bundle exec jekyll build --safe` passes.
- Automated runner can execute APTmap alongside existing sources without custom workflow branching.

## Notes

During this assessment run, direct unauthenticated access to GitHub-hosted APTmap JSON endpoints was blocked in this environment (HTTP 403 / tunnel restrictions), so this recommendation is intentionally based on repository integration patterns and visible APTmap file inventory (`apt.json`, `apt_rel.json`, dated JSON snapshots) rather than a full schema reverse-engineering pass.
