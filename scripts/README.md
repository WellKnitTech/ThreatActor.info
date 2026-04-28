# Scripts Reference

This directory contains Ruby scripts for managing threat actor data, importing external sources, and generating the static site.

## Quick Reference

| Script | Purpose | Frequency |
|--------|--------|----------|
| `add-actor.rb` | Add a new threat actor in <2 min | On-demand |
| `generate-pages.rb` | Generate MD pages from YAML | After edits |
| `generate-indexes.rb` | Build JSON API artifacts | After edits |
| `validate-content.rb` | Validate all content | Before PR |
| `import-automated-sources.rb` | Run snapshot-backed public source imports | Scheduled / on-demand |
| `import-*.rb` | Import from external sources | As needed |

---

## Core Scripts

### actor-creator.rb

Interactive actor creation tool. Creates YAML + generates page.

```bash
ruby scripts/actor-creator.rb new \
  --name "Name" \
  --alias "Alias1" \
  --alias "Alias2" \
  --country "Country" \
  --description "Description"
```

**Creates:**
- `_data/actors/<slug>.yml`
- `_threat_actors/<slug>.md`

---

### generate-pages.rb

Regenerates all threat actor markdown pages from `_data/actors/*.yml`.

```bash
ruby scripts/generate-pages.rb          # Normal run
ruby scripts/generate-pages.rb --force  # Force overwrite
ruby scripts/generate-pages.rb --dry-run  # Preview only
```

**Outputs:** `_threat_actors/*.md`

---

### generate-indexes.rb

Builds JSON artifacts for the search UI and static API.

```bash
ruby scripts/generate-indexes.rb
```

**Outputs:**
- `_data/generated/threat_actors.json`
- `_data/generated/iocs.json`
- `_data/generated/facets.json`
- `_data/generated/campaigns.json`
- `_data/generated/malware.json`
- `_data/generated/attack_mappings.json`
- `_data/generated/references.json`
- `_data/generated/ioc_lookup.json`
- `_data/generated/ioc_types.json`
- `_data/generated/iocs_by_type/*.json`

---

### validate-content.rb

Validates all content and generated artifacts.

```bash
ruby scripts/validate-content.rb
```

**Checks:**
- YAML parsing
- Required files exist
- Duplicate names/URLs
- Page front matter
- JSON parseability
- IOC shard structure

---

## Import Scripts

### import-automated-sources.rb

Run the standard automated import set. Analyst notes are intentionally excluded from this runner and stay a separate manual enrichment path.

```bash
ruby scripts/import-automated-sources.rb                  # Fetch + plan
ruby scripts/import-automated-sources.rb --apply          # Import + regenerate + validate
ruby scripts/import-automated-sources.rb --source malpedia # Limit to one source
```

---

### import-mitre.rb

Import MITRE ATT&CK groups.

```bash
ruby scripts/import-mitre.rb --dry-run    # Preview
ruby scripts/import-mitre.rb             # Apply
ruby scripts/import-mitre.rb --overwrite # Force overwrite
```

---

### import-misp-galaxy.rb

Import MISP Galaxy threat actors.

```bash
# Fetch snapshot
ruby scripts/import-misp-galaxy.rb fetch --output data/imports/misp-galaxy/$(date +%F)

# Preview import
ruby scripts/import-misp-galaxy.rb import --snapshot data/imports/misp-galaxy/DATE

# Apply import
ruby scripts/import-misp-galaxy.rb import --snapshot data/imports/misp-galaxy/DATE --write
```

---

### import-ransomlook.rb

Import RansomLook ransomware tracking data.

```bash
# Fetch snapshot
ruby scripts/import-ransomlook.rb fetch --output data/imports/ransomlook/$(date +%F) --limit 10

# Preview
ruby scripts/import-ransomlook.rb plan --snapshot data/imports/ransomlook/DATE

# Apply
ruby scripts/import-ransomlook.rb import --snapshot data/imports/ransomlook/DATE
```

---

### import-etda-thaicert.rb

Import ETDA/ThaiCERT threat group cards.

```bash
# Fetch snapshot
ruby scripts/import-etda-thaicert.rb fetch

# Preview
ruby scripts/import-etda-thaicert.rb plan --snapshot data/imports/etda-thaicert/DATE

# Apply
ruby scripts/import-etda-thaicert.rb import --snapshot data/imports/etda-thaicert/DATE
```

---

### import-malpedia.rb

Import Malpedia malware/enrichment data.

```bash
ruby scripts/import-malpedia.rb fetch --output data/imports/malpedia/$(date +%F)
ruby scripts/import-malpedia.rb import --snapshot data/imports/malpedia/DATE
```

---

### import-apt-groups-operations.rb

Import APT Groups & Operations tracking.

```bash
ruby scripts/import-apt-groups-operations.rb fetch --output data/imports/apt-groups-operations/$(date +%F)
ruby scripts/import-apt-groups-operations.rb import --snapshot data/imports/apt-groups-operations/DATE
```

---

### import-eternal-liberty.rb

Import EternalLiberty alias crosswalk data for existing actors.

```bash
ruby scripts/import-eternal-liberty.rb fetch --output data/imports/eternal-liberty/$(date +%F)
ruby scripts/import-eternal-liberty.rb plan --snapshot data/imports/eternal-liberty/DATE
ruby scripts/import-eternal-liberty.rb import --snapshot data/imports/eternal-liberty/DATE
```

---

### import-ransomware-tool-matrix.rb

Import BushidoUK Ransomware Tool Matrix observations for existing actors.

```bash
ruby scripts/import-ransomware-tool-matrix.rb fetch --output data/imports/ransomware-tool-matrix/$(date +%F)
ruby scripts/import-ransomware-tool-matrix.rb plan --snapshot data/imports/ransomware-tool-matrix/DATE
ruby scripts/import-ransomware-tool-matrix.rb import --snapshot data/imports/ransomware-tool-matrix/DATE
```

---

### import-ransomware-vulnerability-matrix.rb

Import BushidoUK Ransomware Vulnerability Matrix observations for existing actors.

```bash
ruby scripts/import-ransomware-vulnerability-matrix.rb fetch --output data/imports/ransomware-vulnerability-matrix/$(date +%F)
ruby scripts/import-ransomware-vulnerability-matrix.rb plan --snapshot data/imports/ransomware-vulnerability-matrix/DATE
ruby scripts/import-ransomware-vulnerability-matrix.rb import --snapshot data/imports/ransomware-vulnerability-matrix/DATE
```

---

### import-aptnotes.rb

Import APTnotes references.

```bash
ruby scripts/import-aptnotes.rb fetch --output data/imports/aptnotes/$(date +%F)
ruby scripts/import-aptnotes.rb import --snapshot data/imports/aptnotes/DATE
```

---

### import-cisa-kev.rb

Import CISA Known Exploited Vulnerabilities catalog.

```bash
ruby scripts/import-cisa-kev.rb fetch
ruby scripts/import-cisa-kev.rb map    # Map CVEs to actors
```

---

## Utility Scripts

### fetch-news.rb

Fetches daily security news for auto-generated pages.

```bash
ruby scripts/fetch-news.rb
```

---

### fetch-misp-references.rb

Fetches MISP reference data for linking.

```bash
ruby scripts/fetch-misp-references.rb
```

---

### backfill-source-attribution.rb

Adds source attribution to actors missing it.

```bash
ruby scripts/backfill-source-attribution.rb
```

---

### evaluate-source-deltas.rb

Evaluates changes between snapshots.

```bash
ruby scripts/evaluate-source-deltas.rb \
  --current _data/actors \
  --previous tmp/delta-baseline/actors \
  --report-json tmp/report.json \
  --max-change-ratio 0.10
```

---

### actor-creator.rb

Interactive actor creation (alternative to CLI in add-actor.rb).

```bash
ruby scripts/actor-creator.rb
```

---

### actor_store.rb

Shared library for loading/saving actor YAML.

```ruby
require_relative 'actor_store'

actors = ActorStore.load_all    # Load all actors
ActorStore.save_all(actors)    # Save all actors
```

---

### scrape-beazley.rb

One-off scraper for Beazley threat data.

```bash
ruby scripts/scrape-beazley.rb
```

---

### import-analyst-notes.rb

Batch import of analyst notes.

```bash
ruby scripts/import-analyst-notes.rb
```

---

### validate.sh

Full validation wrapper.

```bash
bash scripts/validate.sh
```

---

## Common Workflows

### Add New Actor (Recommended)

```bash
# 1. Add actor via CLI
ruby scripts/add-actor.rb --name "..." --aliases "..." --country "..." --description "..." --url "/..."

# 2. Optionally edit YAML for more fields
# nano _data/actors/<slug>.yml

# 3. Generate pages and indexes
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb

# 4. Validate
ruby scripts/validate-content.rb
```

### Import From External Source

```bash
# 1. Fetch snapshot
ruby scripts/import-SOURCE.rb fetch --output data/imports/SOURCE/$(date +%F)

# 2. Preview changes
ruby scripts/import-SOURCE.rb plan --snapshot data/imports/SOURCE/DATE

# 3. Apply (after review)
ruby scripts/import-SOURCE.rb import --snapshot data/imports/SOURCE/DATE --write

# 4. Generate pages and indexes
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb

# 5. Validate
ruby scripts/validate-content.rb
```

### Full Local Build

```bash
# Generate all artifacts
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb

# Validate
ruby scripts/validate-content.rb

# Build site
bundle exec jekyll build --safe
```

---

## Documentation

- [Schema Reference](../docs/schema.md) - YAML fields and types
- [Importer Guide](../docs/importers.md) - Source import workflows
- [API Documentation](../docs/api.md) - JSON endpoint shapes