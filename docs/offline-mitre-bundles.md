# Offline MITRE ATT&CK bundles for `generate-indexes`

[`scripts/generate-indexes.rb`](../scripts/generate-indexes.rb) loads Enterprise, Mobile, and ICS STIX bundles through [`scripts/mitre/version_resolver.rb`](../scripts/mitre/version_resolver.rb). Resolution order:

1. **Newest importer snapshot** — `data/imports/mitre-attack/<date>/manifest.yml` plus bundle files listed under `bundles:` (all three domains must be present on disk).
2. **`data/mitre-cache/active.yml`** — points each domain at a bundle file under `data/mitre-cache/` (often copied by `scripts/import-mitre.rb fetch --write-active`).
3. **Optional network fetch** — only when `resolve(fetch_network: true)` runs (index generation enables this); requires connectivity and may write into `data/mitre-cache/`.
4. **Legacy fallback** — Enterprise-only path if nothing else succeeds.

## Why this matters

Without at least one complete offline source (snapshot or active cache), the resolver can fail or downgrade. Symptoms:

- Warning: `MITRE bundle resolver unavailable for indexes`
- Sparse **`technique_tactics.json`** / **`actors_by_tactic.json`**
- Weak **`attack_version.json`** metadata
- Footer ATT&CK version label may not update

`data/mitre-cache/` is **gitignored** (large binaries). CI typically relies on **network fetch** during `generate-indexes.rb` unless you commit a dated **`data/imports/mitre-attack/<date>/`** snapshot with all bundle files.

## Filling local cache (operators)

```bash
ruby scripts/import-mitre.rb fetch --output data/imports/mitre-attack/$(date -I)
```

With default `--write-active`, bundles are copied for offline use and **`active.yml`** is refreshed. Then regenerate indexes **without** relying on fetch:

```bash
ruby scripts/generate-indexes.rb
```

For reproducible CI, prefer committing snapshot manifests + bundles under `data/imports/mitre-attack/` per [MITRE importer docs](importers.md).

## Refreshing MITRE collection pages and actor TTPs (stub replacement)

Stub **`_techniques/`** and **`_tactics/`** pages and YAML **`ttps`** fields are filled by applying an importer snapshot:

```bash
ruby scripts/import-mitre.rb plan --snapshot data/imports/mitre-attack/<YYYY-MM-DD> --report-json tmp/mitre-plan.json
ruby scripts/import-mitre.rb import --snapshot data/imports/mitre-attack/<YYYY-MM-DD> --report-json tmp/mitre-import.json
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb
ruby scripts/validate-content.rb
```

**Maintenance cadence:** Re-run after each major ATT&CK release you want reflected site-wide, or when validator warns about missing **`attack_version`** on large numbers of technique/tactic pages.

See [Importers: MITRE ATT&CK STIX Importer](importers.md#mitre-attck-stix-importer).
