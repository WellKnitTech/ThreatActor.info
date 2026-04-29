# New actor checklist (YAML + Markdown parity)

Threat actors must exist in **both** `_data/actors/*.yml` and `_threat_actors/*.md`. [`scripts/generate-indexes.rb`](../scripts/generate-indexes.rb) skips YAML-only actors (`next unless page`), so they never appear in `/api/threat-actors.json`, search, or facets.

## Checklist

1. **Create or update YAML** — `_data/actors/<slug>.yml` with required fields (`name`, `aliases`, `description`, `url`, …). Prefer [`scripts/actor-creator.rb`](../scripts/actor-creator.rb) for new actors.
2. **Ensure a Markdown page exists** — `_threat_actors/<slug>.md` with matching `permalink` (`#{url}/`).
3. **Regenerate if needed** — `ruby scripts/generate-pages.rb` (use `--force` when regenerating from YAML is intentional and merge conflicts with manual enrichment are acceptable).
4. **Regenerate indexes** — `ruby scripts/generate-indexes.rb`.
5. **Validate** — `ruby scripts/validate-content.rb`.
6. **Build** — `bundle exec jekyll build --safe` (or rely on CI).

## Importers

When an automated importer updates **`_data/actors/*.yml`**, run **`generate-pages.rb`** per [Importer automation policy](importers.md#automation-policy) so Markdown stays aligned unless the page is manually enriched (skipped without `--force`).

See [Contributing](../CONTRIBUTING.md#-add-one-new-actor--2-minutes).
