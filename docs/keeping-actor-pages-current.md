# Keeping threat actor pages in sync with provenance

Threat actor **pages** (`_threat_actors/*.md`) and **API/search indexes** (`_data/generated/*`, `api/*`) are **generated from** `_data/actors/*.yml`. Importers and analysts update YAML (including `provenance`); generation turns that into Markdown and JSON. The live site only reflects what is **committed** to the branch GitHub builds (usually `main`).

See also: [Importers](importers.md), [Data flows](data-flows.md), [Supersession backlog](supersession-backlog.md).

## After imports or YAML edits

1. **Imports update YAML** (and sometimes `_malware/`, snapshots under `data/imports/`, etc.). They do **not** automatically update your git working tree for Markdown until you run generators.
2. **Regenerate pages and indexes** (same order as CI):

   ```bash
   ruby scripts/generate-pages.rb --force
   ruby scripts/generate-indexes.rb
   ruby scripts/validate-content.rb
   ```

   For a full check identical to **Content Validation** on GitHub, run:

   ```bash
   bash scripts/validate.sh
   ```

3. **Commit together** so reviewers and Pages see one coherent change:

   - `_data/actors/*.yml`
   - `_threat_actors/*.md`
   - `_data/generated/*` and `api/*` (and IOC shards under `_data/generated/iocs_by_type/` when present)
   - `_malware/` when MITRE or other importers touch collection pages

   [`scripts/import-automated-sources.rb`](../scripts/import-automated-sources.rb) with `--apply` already runs `generate-pages --force`, `generate-indexes`, and `validate-content` before opening a PR; the PR should include these paths when you merge automated import branches.

## `--force` vs local skips

Without `--force`, [`scripts/generate-pages.rb`](../scripts/generate-pages.rb) may **skip** overwriting existing pages that match **enriched** heuristics (`enriched_page?`), to avoid clobbering hand-heavy Markdown.

**CI and GitHub Pages** always run `generate-pages.rb --force`, so `main` stays aligned with committed YAML. Locally, use `--force` after imports so your Markdown matches YAML before you commit.

## Which automation does what

| Workflow | Role |
|----------|------|
| [`.github/workflows/import-sources.yml`](../.github/workflows/import-sources.yml) | Full **`import-automated-sources.rb --apply`** (all configured sources in priority order), regenerates pages/indexes, validates content, **`jekyll build`**, opens a PR with actor + generated + api paths. **Primary path for a broad, PR-reviewed refresh.** |
| [`.github/workflows/weekly-data.yml`](../.github/workflows/weekly-data.yml) | Partial fetch/import subset (MISP, ETDA, Malpedia, APT spreadsheet, APTnotes, RansomLook, CISA KEV, etc.), then generators and push to `main`. **Does not replace every source** in `import-automated-sources.rb`. |
| [`.github/workflows/daily-news.yml`](../.github/workflows/daily-news.yml) | News feed + generators + validators + build; commits news-related updates. |
| [`.github/workflows/validate.yml`](../.github/workflows/validate.yml) | Runs **`scripts/validate.sh`** on pushes/PRs. |
| [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) | On push to `main`: regenerate pages/indexes, build `_site`, deploy Pages. |

Do not assume weekly pushes alone cover the same surface as **Automated Source Imports**; use the right workflow for the sources you care about.

## GitHub repository settings (manual)

Configure in the GitHub UI (org/repo **Settings**):

1. **Branch protection on `main`:** Require the **Content Validation** workflow (or its check names) to pass before merge, so broken YAML or generator output does not ship.
2. **GitHub Pages:** Set **Source** to **GitHub Actions** so [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) deploys the site (Jekyll 4 from this repo’s `Gemfile`, not the legacy `github-pages` gem image).

## Verification checklist

1. Locally: `bash scripts/validate.sh` exits 0 (Ruby 3.2.5, `bundle install` first per [AGENTS.md](../AGENTS.md)).
2. After doc or workflow edits: open a PR to `main` and confirm **Content Validation** passes.
3. Optional: **Actions → Automated Source Imports → Run workflow** (optionally set `source` / `limit`); merge the opened PR and spot-check an actor’s page for expected `provenance`-driven sections.
