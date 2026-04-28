# API

This project publishes a static JSON API for threat actor metadata and extracted IOCs.

## Design

- Static files only; no runtime backend is required.
- Generated artifacts live in `_data/generated/`.
- Public API files are served from `api/`.
- Queries are exact-match or client-side filtered against static indexes.

## Generation

Rebuild API artifacts after content changes:

```bash
ruby scripts/generate-indexes.rb
```

## Endpoints

### `/api/threat-actors.json`

Array of actor records used by the site UI.

Fields include:

- `name`
- `aliases`
- `description`
- `url`
- `permalink`
- `country`
- `sector_focus`
- `first_seen`
- `last_activity`
- `last_updated`
- `risk_level`
- `page_path`
- `headings`
- `ioc_count`
- `ioc_types`
- `campaigns`
- `malware_and_tools`
- `attack_mappings`
- `references`

Optional source provenance fields may also be present when an actor entry was imported from a licensed upstream dataset:

- `source_name`
- `source_attribution`
- `source_record_url`
- `source_license`
- `source_license_url`
- `provenance`

When MITRE ATT&CK STIX import has run, records may also include:

- `mitre_ttps` (objects with `technique_id`, `technique_name`, `url`)
- `mitre_software` (objects with `mitre_id`, `name`, `url`, `type`)
- `mitre_campaigns_yaml` (objects with `campaign_id`, `name`, `url`)

### `/api/recently-updated.json`

Array of actor records with `last_updated` values, sorted newest first for homepage freshness cards.

Fields include:

- `name`
- `aliases`
- `description`
- `url`
- `permalink`
- `country`
- `sector_focus`
- `risk_level`
- `last_updated`
- `last_activity`
- `ioc_count`

### `/api/campaigns.json`

Array of flattened campaign entries extracted from `## Notable Campaigns`.

Fields include:

- `actor_name`
- `actor_slug`
- `actor_url`
- `actor_permalink`
- `ordinal`
- `name`
- `summary`
- `source_section`
- `source_file`

### `/api/malware.json`

Array of flattened malware and tool entries extracted from `## Malware and Tools`.

Fields include:

- `actor_name`
- `actor_slug`
- `actor_url`
- `actor_permalink`
- `category`
- `name`
- `summary`
- `is_software`
- `source_section`
- `source_file`

### `/api/attack-mappings.json`

Array of flattened ATT&CK mappings extracted from external links, TTP sections, and Atomic Red Team emulation sections.

Fields include:

- `actor_name`
- `actor_slug`
- `actor_url`
- `actor_permalink`
- `mapping_type`
- `id`
- `label`
- `name`
- `url`
- `source_section`
- `mapping_origin`

### `/api/references.json`

Array of flattened references and IOC source links.

Fields include:

- `actor_name`
- `actor_slug`
- `actor_url`
- `actor_permalink`
- `title`
- `url`
- `kind`
- `source_section`
- `source_subheading`
- `source_file`

### `/api/iocs.json`

Array of extracted IOC records.

Fields include:

- `actor_name`
- `actor_slug`
- `actor_url`
- `actor_permalink`
- `type`
- `inferred_type`
- `atomic`
- `heading`
- `label`
- `value`
- `normalized_value`
- `canonical_value`
- `legacy_normalized_value`
- `lookup_keys`
- `source_text`
- `source_file`

### `/api/facets.json`

Object containing generated filter values and top-level counts.

Fields include:

- `countries`
- `risk_levels`
- `sectors`
- `ioc_types`
- `counts`

### `/api/ioc-lookup.json`

Object keyed by normalized IOC value for exact-match lookups.

Example usage:

```js
const lookup = await fetch('/api/ioc-lookup.json').then((response) => response.json());
const match = lookup['45.32.22.62'];
```

Each value includes:

- `normalized_value`
- `types`
- `inferred_types`
- `actors`
- `matches`

### `/api/ioc-summary.json`

Aggregate IOC statistics for the IOC hub (`/iocs/`).

- `total_records` — all extracted IOC rows
- `total_unique_values` — distinct `normalized_value` count
- `actor_count_with_iocs` — distinct actors with at least one IOC
- `type_count` — number of distinct `type` values in the manifest

### `/api/ioc-types.json`

Manifest of available IOC type shards, used to build the hub and per-type pages.

Each type entry includes:

- `type` — internal key (for example `ip_address`, `sha256`, or a slugified subsection heading)
- `label` — display name
- `description` — one-line summary for cards
- `category` — hub grouping: `network`, `host`, `hash`, `vuln`, `attack`, `other`
- `page_url` — site path to browse this type (`/iocs/<slug>/`, or `/iocs/other/?ioc_type=<type>` for uncommon headings)
- `top_actors` — up to five `{ name, slug, count }` entries
- `count`
- `atomic_count`
- `unique_values`
- `path` — `/api/iocs/by-type/<type>.json`

### `/api/iocs/by-type/<type>.json`

Type-scoped IOC shard (underscore key in the URL matches `type` from manifest records).

Server-side grouping reduces oversized lists:

- `grouping` — strategy name (`cidr16`, `etld1`, `url_host`, `cve_year`, `technique_parent`, `first_letter`, `by_actor`, …)
- `groups` — array of `{ key, label, count, records }`; groups are sorted by size then key
- `facets.actor` — actor facet with `{ name, slug, count }` for sidebar filters
- `records` — full flat list for this type (same rows as in groups), sorted by value and actor

Additional metadata mirrors the manifest: `label`, `description`, `category`, `page_url`.

Example:

```js
const manifest = await fetch('/api/ioc-types.json').then((response) => response.json());
const shard = await fetch(manifest.ip_address.path).then((response) => response.json());
const group = shard.groups.find((g) => g.key === '192.168');
```

## Query Model

- Exact IOC lookup: fetch `/api/ioc-lookup.json` and index by normalized lookup keys (includes atomic IOCs).
- Type-specific browsing: open `/iocs/` or fetch `/api/ioc-types.json`, then `/api/iocs/by-type/<type>.json`. Prefer `groups` for grouped navigation.
- Deep-link from hub search: `/iocs/ip-address/?value=<canonical>` (URL-encoded) expands the matching group and highlights the row.
- Actor-specific IOC filtering: use `facets.actor` or filter `records` / group `records` by `actor_slug`.

### `/api/attack-version.json`

Single object describing the **active ATT&CK release** and per-domain bundle metadata used to build MITRE indexes (Enterprise, Mobile, ICS).

Typical keys:

- `active_version` — unified release string (for example `19.0`) when all domains resolve to the same ATT&CK version.
- `retrieved_at` — ISO timestamp when bundles were last resolved.
- `domains` — object with keys `enterprise`, `mobile`, and `ics`; each value includes `version`, `source_url`, and optional counts (`techniques`, `tactics`).

Populated by `scripts/generate-indexes.rb` via `scripts/mitre/version_resolver.rb` (snapshot manifest → `data/mitre-cache/active.yml` → optional network fetch). The site footer and `/ttps/` use this for the “ATT&CK vX.Y” label.

### `/api/techniques.json`

Array of MITRE technique summaries from `_techniques/*.md` front matter (`title`, `mitre_id`, `permalink`, `mitre_url`, `domains`, `attack_version`).

Each record may include **`domain`** — the primary MITRE framework for that row (`enterprise`, `mobile`, or `ics`) when generated from merged multi-domain STIX.

The `/ttps/` ATT&CK matrix page consumes this together with `tactics.json`, `technique-tactics.json`, `attack-version.json`, and the actor indexes below.

### `/api/tactics.json`

Array of MITRE tactic summaries from `_tactics/*.md`. Records may include **`domain`** and **`attack_version`**.

The `/ttps/` matrix orders its tactic columns using this array (filtered client-side by selected framework). Enterprise columns follow kill-chain order when indexes are regenerated.

### `/api/mitigations.json`

Array of MITRE mitigation summaries from `_mitigations/*.md`.

### `/api/campaigns_mitre.json`

Array of MITRE campaign summaries from `_campaigns/*.md` (distinct from `/api/campaigns.json`, which is extracted from actor page **Notable Campaigns** sections).

### `/api/actors_by_technique.json`

Object keyed by technique ID (for example `T1059`) listing actors that reference that technique — parsed from actor YAML `ttps` strings, structured `ttps` entries where present, and technique IDs extracted from page **TTPs** / Atomic mappings (`attack_mappings`).

### `/api/actors_by_tactic.json`

Object keyed by tactic ID (for example `TA0007`) listing actors whose cited techniques map to that tactic. Entries may be actor names (legacy) or objects with `name` and `domain` when domain-specific bucketing is available. Requires `technique_tactics` mappings from `scripts/generate-indexes.rb` (cached MITRE bundles or importer snapshot).

### `/api/technique-tactics.json`

Object keyed by technique ID; each value is an array of mappings from MITRE STIX `kill_chain_phases`. Each element is either a tactic ID string (`TA####`, legacy Enterprise-only) or an object `{ "tactic_id": "TA####", "domain": "enterprise|mobile|ics" }`. Populated when MITRE bundles are available for the corresponding domains (see `data/mitre-cache/` and `scripts/mitre/version_resolver.rb`).

### `/api/software_by_actor.json`

Object keyed by actor name listing MITRE `software` entries from actor YAML.

### `/api/search-index.json`

Composite search payload with `actors`, `techniques`, and `campaigns` arrays for the site search UI.

## Limitations

- IOC extraction is currently heuristic and driven by page headings and bullet formatting.
- Some records in IOC sections are descriptive only; those are preserved with `atomic: false` and excluded from exact-match lookup indexes.
- There is no server-side query language, pagination, or prefix search in `v1`.

## Future Improvements

- Add versioned API paths such as `/api/v1/`.
- Add richer normalized typing for URLs, hashes, emails, filenames, and infrastructure.
- Add provenance metadata such as extraction confidence and review timestamps.
