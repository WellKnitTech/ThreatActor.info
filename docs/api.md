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
- `risk_level`
- `page_path`
- `headings`
- `ioc_count`
- `ioc_types`
- `campaigns`
- `malware_and_tools`
- `attack_mappings`
- `references`

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

### `/api/ioc-types.json`

Manifest of available IOC type shards.

Each type entry includes:

- `type`
- `count`
- `atomic_count`
- `unique_values`
- `path`

### `/api/iocs/by-type/<type>.json`

Type-scoped IOC shard for efficient client-side filtering.

Example:

```js
const manifest = await fetch('/api/ioc-types.json').then((response) => response.json());
const shard = await fetch(manifest.ip_address.path).then((response) => response.json());
const apt28Matches = shard.records.filter((record) => record.actor_slug === 'apt28');
```

## Query Model

- Exact IOC lookup: fetch `/api/ioc-lookup.json` and index by `normalized_value`.
- Type-specific browsing: fetch `/api/ioc-types.json`, then fetch a shard from `/api/iocs/by-type/<type>.json`.
- Actor-specific IOC filtering: fetch `/api/iocs.json` or a type shard and filter by `actor_slug`.

## Limitations

- IOC extraction is currently heuristic and driven by page headings and bullet formatting.
- Some records in IOC sections are descriptive only; those are preserved with `atomic: false` and excluded from exact-match lookup indexes.
- There is no server-side query language, pagination, or prefix search in `v1`.

## Future Improvements

- Add versioned API paths such as `/api/v1/`.
- Add richer normalized typing for URLs, hashes, emails, filenames, and infrastructure.
- Add provenance metadata such as extraction confidence and review timestamps.
