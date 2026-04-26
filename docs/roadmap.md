# Roadmap

This roadmap turns the current modernization slice into a maintainable plan for evolving `threatactor-info` into a deeper threat-actor knowledge base with a practical static JSON API.

## Near-Term

- Treat `_threat_actors/` as the canonical Jekyll collection for rendered actor pages
- Keep `_data/threat_actors.yml` and collection pages synchronized through validation
- Generate static JSON artifacts for actors, IOCs, facets, IOC lookup, and IOC type shards
- Keep the search UI powered by generated JSON rather than raw YAML parsing
- Document the content workflow so contributors regenerate indexes after content edits

## Medium-Term

- Expand the generator to extract more structured sections such as malware, campaigns, ATT&CK techniques, and references
- Normalize IOC parsing further for hashes, file extensions, domains, URLs, and deconfanged values
- Add lightweight cross-links between actors that share infrastructure, malware families, or aliases
- Add collection-backed landing pages for sectors, countries, malware, and campaigns using generated JSON facets
- Introduce versioned API snapshots or changelog metadata so downstream users can track dataset changes

## Longer-Term

- Split the knowledge base into richer structured entities: actors, campaigns, malware, tools, references, and ATT&CK mappings
- Publish a stronger static API surface with stable schemas, versioning, and compatibility notes
- Add provenance metadata for generated records, including source section, extraction confidence, and last-reviewed timestamps
- Support static client-side drilldowns for IOC relationships, actor clusters, and shared infrastructure graphs
- Add release automation that regenerates artifacts, validates schema changes, and publishes a documented dataset release

## API Evolution Notes

- Keep the API static-hosting friendly: generated JSON files, no runtime services, no custom backend
- Prefer additive schema changes where possible so external consumers do not break unexpectedly
- Use manifest endpoints for discovery, then shard larger datasets by type or topic to keep client fetches efficient
- Treat `_data/generated/` as the source for Jekyll rendering and `api/` as the public static delivery surface
