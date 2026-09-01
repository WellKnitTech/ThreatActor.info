# Incremental source fetching

The importer keeps the existing snapshot-first and fail-closed contract. Conditional
fetching is opt-in and never replaces a snapshot with an incomplete response.

## Implemented opportunity: MITRE ATT&CK

`import-mitre.rb fetch --prior-snapshot DIR` sends `If-None-Match` and
`If-Modified-Since` from the prior bundle manifest. A prior bundle is eligible
only when its URL matches and its SHA-256 checksum verifies. A `304 Not Modified`
response copies that verified file into the new snapshot and records
`response.status: not_modified`, validators, byte count, and the copied file's
checksum. New responses are written through a temporary file and renamed only
after a successful 2xx response. The resulting manifest retains source URL,
provenance, freshness (`retrieved_at`), and integrity metadata.

Example:

```sh
ruby scripts/import-mitre.rb fetch \
  --prior-snapshot data/imports/mitre-attack/2026-08-31 \
  --output data/imports/mitre-attack/$(date -u +%F)
```

A 304 without a verified prior snapshot is an error, not a successful empty
fetch. A validator mismatch or missing prior checksum falls back to a normal
full request.

## Sources intentionally left as full fetches

- Wiz Cloud Threat Landscape: one generated STIX document and no documented
  stable cursor or conditional contract in the source API.
- MISP Galaxy: multiple raw cluster files are selected by name; the public raw
  endpoint does not provide a source-native delta contract that can safely
  represent deletions.
- HTML/catalog importers (Dragos, Unit 42, Google Cloud, Breach-HQ, and similar):
  parser completeness depends on the complete page/catalog, so partial or
  cursor-based fetching would risk silently dropping actors.
- API feeds with bounded windows (ThreatFox, Malpedia, RansomLook): their
  semantics are query-window or paginated results rather than a reusable snapshot
  delta; retain complete-window fetching until a deletion-safe cursor contract is
  available.

These decisions are deliberate: bandwidth reduction must not weaken snapshot
manifests, checksums, provenance, freshness, rate-limit handling, or validation.
