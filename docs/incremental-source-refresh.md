# Automated source refresh and cache contract

Every automated source is run by `scripts/import-automated-sources.rb`; none is
implicitly omitted by cache logic. Each dated snapshot may contain a
`cache-manifest.yml` written by `scripts/lib/import/cache_manifest.rb`. The
manifest is deliberately dependency-free and contains only source version,
public HTTP validators, stable record hashes, retrieval/freshness timestamps,
schema/transform versions, and request/byte metrics. Invalid or incomplete
cache manifests are ignored and the normal snapshot/fail-closed path is used.

## Capability inventory

| Source | Version / validator | Stable IDs or hashes | Refresh policy |
|---|---|---|---|
| mitre-attack | ATT&CK version; HTTP validators when supplied by upstream | STIX object IDs and bundle SHA-256 | Reuse a complete bundle when the pinned version and checksum match; otherwise full bundle fetch |
| wiz-cloud-threat-landscape | none documented | content hash | full fetch |
| misp-galaxy | Git repository revision when exposed | cluster UUID/content hash | full cluster fetch; cache metadata only |
| etda-thaicert | none documented | content hash | full fetch |
| malpedia | global version endpoint is not exposed by the current importer; public validators may be added | actor IDs and record hashes | metadata fetch plus bounded detail fetch; cache metadata records request/byte counts |
| aptmap | none documented | content hash | full fetch |
| eternal-liberty | repository revision when exposed | content hash | full fetch |
| microsoft-threat-actor-list | workbook Last-Modified/ETag when exposed | row content hash | full workbook fetch |
| apt-groups-operations | repository revision when exposed | content hash | full fetch |
| aptnotes | repository revision when exposed | report URL/content hash | full fetch |
| rapid7-aba-detections | repository revision when exposed | content hash | full fetch |
| ransomlook | API/feed validators when exposed | record IDs/content hash | full fetch |
| reddrip7-apt-digital-weapon | repository revision when exposed | content hash | full fetch |
| ransomware-tool-matrix | repository revision when exposed | content hash | full fetch |
| ransomware-vulnerability-matrix | repository revision when exposed | content hash | full fetch |
| russian-apt-tool-matrix | repository revision when exposed | content hash | full fetch |
| bushido-breach-reports | repository revision when exposed | content hash | full fetch |
| curated-intel-moveit-transfer | repository revision when exposed | content hash | full fetch |
| sophos-threat-profiles | none documented | content hash | full fetch |
| google-cloud-apt-groups | repository revision when exposed | content hash | full fetch |
| breach-hq-threat-actors | none documented | content hash | full fetch |
| dragos-threat-groups | none documented | content hash | full fetch |
| unit42-threat-actor-groups | none documented | content hash | full fetch |
| threatfox | `get_iocs` has no conditional POST contract | ThreatFox IOC `id` and record hashes | bounded API query; known-good snapshot is reused only as an explicit stale fallback on provider/auth failure |

"Full fetch" is intentional: the upstream contract does not provide a safe
version, cursor, conditional request, or stable record deletion signal. The
importer still records hashes and metrics so a future adapter can add
incremental behavior without changing snapshot semantics.

## Diagnostics and metrics

`metrics.request_count` and `metrics.response_bytes` are recorded per fetch
where the importer has request visibility. Reports and manifests distinguish
fresh snapshots from stale fallback. A partial response, provider error,
expired/corrupt cache, or failed validation never becomes a successful empty
source; it remains quarantined or uses the source's explicitly documented
last-known-good fallback.

Run the offline contract check with:

```bash
ruby scripts/test-cache-manifest.rb
ruby test/import_threatfox_fallback_test.rb
```
