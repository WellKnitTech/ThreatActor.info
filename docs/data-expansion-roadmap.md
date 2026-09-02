# ThreatActor.info data-expansion roadmap

**Decision date:** 2026-09-02  
**Status:** implementation decision; no production data is imported by this document

## Executive decision

Ship an additive **Observable v1 canary** before broadening the entity catalog. The first release is the smallest coherent slice that improves analyst usefulness while preserving the static, offline, snapshot-backed architecture:

1. canonical typed observations and evidence metadata;
2. a fail-closed, bounded adapter pipeline;
3. ThreatFox as the first live-shaped adapter, with no-auth and stale fallback behavior;
4. evidence-aware generated API/index projections that retain current endpoints; and
5. a bounded, reviewable backfill followed by independent acceptance testing.

The first release must not attempt general MISP-feed crawling, OTX, commercial feeds, organization resolution, raw malware samples, or automatic actor attribution from co-occurrence. URLhaus, MalwareBazaar, and Feodo Tracker follow only after the canary demonstrates safe provenance and acceptable volume. CISA KEV/EPSS are a later vulnerability-enrichment track and must not be forced into actor IOC YAML.

This ordering follows the measured baseline: roughly 3,614 actor records/pages, 1,881 malware pages, 4,834 flattened malware rows, but only 9 generated IOC rows and 7 lookup keys. It targets the highest information gap without multiplying identity or licensing risk. Sources and figures: [source coverage roadmap](source-coverage-roadmap.md), [entity gap matrix](entity-relationship-gap-matrix.md), and [API/search review](api-search-page-workflow-review.md).

## Non-negotiable gates

Every implementation and import must satisfy these gates before merge or publication:

- **Identity:** fix or explicitly report canonical-to-generated projection gaps; the known duplicate-actor audit finding (empty actor-directory fallback) is a prerequisite for trusting expansion. Never let new observations amplify an unresolved actor collision.
- **Schema:** validate supported types, deterministic `(type, normalized_value)` IDs, reversible defanging, atomicity, status, and source records. Reject credentials, raw certificate material, malformed values, and unregistered types.
- **Evidence:** every public observation has source name, stable source record/dataset URL when available, retrieval time, applicable terms/license, normalization version, and field-level confidence/status. Actor confidence is never substituted for observation confidence.
- **Attribution:** direct source attribution or an explicitly reviewed mapping only. Malware-name or report co-occurrence is not actor ownership. Unmatched and ambiguous rows remain unassigned/quarantined.
- **Safety and rights:** public output contains defensive minimums only; no secrets, personal data, victim-sensitive details, payloads, samples, leak content, or unclear-rights source material. Defanging is not a privacy control.
- **Operations:** fetch is bounded and snapshot-backed; plan is side-effect free; apply is atomic; malformed, empty, anomalous, unauthorized, rate-limited, or stale inputs cannot silently become healthy data. Builds never fetch the network.
- **Compatibility:** current arrays, page URLs, type names, legacy API array shapes, and underscore aliases remain valid. New envelopes/indexes are additive.

Policy sources: [IOC contract](ioc-observable-contract.md), [provenance policy](provenance-quality-policy.md), and [privacy/safe-sharing policy](privacy-sharing-policy.md).

## Release slices

### Slice A — foundation (P0)

Implement the canonical observable/evidence schema, deterministic IDs, validation fixtures, source manifest, coverage/integrity reporting, and the shared `fetch -> validate -> plan -> apply -> report` lifecycle. Preserve legacy IOC lists and classify missing legacy metadata as unknown rather than inventing dates or confidence. Add duplicate/conflict/supersession semantics before writing new actor YAML.

**Exit criteria:** all normative valid/invalid and legacy fixtures pass offline; failed plans leave canonical and generated artifacts byte-identical; every rejected/quarantined row has a machine-readable reason; two generation runs are byte-equivalent; the duplicate-actor audit is either remediated or represented in the coverage manifest with a blocking disposition.

### Slice B — ThreatFox canary (P1)

Use the existing `THREATFOX_API_KEY` binding and no-auth empty-snapshot behavior. Fetch only the permitted 1–7 day bounded window, preserve ThreatFox record IDs and report URLs, and apply only direct/evidence-backed matches. Keep unmatched indicators in a non-public report/quarantine path. Do not download or expose raw payloads.

**Exit criteria:** fixture and limited canary reports distinguish fresh, 304/reused, stale fallback, no-auth, unauthorized, timeout, malformed, rate-limited, empty, duplicate, and ambiguous-match outcomes; no key appears in logs, snapshots, reports, generated artifacts, or diffs; no ambiguous row is actor-owned.

### Slice C — generated projections (P1)

Extend deterministic indexes with stable observable IDs, source observations, citations, dates, confidence scope, status, relationships, corroboration semantics, source-manifest reference, and coverage counts. Keep `/api/iocs.json` and current lookup/type/actor paths as compatibility views. Exclude false-positive and quarantined records from ordinary lookup/search/counts; qualify stale/disputed records.

**Exit criteria:** API payloads validate; every public row traces to evidence; lookup, type page, actor page, and citation agree on one ID and safe display value; stale and restricted data cannot leak through a legacy alias; stale shards are removed atomically; output is deterministic.

### Slice D — bounded backfill and analyst workflow (P1/P2)

Backfill a predeclared high-confidence cohort only after A–C. The target is at least 100 useful non-demo observations across at least 10 actors or malware families and at least 4 types, but volume is subordinate to provenance, attribution, rights, and safety. Add exact/normalized lookup, source/type/status/freshness filters, detail/citation pivots, safe defanged display, pagination, and bounded exports only after API contracts are stable.

**Release acceptance:** the end-to-end gate exercises all failure modes in the dedicated acceptance card, records before/after counts by source/type/entity, and confirms no unexplained public row. If the target cannot be met safely, release the smaller measured result and keep the next source/backfill blocked rather than lowering evidence standards.

## Deferred expansion

- **URLhaus:** first follow-on IOC source; use bulk export, age filtering, terms verification, and no automatic actor ownership.
- **MalwareBazaar:** metadata and hashes only; never samples; verify fair-use/auth/redistribution terms.
- **Feodo Tracker:** bounded C2 infrastructure observations with expiry semantics; malware family is not actor proof.
- **CISA KEV then FIRST EPSS:** generated vulnerability enrichment, not actor YAML writes in the first phase.
- **MISP allowlist:** one explicitly licensed feed at a time after a feed-specific manifest and fixture review.
- **OTX and other/community/commercial feeds:** research-only until quotas, terms, provenance, and redistribution are verified.

Reference: [source coverage and IOC ingestion roadmap](source-coverage-roadmap.md), especially its source ranking and research-only list.

## Migration and generated-artifact impact

Canonical authoring remains `_data/actors/*.yml`; `iocs:` is preferred while legacy `ips`, `domains`, `urls`, `emails`, `cves`, and inferred hashes remain readable. Generate pages and indexes together (`generate-pages.rb --force`, then `generate-indexes.rb`); never hand-edit `_site/` or generated output. The change fans out to actor pages, `_data/generated/*`, `api/*`, IOC shards/lookups, search indexes, malware/relationship projections, and attribution notices. A coverage manifest must explain every skipped canonical record so a generator cannot silently hide a record/page mismatch.

Migration is additive and reversible: compare counts, lookup keys, IDs, status distributions, source counts, and generated checksums before/after; apply only reviewed plans; roll back canonical YAML and its generated artifacts together. Takedown/correction verification must search the repository and built site, including legacy API aliases, fixtures, snapshots where permitted, and CI artifacts.

## Test and fixture contract

Use small committed fixtures, not the full corpus, for deterministic tests:

- valid observations covering each initial type, defanging, repeated sources, dates, and relationships;
- invalid values (bad hash/URL/email/IP, CIDR atomic IP, missing source, raw certificate, secret-like value, unsupported subtype);
- legacy nested/top-level IOC lists and duplicate collapse;
- adapter outcomes: empty, malformed, partial, timeout, HTTP error/401/429, unchanged/304, fresh response, stale fallback, expired fallback;
- direct, malware-mediated, unassigned, and ambiguous actor matches;
- duplicate/conflicting source observations, source-scoped false positive, quarantine, and analyst supersession;
- one relation fixture each for malware/tool, campaign/operation, technique, CVE, victim string, and reviewed actor-to-actor mapping.

Required checks include focused Ruby fixture tests, `ruby scripts/test-source-adapter.rb`, `ruby scripts/validate-import-plans.rb` where applicable, JSON/content validators, `bash scripts/validate.sh`, safe Jekyll build, generated JSON parsing, and a browser acceptance pass for exact lookup, filters, pivots, empty states, citations, defanged output, and safe exports. Record blocked dependency/environment checks honestly.

## Rollout, rollback, and operational ownership

1. Land contracts, fixtures, and validators without production imports.
2. Run adapters in fetch/plan/report-only mode; review manifests, terms, cardinality, match quality, quarantine, and sensitive-scan results.
3. Apply one canary cohort; inspect generated diff and independent acceptance results.
4. Expand only if all gates pass and source health is explicitly successful.
5. Roll back on unexplained volume, attribution error, rights/privacy/safety finding, nondeterminism, generated leakage, or failed validation by reverting the canonical and generated bundle together; quarantine the snapshot and leave prior artifacts unchanged.

The automated import health summary should be the operator checkpoint for last successful run, per-source freshness/status, quarantine counts, stale/degraded blocking, changes, diagnostics, and PR outcome. Source-specific ownership must include a terms/attribution owner and a takedown/correction owner; unknown ownership blocks publication.

## Recommended Kanban graph

The pre-created graph below is the implementation plan. Dependencies are gates, not merely scheduling hints; downstream cards must remain blocked until upstream review and integration are complete.

```text
t_f0edc049 (this decision)
  |
  +--> t_c356e8ec  P0 canonical IOC/evidence schema
  |       |
  |       +--> t_8745dbc6  P0 source attribution policy
  |       |       |
  |       |       +--> t_1878fac2  P0 safe adapter pipeline
  |       |               |
  |       |               +--> t_175153a1  P1 ThreatFox adapter
  |       |               |       |
  |       |               |       +--> t_46d6c108  P1 bounded backfill
  |       |               |               |
  |       |               |               +--> t_d3a9bf36  P0 end-to-end release gate
  |       |               |
  |       |               +--> t_f4cdb242  P1 MalwareBazaar/URLhaus adapters
  |       |
  |       +--> t_d0afb761  P1 evidence-aware APIs/indexes
  |               |
  |               +--> t_f7c8ae01  P1 analyst IOC search/evidence views
  |                       |
  |                       +--> t_d3a9bf36
  |
  +--> t_211c70dc  entity/relationship gap work (input to schema/API)
  +--> t_2d960f8e  source coverage decisions (input to policy/adapters)
  +--> t_72ea5fac  API/search workflow constraints (input to projections/UI)
  +--> t_92d1ac41  provenance policy (input to schema/pipeline)
  +--> t_a009b476  privacy/licensing policy (input to policy/pipeline)
  +--> t_4ba93f2d  duplicate-actor audit (blocking identity prerequisite)
```

The source-ranking decision is intentional: ThreatFox proves the controlled IOC path first; URLhaus is the next highest-value direct feed; MalwareBazaar and Feodo follow with separate manifests; KEV/EPSS broaden vulnerability utility without increasing actor-attribution risk. Do not add parallel adapters that bypass the shared pipeline.

## Decision record and citations

- `docs/ioc-observable-contract.md` — typed observation shape, normalization, compatibility, fixtures, and acceptance criteria.
- `docs/provenance-quality-policy.md` — field-level lineage, confidence, freshness, conflicts, supersession, publication, and rollback behavior.
- `docs/privacy-sharing-policy.md` — publish/redact/restrict/quarantine decisions and generated-output/takedown requirements.
- `docs/entity-relationship-gap-matrix.md` — measured non-IOC gaps and minimal relation contract.
- `docs/api-search-page-workflow-review.md` — current workflow, compatibility constraints, and deterministic page/API acceptance gates.
- `docs/source-coverage-roadmap.md` — source ranking, terms/operational constraints, and staged source sequence.
- `docs/source-adapter-contract.md` — existing lifecycle and deterministic value objects.
- `docs/importers.md` — current source attribution and ThreatFox operational behavior.
- External source references are maintained in `docs/source-coverage-roadmap.md`; they include abuse.ch ThreatFox/URLhaus/MalwareBazaar, CISA KEV, FIRST EPSS, MISP feeds, OTX, and OpenCTI documentation.
