# Provenance and data-quality policy

This policy defines how imported and analyst-supplied observations are represented, merged, displayed, and exported. It is deliberately conservative: an unknown, disputed, or stale value must not be rendered as a precise current fact.

## Scope and terms

- **Entity**: actor, malware/tool, operation, technique mapping, reference, or IOC.
- **Observation**: one source's claim about one field of one entity. An observation is never silently converted into consensus.
- **Source**: the publisher or dataset, not the importer that happened to read it.
- **Snapshot**: the immutable input identified by source key, retrieval time, URL, and checksum.
- **Primary**: the value selected for the normal site view after quality rules. Primary does not mean true; it means preferred for this field.

The existing top-level actor fields remain compatible. New quality data should be additive and use the following field-level shape wherever practical:

```yaml
field_quality:
  malware:
    - value: "ExampleTool"
      source_name: "Publisher"
      source_record_url: "https://example.test/record"
      source_dataset_url: "https://example.test/dataset"
      observed_at: "2026-04-28T00:00:00Z"
      retrieved_at: "2026-04-29T00:00:00Z"
      confidence: "high"
      status: "active"
      attribution: "Publisher attribution text"
```

`field_quality` is an observation ledger, not a replacement for the convenient canonical field (`malware`, `iocs`, `ttps`, etc.). A future implementation may use an equivalent per-item `provenance` property, but must preserve these semantics and field names. Dates are UTC ISO 8601; date-only source dates remain date-only and are not promoted to timestamps.

## Required quality dimensions

Every imported observation that reaches canonical YAML must have, or explicitly lack, these dimensions:

| Dimension | Values/rule |
|---|---|
| Lineage | source name plus exact record/dataset URL when available; snapshot ID/checksum in importer reports |
| Time | `observed_at` (when the source says when), `retrieved_at` (when we fetched it), and `last_reviewed_at` only for human review |
| Confidence | ordinal `high`, `medium`, `low`, or `unknown`; never present ordinal labels as percentages |
| Status | `active`, `stale`, `disputed`, `superseded`, `rejected`, or `quarantined` |
| Attribution | source-required credit/license text, retained with the observation |

Missing metadata is represented as `unknown` or omitted with a documented reason. Never infer an observation date from retrieval time, and never infer confidence from popularity, row count, or a successful parser run.

### Confidence rubric

- **High**: the source explicitly identifies the entity/value and the parser matched it deterministically; or an analyst reviewed the exact source record.
- **Medium**: source-backed but indirect, normalized, inferred, or matched through a non-unique crosswalk.
- **Low**: heuristic extraction, weak alias match, or context that needs analyst confirmation.
- **Unknown**: legacy data or a source that supplies no defensible confidence signal.

Confidence is field-level. An actor with high-confidence identity may still have low-confidence malware or IOC observations.

## Freshness and time

Use `data/imports/source_freshness.yml` as the operational default for snapshot age. Freshness is source- and field-specific, not a truth score:

- `retrieved_at` beyond the source's `max_age_days` marks observations `stale` unless the source explicitly supplies a newer `observed_at` and the field's policy permits historical retention.
- Historical observations remain exportable when useful, but must carry `status: stale` (or `observed_at` as historical) and must not appear in a “recent/current” view.
- A stale fallback is visibly degraded: preserve the last snapshot's lineage and report status `stale_fallback`; never relabel it fresh.
- `last_updated` is an editorial timestamp, not evidence that an IOC was recently observed. `last_activity` is a source claim and must not be treated as a retrieval timestamp.
- Unknown time is displayed as “date not provided,” never as today or the build date.

## Merge, duplicates, conflicts, and supersession

1. Normalize only for matching. Preserve the original `value` and `source_text`; normalization must not erase meaningful source spelling or formatting.
2. Exact duplicates from the same source/snapshot collapse to one observation, retaining all source references and the earliest supplied observation time.
3. Cross-source duplicates are one canonical value with multiple observations, not evidence of independent confirmation. Show source count only when the UI makes clear it is a count of sources.
4. Conflicting values, names, dates, or attribution are retained as separate observations. Select a primary value only through an explicit source priority or analyst decision; record the reason and competing sources.
5. A source cannot supersede another source globally. Supersession is field/entity scoped and requires a deterministic match plus an explicit takeover rule. Automated provenance may supersede an analyst placeholder for identity, while the old value moves to `analyst_notes`/history rather than being deleted.
6. `superseded` means replaced for primary display, not disproven. `rejected` means failed validation or policy and is excluded from public canonical output. `quarantined` means the source/run is held out pending review; it must never mutate generated artifacts.
7. An ambiguous actor/IOC match is not merged. Keep it as `disputed` or `quarantined` with candidate IDs and require review.

These rules close SB-1 through SB-3 in [supersession-backlog.md](supersession-backlog.md); one-off sources must adopt the same snapshot/plan/apply gates before being promoted.

## Publication rules

### Site display

- Normal pages show primary observations plus a compact source, confidence, and freshness/status label.
- `low`, `unknown`, `stale`, and `disputed` are visibly qualified; do not use green/verified language for them.
- Historical and superseded observations may appear in an expandable provenance/history section, never as unqualified current facts.
- Quarantined and rejected values are not rendered. Analyst notes are visibly labelled as analyst context and are not presented as automated corroboration.
- Source attribution and license notices remain adjacent to the fields they govern where feasible.

### API and lookup indexes

- Public records include quality metadata for each published observation (at minimum source, confidence, status, and available timestamps); top-level convenience fields remain backward compatible.
- `/api/iocs.json` and IOC shards preserve `source_text`, `source_file`, source lineage, and quality status. Non-atomic rows remain excluded from exact-match lookup, as today; `disputed`/`stale` rows may be returned but clients must filter by status for current use.
- `/api/ioc-lookup.json` indexes only atomic, non-rejected, non-quarantined values. A lookup match must return all eligible observations, not whichever source was generated first.
- Counts and facets state whether they include historical, stale, or disputed rows. Never imply that a count is a count of currently valid indicators without saying so.
- Quarantined input and rejected values are absent from public API artifacts and retained only in run diagnostics/quarantine storage.

### Generated artifacts and build safety

The pipeline remains snapshot -> fetch -> validate -> plan -> apply -> generate. Only accepted plans may write `_data/actors`, `_data/generated`, `api`, or collection pages. Generation is deterministic from committed canonical data; it never fetches live sources. A failed, stale, anomalous, or quarantined plan leaves the prior generated artifacts unchanged and reports the degraded state.

## Regression scenarios (acceptance tests)

Implement these as fixture contracts or focused validator tests before enabling publication of field-level quality data:

1. **Complete lineage**: an accepted IOC contains original value/text, source name, record URL, snapshot/retrieval time, confidence, and status in YAML, generated JSON, and the actor page.
2. **Unknown is honest**: a legacy IOC with no dates/confidence exports `unknown`/missing metadata and never receives the build date or a percentage.
3. **Source disagreement**: two sources provide different malware/IOC values; both observations survive, one primary is selected only with an explicit priority/reason, and the page/API expose the conflict.
4. **Duplicate collapse**: repeated identical values in one snapshot yield one canonical row while retaining all relevant source references; independent sources are not counted as corroboration unless policy explicitly says so.
5. **Ambiguous match quarantine**: an IOC or actor matching multiple candidates is not attached to an arbitrary actor and cannot reach lookup or generated public artifacts.
6. **Freshness boundary**: snapshots at exactly `max_age_days` and one second beyond it exercise fresh versus stale behavior; stale fallback keeps prior data, marks degraded status, and does not update `last_updated`.
7. **Supersession**: automated identity provenance takes over an `Analyst Notes` placeholder, preserves the prior text in analyst history, and leaves unrelated analyst-only fields intact.
8. **Rejected/quarantined immutability**: a malformed, empty, anomalous, or rejected plan produces diagnostics but byte-for-byte preserves prior generated/API artifacts.
9. **Atomic lookup safety**: descriptive (`atomic: false`), rejected, and quarantined IOC rows never enter `/api/ioc-lookup.json`; eligible stale rows carry status so clients can exclude them.
10. **Attribution and licensing**: every published source-backed field retains required attribution/license metadata; quarantined data does not leak into public pages or APIs.

## Rollout and migration

First add readers/validators that tolerate legacy records and classify missing dimensions as unknown. Then migrate observations source-by-source, starting with IOC rows and array fields (`malware`, `operations`, `ttps`), regenerate all committed artifacts, and compare counts and lookup keys before/after. Roll back by reverting the canonical YAML and regenerated artifacts together; never hand-edit generated output. Update this policy and the backlog when a field gains a stricter source-specific freshness or confidence rule.
