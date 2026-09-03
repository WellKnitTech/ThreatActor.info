# Observable source and attribution policy

**Status:** normative for Observable v1 (2026-09-02)

This policy governs whether a source may contribute a public observable and whether that observable may be linked to an actor. The machine-readable source register is `data/observable-source-policy.yml`; regression cases are in `data/observable-policy-scenarios.yml`.

## Non-negotiable publication gates

An observable is public only when all of these are true:

1. The source decision in the register permits publication (`publish_conditional`, `publish_metadata_only`, or `publish_enrichment_only`) and its terms permit the intended use and attribution.
2. The snapshot is bounded, checksummed, fresh within `max_age_days`, and has a stable source URL plus source record ID (or an explicit documented exception).
3. The value passes Observable v1 normalization and validation; secrets, credentials, raw certificates, samples, victim-sensitive data, and personal data are rejected.
4. Evidence describes the observable itself: source, record, retrieval time, normalization version, confidence scope, and status. Actor confidence never substitutes for observable evidence.
5. The plan is deterministic, reviewed, and free of unresolved conflicts, excessive duplicates, parser anomalies, or failed source health.
6. Actor linkage is direct and evidence-backed, or explicitly reviewed under the relationship rules below. Otherwise the observable is public only as `unassigned` when safe, or quarantined.

A failed, unauthorized, rate-limited, malformed, partial, or expired source is never silently healthy. Stale fallback may preserve an already-published record only with stale status and an operator-visible warning; it cannot create new actor links.

## Actor-linkage rules

- **direct:** the source record explicitly names the actor, or contains a source-maintained actor/group relationship. Publish only with the record URL/ID and reviewed mapping evidence.
- **malware-mediated:** the source explicitly links the observable to malware and a separate trusted relationship links that malware to the actor. This is not actor proof by itself; publish the observable as malware-linked and leave actor ownership unassigned unless the two-hop evidence is reviewed and recorded.
- **report-mediated:** a report explicitly attributes the observable to an actor. Preserve the report citation and publisher; a report index alone is not evidence. Publish only after review.
- **unassigned:** safe observable with no actor claim. It may appear in source/type views but never in an actor view.
- **prohibited:** no actor linkage. This includes name/tag coincidence, malware-name coincidence without reviewed two-hop evidence, and two entities merely co-occurring in one report.

Conflicting actor claims are quarantined, not resolved by source priority. A false-positive assertion is source-scoped and suppresses publication until reviewed; it does not delete evidence.

## Source operations

Adapters must use `fetch -> validate -> plan -> apply -> report`, bounded requests, response-size limits, retry/backoff only for retryable failures, deterministic ordering, deduplication, atomic apply, and report-only/dry-run operation. Retain raw snapshots only as allowed by the source terms and repository retention controls; public output retains the minimum evidence needed to reproduce attribution and correction.

The register is deliberately conservative: existing actor/report sources are not IOC sources, and deferred IOC feeds remain quarantined until their terms and adapter fixtures are accepted.

## Required review for changes

Adding a source or changing a decision requires updating the register, attribution page, and a scenario covering its failure and linkage behavior. A source with unknown terms, rate limits, retention, attribution strength, or correction contact is `quarantine`, regardless of apparent data quality. No adapter may bypass this register.
