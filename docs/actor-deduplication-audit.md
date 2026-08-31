# Threat-actor identity and duplicate audit

Date of audit: 2026-08-31

## Result

The canonical store contains 3,614 actor YAML records after quarantining the malformed `_data/actors/.yml` record. The generated actor projection also contains 3,614 rows. Before this correction, the canonical store contained 3,615 records but published 3,614 because the `url: "/"` record had no matching actor page; this was a projection defect, not a duplicate merge.

The deterministic audit command is:

```text
ruby scripts/audit-actor-duplicates.rb --output /tmp/actor-duplicates.json
```

It uses the shared `AliasResolver` normalization (names, aliases, URL slugs, and explicit MITRE/external IDs), disables synonym hints for a reproducible baseline, sorts actor files and collision keys, includes source files in collision entries, and never mutates data.

Observed baseline:

- Canonical actor records: 3,614
- Normalized identity keys: 7,603
- Collision groups: 436
- Actors participating in a collision group: 228
- Duplicate URLs: 0
- Duplicate normalized actor names: 2 groups / 4 records
- Generated actor rows: 3,614
- Exact duplicate normalized-name groups: 2 / 4 actor records (`c3rb3r` + `Cerber`; `Crypt0L0cker` + `CryptoLocker`)

## Qilin assessment

Qilin is not a proven duplicate in the canonical store. These are separate records with separate source provenance and URLs:

| Record | URL | Source identity | Assessment |
| --- | --- | --- | --- |
| Qilin | `/qilin` | APT Groups & Operations; Bushido matrices | Canonical ransomware-group record |
| Qilin Ransomware Actors | `/qilin-ransomware-actors` | MISP Galaxy UUID `e5395df4-59e0-4eb7-b864-335bfd3a9bc2` | Separate MISP relationship/catalog object; name does not equal `Qilin Ransomware` |
| Qilin Securotrop | `/qilin-securotrop` | RansomLook ID `qilinsecurotrop` | Separate RansomLook label; insufficient evidence to equate with Qilin |

`Qilin` and `Qilin Ransomware` share a semantic subject, but the latter is only an alias on `/qilin`; `Qilin Ransomware Actors` normalizes to a different key. `Qilin Securotrop` also has a different key. No raw source snapshots containing Qilin were committed under `data/imports/`; conclusions are based on canonical provenance and generated projections.

The report also finds two high-confidence collision candidates that require analyst decisions, not automatic merges:

- `c3rb3r` (`/c3rb3r`, RansomLook) vs `Cerber` (`/cerber`, MISP Galaxy). The RansomLook description says C3RB3R is a revived use of the Cerber name, but the source records and URLs are distinct.
- `Crypt0L0cker` (`/crypt0l0cker`) vs `CryptoLocker` (`/cryptolocker`). Leet normalization makes these collide, but the source records are distinct and one source says the latter is no longer relevant.

All other 434 collision groups are alias/identifier overlaps and are intentionally left unresolved. Shared keys cause importer matches to become `:ambiguous` rather than silently merging records. The JSON report records the exact source file for every affected actor.

## Root cause and correction

MISP conversion accepted any non-empty display name, then converted names containing no ASCII letters or digits to `/`. The `$$$` MISP record consequently became `_data/actors/.yml`, while publication skipped it because there is no valid actor page at the site root. The importer now records such rows as `skipped: [{ name: ..., reason: "empty_url_slug" }]` in its JSON report and does not create an unpublished root actor. Existing provenance remains untouched; the malformed record is not destructively merged or silently promoted.

Regression coverage is in `test/actor_duplicate_audit_test.rb` with a Qilin fixture at `test/fixtures/actor_dedup/actors.yml`.
