# IOC and Observable Contract (proposal)

**Status:** design only. This document defines the smallest publishable contract for the next implementation; it does not change importers, schemas, or generated artifacts.

**Decision:** keep actor YAML as the authoring boundary, but represent each observable as a typed observation object. Existing lists and generated row/API shapes remain compatibility views until a later migration. Never publish a raw source payload merely because it contains an indicator.

## 1. Supported scope

The first contract supports these atomic types:

| `type` | Canonical value and validation |
|---|---|
| `ip_address` | IPv4 or IPv6 address; strict parser, no CIDR in an atomic value |
| `domain` | DNS name in lowercase, without scheme, path, port, or trailing dot; IDNs are stored as lower-case A-labels |
| `url` | Absolute `http`/`https` URL; lowercase scheme/host, remove default port and fragment, preserve meaningful path/query; credentials are rejected |
| `email` | Lowercase address with one `@`; validate syntax conservatively, do not claim mailbox existence |
| `md5`, `sha1`, `sha256`, `sha512` | Lowercase hexadecimal digest of exactly 128/160/256/512 bits |
| `file_path` | OS-qualified path string; preserve case and separators as observed, normalize only redundant separators and `.` segments; never infer a host OS |
| `registry_key` | Windows registry key; uppercase hive (`HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`), normalized separators, no value data |
| `mutex` | Non-empty mutex name; trim Unicode whitespace and preserve case unless source explicitly says it is case-insensitive |
| `certificate` | Certificate fingerprint only, with `algorithm` (`sha1` or `sha256`) and hex digest; PEM/DER payloads are not public observables |
| `vulnerability` | CVE identifier (`CVE-YYYY-N…`) or a future explicitly registered identifier; CVEs normalize uppercase |
| `attack_technique` | MITRE technique ID (`T####` or `T####.###`), uppercase |

`other` is not a free pass: it requires a registered `subtype`, a documented validator, and is non-atomic until that validator exists. Initial implementation should reject unregistered subtypes. File names, user agents, autonomous-system numbers, and cryptocurrency addresses remain deferred rather than being silently stuffed into `other`.

A vulnerability is an observable for compatibility, but exploitation, affected product, and relationship semantics belong on a separate vulnerability relationship/entity contract. `cisa_kev_cves` remains a legacy actor field and is not implicitly merged into `observables`.

## 2. Canonical observation shape

An observation has this minimum shape:

```yaml
id: "obs_v1_..."                 # deterministic, type + canonical value
type: "domain"
value: "example.com"             # canonical, safe-to-index value
normalized_value: "example.com"  # explicit for compatibility/query clients
display_value: "example[.]com"   # defanged public rendering
atomic: true
status: "active"                 # active | deprecated | false_positive | quarantined
first_seen: "2024-01-02T03:04:05Z"
last_seen: "2024-02-03T04:05:06Z"
confidence:
   score: 0.8                       # 0..1, optional
   rating: "medium"                # low | medium | high, optional
   scope: "observation"            # never implied to be actor confidence
   rationale: "Two independent reports"
sources:
  - source: "example-feed"
    record_id: "row-17"
    record_url: "https://example.com/report/17"
    retrieved_at: "2024-02-04T00:00:00Z"
    transform: "domain-lowercase-v1"
    license_url: "https://example.com/terms"
relationships:
  - target_kind: "actor"         # actor | malware | campaign | operation | report
    target_id: "apt28"
    role: "reported_by"
    confidence: "medium"
```

`type`, `value`, `atomic`, `status`, and at least one `sources` entry are required at publication time; relationships are optional but required for any published attribution pivot. `normalized_value` equals the canonical value for v1 but is retained as a named field so lookup behavior is explicit. `display_value` is the only value intended for ordinary HTML; API consumers may receive `value` only for approved publishable atomic records. Never include source secrets, credentials, malware payloads, private keys, or raw certificate material.

`first_seen`/`last_seen` are observation bounds, not page or importer timestamps. `retrieved_at` records collection time. `last_updated` remains editorial actor metadata and must not be substituted for either field. Dates must be RFC 3339 UTC; date-only source data may use midnight UTC only when `precision: day` is also retained.

## 3. Normalization and deduplication

Normalization is type-specific and deterministic:

* trim surrounding Unicode whitespace; reject empty values;
* defanging is input syntax, not a second indicator: accept common `[.]`, `(.)`, and `hxxp` forms only through an explicit reversible defang step, then validate the restored value;
* IPs use standard textual parsing and canonical compressed IPv6;
* domains are IDNA A-label/lowercase and have no trailing dot;
* URLs use parsed components; fragments and default ports are removed, credentials rejected;
* emails are lowercased for v1 (provider-specific case rules are not inferred);
* hashes, certificate digests, CVEs, and ATT&CK IDs are uppercase/lowercase as specified above;
* file paths, registry keys, and mutexes do not receive destructive case folding.

The deduplication key is `(type, normalized_value)`; source, dates, confidence, status, and relationships are merged into the one observation. Preserve every distinct source record rather than choosing an arbitrary winner. Conflicting values or attribution are separate source observations in one record, not evidence for a stronger score. A false-positive status is scoped to the observation and source/relationship when known; it must not erase a corroborating source. `deprecated` means superseded or no longer preferred, not false.

Stable IDs are `obs_v1_` plus a deterministic digest of the type and normalized value (the exact digest encoding is an implementation decision, but must be documented and immutable). Actor/malware/campaign IDs are relationship targets, not part of the observable ID, so the same domain can pivot across entities without duplicate values.

## 4. Safe sharing and review states

Publication is fail-closed:

* `active`: validated and approved for the relevant public projection;
* `deprecated`: retained for historical lookup where policy permits, visibly marked;
* `false_positive`: not included in exact lookup or ordinary public lists, but retained in audit input with rationale;
* `quarantined`: malformed, ambiguous, sensitive, unlicensed, or awaiting review; never included in public pages, lookup, or counts.

Sensitive email addresses, active infrastructure, named victims, credentials, secrets, payloads, and leak-site material require source/licensing/privacy review. A defanged display does not make a sensitive value safe. Every public source record needs source name, exact record/dataset URL where available, retrieval time, and applicable license/terms URL. Ambiguous actor matches must retain `match_method` and review state and default to quarantine.

## 5. Relationships

Relationships are directional and explicit: `actor`, `malware`, `campaign`, `operation`, and `report` are initial target kinds. A relationship requires `target_id`, `role`, and its own confidence/review state when attribution is uncertain. Examples include `reported_by`, `used_by`, `observed_in`, and `mentioned_in`. Do not infer ownership from co-occurrence, shared infrastructure, or a source's page title.

## 6. Backward-compatible projections

The current reader (`scripts/ioc_yaml_reader.rb`) merges nested `iocs` with legacy top-level `ips`, `domains`, `urls`, `emails`, `cves`, and inferred `hashes`, deduplicating exact strings. The current generator also extracts Markdown IOC bullets and emits rows with `type`, `value`, `normalized_value`, `canonical_value`, `lookup_keys`, `atomic`, actor identity, heading, and source file. The proposed contract preserves these views:

* `/api/iocs.json` remains an array; existing row keys remain present. New rows add `id`, `status`, `display_value`, dates, confidence, sources, and relationships.
* `/api/ioc-lookup.json` continues to map approved atomic normalized lookup keys to rows. False-positive and quarantined records are excluded.
* `/api/ioc-types.json`, `/api/iocs/by-type/<type>.json`, and `/api/iocs/by-actor/<slug>.json` remain available, with `schema_version`, `generated_at`, and source-manifest metadata added.
* Existing type keys (`ip_address`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `cve`, `attack_technique`) and page URLs are not renamed. New types get their own shards only after validation exists.
* Legacy lists map one string to one observation with `source.kind: legacy_actor_yaml`, `status: active` only if validation passes, and no invented dates/confidence/relationship. Markdown-only rows remain `atomic: false` until lifted into canonical YAML.

YAML remains backward compatible during migration: old lists are read; canonical observation objects are preferred; duplicate legacy/canonical values collapse by the key above. No generator may silently drop an invalid canonical object—report and quarantine it.

## 7. Fixture and acceptance contract

Fixtures in `test/fixtures/observables/` are normative examples, not production data:

* `valid-observables.yml` exercises every initial type, defanging, duplicate source observations, dates, relationships, and a false-positive record;
* `invalid-observables.yml` is a table of expected rejection reasons (bad hash length, malformed URL/email/IP, CIDR-as-IP, missing source, unregistered `other` subtype, and raw certificate material);
* `legacy-actor.yml` demonstrates nested and top-level legacy lists plus a duplicate;
* `expected-api-records.json` defines the compatibility row fields and exclusion of quarantined/false-positive records.

Implementation acceptance criteria:

1. Fixture values normalize to exactly one deterministic ID per `(type, normalized_value)`; repeated sources do not create duplicate rows.
2. Every invalid fixture case fails closed with a stable machine-readable reason; no invalid value reaches lookup, page output, or counts.
3. Defanged inputs validate only after reversible restoration; HTML uses `display_value`, while approved API atomic rows expose the documented canonical field.
4. Dates, confidence scope, source record metadata, relationship roles, status, and precision survive all projections without being confused with actor `last_updated` or actor-level confidence.
5. Legacy YAML and Markdown projections preserve existing keys, type names, URLs, and exact lookup behavior for valid values; canonical data wins only by normalized deduplication, never by deleting provenance.
6. False-positive and quarantined observations are retained for audit but excluded from public exact lookup, pages, and published counts.
7. A schema version and generated/source-manifest reference appear in each new/changed public payload, and deterministic generation produces byte-stable output.

See the parent audit in [data-sharing-audit.md](data-sharing-audit.md) for current measured coverage and the dependency order. This contract must be synthesized with provenance/safe-sharing and API/search contracts before implementation.
