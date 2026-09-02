# Source coverage and IOC ingestion roadmap

Reviewed: 2026-09-02

This is an evidence-backed prioritization of additional public sources for ThreatActor.info. It is a roadmap, not an approval to ingest data. Every new source must remain snapshot-backed and deterministic: fetch raw input, record URL/retrieval/checksum/license terms, validate the snapshot, produce a side-effect-free plan, quarantine bad or surprising input, and only then apply reviewed changes.

## Current coverage

The automated runner currently exposes 24 sources (`ruby scripts/import-automated-sources.rb --list-sources`). The first 23 are principally actor identity, alias, ATT&CK, malware, vulnerability, tradecraft, or report-index enrichment; `threatfox` is the only current source explicitly designed to add structured IOCs to actor YAML.

| Tier | Current sources | Coverage and limitation |
|---|---|---|
| Canonical structured backbone | MITRE ATT&CK; Wiz Cloud Threat Landscape; MISP Galaxy; ETDA/ThaiCERT; Malpedia; APTmap; EternalLiberty | Strongest deterministic inputs (STIX/JSON/static data). Mostly identity, relationships, malware, and TTPs rather than fresh observables. MITRE is the ordering anchor. |
| Identity and report enrichment | Microsoft Threat Actor List; APT Groups & Operations; APTnotes; Google Cloud APT Groups; BreachHQ; Dragos; Unit 42; RansomLook | Useful names, aliases, reports, incidents, and ransomware context. Most are secondary indexes or HTML-derived and should not create an actor without review. |
| Tradecraft and vulnerability context | Rapid7 ABA Detections; Sophos Threat Profiles; Bushido ransomware tool/vulnerability matrices; Russian APT Tool Matrix; RedDrip7 APT_Digital_Weapon; MOVEit tracking; Bushido breach reports | High analyst value, but observations are not equivalent to actor attribution or durable IOC evidence. Preserve as attributed provenance, not volatile IOC lists. |
| IOC path | abuse.ch ThreatFox | API requires `THREATFOX_API_KEY`; without it the importer deliberately writes a deterministic `no_auth_key` empty snapshot. Current matching is conservative (malware/tags plus alias overrides) and supports the repository's structured IOC types. |

Existing implementation already supplies the needed safety pattern: shared source-adapter lifecycle (`docs/source-adapter-contract.md`), dated snapshots and manifests, plan thresholds, quarantine/quality gates, and a runner that fetches/plans all sources before applying any of them. New work should extend those paths rather than add an ad hoc downloader.

Measured baseline from the upstream coverage audit (`docs/data-sharing-audit.md`, parent task): 3,615 canonical actor YAML records, 3,614 generated actor API rows, 3,615 actor pages, 1,881 malware pages, and only 9 generated IOC rows across 7 IOC lookup keys and 2 IOC types. The largest near-term value is therefore reliable observable enrichment, not another alias-only catalog.

## Ranked roadmap

Estimates are engineering effort for a minimal fetch/validate/plan/import adapter, excluding long-running manual mapping. They assume reuse of `ImportUtils`, `SourceAdapter`, `IocYamlReader`, snapshot manifests, and existing validation. `P0` means do next; `P1` means valuable after the first IOC feed proves safe; `R` means research/triage only for now.

| Rank | Source / proposed key | Value and likely fields | Evidence and operational constraints | Licensing / provenance decision | Estimate |
|---:|---|---|---|---|---:|
| 1 | URLhaus (`urlhaus`) | Malware-distribution URLs, domains, IPs, tags, malware family, first/last seen; direct IOC expansion complementary to ThreatFox. | Official Community API documents full/active/recent dumps: https://urlhaus.abuse.ch/api/ . Bulk export is a better deterministic input than per-URL lookups. Add bounded HTTPS fetch, conditional/checksum capture, age filtering, and reject rows lacking URL/date/type. Do not ingest every historical URL into actor YAML. | Record the exact export URL and abuse.ch/Spamhaus terms in manifest; preserve source row IDs and attribution. Confirm current redistribution terms before publishing derived data. | 3–5 days |
| 2 | MalwareBazaar (`malwarebazaar`) | SHA-256/MD5/SHA-1, malware family, signature, tags, file type, first seen, reporter; joins actor↔malware already modeled in the site. | Official API says community API is free under fair-use principles and documents a daily download limit: https://bazaar.abuse.ch/api/ . Exports state recent additions cover 48 hours, generated every 5 minutes, and full dumps hourly: https://bazaar.abuse.ch/export/ . Use metadata/hash exports only; never download samples. Auth key is required for exports/API. | Store only metadata and stable source links; do not redistribute samples. Gate on key availability exactly as ThreatFox does and mark no-auth snapshots rather than failing the whole run. Verify commercial/fair-use terms at implementation. | 3–5 days |
| 3 | Feodo Tracker (`feodo-tracker`) | Botnet C2 IPv4/IPv6, port, malware family, status, first/last seen; source-specific C2 observables useful for actor and malware correlation. | abuse.ch publishes machine-readable downloads, including the documented recommended IP blocklist at `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`; use the project API/download documentation as canonical source. Static export is low complexity but needs strict CSV/line validation and expiry handling. | Same abuse.ch attribution/terms review as URLhaus and MalwareBazaar. Keep feed rows in a provenance/IOC snapshot and do not imply actor attribution from malware family alone. | 2–4 days |
| 4 | CISA KEV (`cisa-kev`) | CVE, vendor/product, vulnerability name, date added, due date, required action, known ransomware use; enrich existing vulnerability and ransomware context. | Official catalog supplies CSV and JSON: https://www.cisa.gov/known-exploited-vulnerabilities-catalog . CISA's `cisagov/kev-data` mirror reports updates shortly after canonical changes, typically weekdays when entries change: https://github.com/cisagov/kev-data . Fetch canonical JSON with checksum and fail closed on schema/duplicate-CVE anomalies. | Record CISA catalog license/reuse notice verbatim in manifest; this is public vulnerability data, not actor attribution. No actor YAML writes in the first phase; populate a generated vulnerability enrichment index. | 2–4 days |
| 5 | FIRST EPSS (`first-epss`) | Daily CVE exploit-probability score and percentile; prioritization signal for KEV/CVE pages and API consumers. | Official data page says scores are daily, free, and no registration is required; API is intended for one/small-batch lookup rather than bulk: https://www.first.org/epss/data . API documentation warns that 429 means temporary blocking and discourages concurrent large loops: https://api.first.org/ . Prefer daily CSV, if terms permit, or bounded batch lookups with backoff. | Preserve FIRST usage agreement and attribution; treat scores as enrichment, not evidence that an actor exploited a CVE. | 2–3 days |
| 6 | MISP public feed catalog (`misp-feeds`) | STIX/MISP events with domains, IPs, URLs, hashes, malware and threat-actor context; potentially high IOC yield and overlap with existing MISP Galaxy. | MISP documents public OSINT feeds and feed formats at https://www.misp-project.org/feeds/ . Feeds differ in availability, quality, schema, and licensing. Start with an allowlisted feed manifest and one feed at a time; never crawl the catalog indiscriminately. Require event UUID, timestamp, indicator type/value, distribution/expiry handling, and per-feed failure quarantine. | License is feed-specific, not inherited from MISP software. Store feed URL, event UUID, publisher, and license in every snapshot; exclude feeds whose redistribution terms are unclear. | 5–8 days for framework + first feed |
| 7 | AlienVault OTX (`otx`) | Pulses containing IP/domain/URL/hash observables and analyst context; broad coverage for enrichment and cross-source correlation. | Official API landing page: https://otx.alienvault.com/api . Public documentation/search results indicate API-key use and rate limiting, but no stable universal quota was found in this audit. Treat quota as unknown until verified with a test key; use bounded pulse windows, retries/backoff, and `Retry-After`. | User/community-contributed pulse licensing and redistribution terms must be reviewed before any public derived dataset. Initial adapter should produce a private/research snapshot and no actor writes. | 5–8 days plus terms review |
| 8 | Abuse.ch specialized exports beyond Feodo (`sslbl`, `urlhaus`, `bazaar`) | SSL certificate fingerprints, botnet infrastructure, hashes, and URLs where a source-specific feed is materially better than a generic feed. | abuse.ch's projects publish separate API/export surfaces and refresh schedules. Reuse one hardened abuse.ch client, but retain independent manifests and quality thresholds per dataset. | Dataset-specific attribution and reuse terms required; do not assume one feed's terms apply to another. | 2–3 days per feed after shared client |

## Research-only / do not automate yet

These can improve analyst discovery but currently lack a sufficiently stable, clearly redistributable, machine-readable contract for a public deterministic build:

- Vendor report/article pages (Google Cloud, Unit 42, Dragos, Sophos, Microsoft, Rapid7): retain the existing snapshot-backed adapters for reviewed aliases and citations, but do not turn prose scraping into automatic IOC attribution. Article URLs and copyright remain with the publisher.
- GreyNoise, VirusTotal, Recorded Future, Mandiant, CrowdStrike, Palo Alto commercial APIs: potentially excellent observables, but authentication, quotas, paid terms, and redistribution restrictions make them unsuitable for the public repository without an explicit license agreement.
- Social/search-derived IOC feeds and arbitrary GitHub repositories: useful for leads but unstable, frequently duplicated, and unclear in provenance. Accept only through a reviewed source manifest with pinned commit/release and explicit license.
- OpenCTI demonstration/public instances: OpenCTI is a platform, not one authoritative feed. Its model is STIX 2.1 and supports TAXII/feeds, but instance data provenance and redistribution rights vary. Use only when a named collection and license are available; reference: https://docs.opencti.io/latest/usage/feeds/ .

## Integration contract for every new source

1. Add a canonical source row to `docs/importers.md` and `attribution.md` in the same change.
2. Add a unique runner priority in the appropriate structured/tabular/markdown/HTML tier; preserve MITRE priority `1` and do not reorder existing sources casually.
3. Implement `fetch -> validate_snapshot -> plan -> apply -> report` (or wrap the legacy importer), writing only under `data/imports/<key>/<date>/` during fetch/plan.
4. Persist retrieval URL, timestamp, HTTP status, ETag/Last-Modified when available, content checksum, source version/commit, license/terms URL, and authentication mode in `manifest.yml`.
5. Validate content type, schema, row cardinality, duplicate IDs, indicator syntax, timestamps, and maximum size. Quarantine empty, truncated, malformed, unexpectedly huge, or license-unknown snapshots instead of applying them.
6. Keep actor attribution conservative: an IOC can be attached only through explicit source context or a reviewed mapping; malware-name coincidence alone is not actor attribution. Preserve unmatched rows in the plan report for analyst review.
7. Use `iocs:` and supported `ioc_type` values so `IocYamlReader`, generated actor `ioc_count`, `/api/iocs.json`, and lookup indexes stay aligned. Add expiry/last-seen semantics before importing feeds with rapidly aging indicators.
8. Add deterministic fixture tests and run `ruby scripts/test-source-adapter.rb`, source-specific tests, `ruby scripts/validate-import-plans.rb`, `ruby scripts/validate-content.rb`, and the safe build. Never make Jekyll build depend on a live feed.

## Recommended sequence

- Sprint 1: URLhaus adapter, using ThreatFox's IOC merge and no-auth/quarantine behavior as the reference. Measure matched, unmatched, expired, and duplicate indicators before enabling apply.
- Sprint 2: MalwareBazaar metadata and Feodo Tracker, sharing HTTP/export and IOC normalization code but keeping separate provenance and thresholds. Add malware-hash joins without sample downloads.
- Sprint 3: CISA KEV plus FIRST EPSS as non-actor vulnerability enrichment. This broadens useful coverage without increasing attribution risk.
- Sprint 4: MISP allowlisted-feed framework; select one explicitly licensed feed after a fixture and terms review. Defer general feed crawling.
- Reassess OTX and additional abuse.ch feeds only after observing snapshot size, duplicate rate, match quality, and CI/runtime impact.

Success should be measured by provenance-complete, deduplicated, reviewable coverage—not raw IOC count. A source that cannot explain where an indicator came from, when it expires, and why it maps to an actor must remain quarantined or research-only.

## Evidence links

- Current importer inventory and policy: `docs/importers.md`, `scripts/import-automated-sources.rb`
- Adapter lifecycle: `docs/source-adapter-contract.md`
- abuse.ch ThreatFox: https://threatfox.abuse.ch/api/
- abuse.ch URLhaus API: https://urlhaus.abuse.ch/api/
- abuse.ch MalwareBazaar API/export: https://bazaar.abuse.ch/api/ and https://bazaar.abuse.ch/export/
- MISP feeds: https://www.misp-project.org/feeds/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS data/API: https://www.first.org/epss/data and https://api.first.org/
- AlienVault OTX API: https://otx.alienvault.com/api
- OpenCTI feeds: https://docs.opencti.io/latest/usage/feeds/
