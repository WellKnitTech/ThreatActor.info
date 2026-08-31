# Offline source-import fixture harness

The fixture contract suite exercises the source parser boundary without contacting Unit 42 or Dragos:

```bash
ruby scripts/test-source-import-fixtures.sh
```

It is intentionally standard Minitest and runs under Ruby 3.2 with the normal `Gemfile` dependencies. Each source has canonical, changed-layout, malformed, and empty snapshots. Dragos also includes blocked, timeout, and HTTP-error contract cases.

Fixture directories contain source HTML and an `expected.json` contract with:

- `status`: `accepted`, `retryable_error`, or `quarantine`
- `counts`: parser/detail-page counts where applicable
- `provenance.source_name`: the source attribution required in reports

The harness copies snapshots into temporary directories when testing plan/apply behavior and compares generated-data bytes before and after failed plans. No live network or repository data is needed.
