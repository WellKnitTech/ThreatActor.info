# Shared source adapter contract

`require_relative 'scripts/lib/import/source_adapter'` exposes the foundation for staged source imports.

Adapters include `SourceImport::SourceAdapter` and implement the five lifecycle hooks:

```ruby
fetch(context)                         # => Result, snapshot data only
validate_snapshot(snapshot, context)   # => ValidationResult
plan(snapshot, catalog, context)        # => Plan (side-effect free)
apply(plan, writer, context)            # => ApplyResult
report(results, sink)                   # => ReportResult
```

The value objects are immutable and serialize to deterministic JSON. `SnapshotRef` and
`SnapshotManifest` identify the exact input; `Plan` records snapshot/catalog bindings and
computes a deterministic checksum; `RunReport` makes phase status, counts, warnings, and
diagnostics machine-readable. Statuses and diagnostic codes are stable strings from the
architecture contract. Unknown diagnostic codes are retained with `known_code: false`, so
new adapters remain forward-compatible without exception-message matching.

`SourceImport::LegacyAdapter` wraps an existing object exposing `fetch`, `plan`, and `apply`
without requiring an immediate importer migration. The wrapper does not add repository writes
to fetch or plan.

Focused contract tests run with the Ruby standard library:

```sh
ruby scripts/test-source-adapter.rb
```
