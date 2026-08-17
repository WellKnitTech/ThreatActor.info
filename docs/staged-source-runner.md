# Staged source runner

`scripts/lib/import/staged_runner.rb` provides the orchestration boundary for source adapters.

Each source receives a private, deterministic directory under `<root>/staging/<source-key>`
and runs `fetch`, `validate`, and `plan` there. Plans are not applied until the source reaches
`accepted`; quarantined sources retain diagnostics and cannot write to the output tree.

Accepted plans are applied to a temporary output tree. The old output is renamed to a rollback
path before the candidate tree is atomically installed; a write failure restores the old tree.
Derived-output regeneration is invoked once, after a successful apply. Runner state remains in
memory so a rerun can select a quarantined source without fetching, planning, or applying sources
that already succeeded.

Adapter shape:

```ruby
SourceImport::StagedRunner.new(sources: adapters, root: 'tmp/run', retries: 1,
  regenerate: -> { regenerate_outputs })
```

Each adapter implements `key`, `fetch(stage:, attempt:)`, `validate(snapshot:, stage:)`,
`plan(snapshot:, stage:)`, and `apply(plan:, output:, stage:)`.
