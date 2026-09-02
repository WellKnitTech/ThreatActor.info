# Scheduled data workflow safety

The weekly threat-data workflow keeps unattended ingestion, but it cannot merge
around repository controls. It creates a bot pull request after the import and
validation steps, then uses GitHub's normal auto-merge path (`gh pr merge
--auto`). It deliberately does not use `--admin`; required checks, required
reviews, and any other branch-protection rules on `main` remain authoritative.

Repository administrators should keep `main` protected with the validation
workflow as a required status check and require an approving review (or an
explicitly governed bot-review policy) before enabling automatic merge for the
generated pull requests. If auto-merge is unavailable or protection requirements
are unmet, the scheduled job may leave the pull request open for normal review;
it must not bypass those requirements.

The failure-mode regression test is intentionally static and local:

```text
ruby scripts/verify-weekly-data-workflow.rb
```

Both automated import workflows use the shared GitHub Actions concurrency
group `threat-data-import` with `cancel-in-progress: false`. A scheduled or
manual run waits for another import instead of creating a concurrent source
fetch. See [Automated import operations](import-operations.md) for the
operator runbook, secret handling, and source-specific rate-limit policy.

It fails if `--admin` returns, if the workflow stops queueing a protected
auto-merge, if the default token becomes write-capable, if write permissions
escape the update job, or if validation is moved after pull-request creation.
For a failure-mode check, pass a temporary modified workflow path; the command
must fail when `--auto` is replaced with `--admin`:

```text
cp .github/workflows/weekly-data.yml /tmp/weekly-data-unsafe.yml
sed -i 's/--auto --squash/--admin --squash/' /tmp/weekly-data-unsafe.yml
ruby scripts/verify-weekly-data-workflow.rb /tmp/weekly-data-unsafe.yml
```

## Run evidence and targeted reruns

Every scheduled or manual run uploads the source snapshots under
`data/imports/`, importer reports, the human-readable health summary, the run
log, and failure diagnostics. The artifact is uploaded even when a fetch,
plan, validation, or build step fails. The summary is also written to the job
summary and used as the pull-request body.

`workflow_dispatch` accepts a source key and a phase (`all`, `fetch`, `plan`,
or `import`). `fetch` creates or refreshes a snapshot, `plan` evaluates an
existing snapshot without applying it, and `import` applies an existing plan
without fetching. The import step retries ordinary failures at most three
times with 1-second and 2-second backoff, but does **not** retry an upstream
HTTP 429. In particular, the Malpedia importer spaces requests by 2 seconds
and stops at the first 429 rather than continuing through the actor list.
The workflow does not use `continue-on-error`, and it never passes
`--allow-plan-anomalies`; quarantined or anomalous sources therefore remain
diagnostic-only.