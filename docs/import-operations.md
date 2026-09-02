# Automated import operations

This is the operator runbook for the scheduled source-import workflows. The
canonical data path is:

```text
fetch snapshot -> plan -> validate plans -> import -> regenerate -> validate -> PR
```

The workflows never write directly to `main`. They create a pull request (and
the weekly workflow queues normal protected auto-merge when all repository
rules allow it).

## Workflows and scheduling

| Workflow | Schedule | Purpose |
|---|---:|---|
| `Weekly Threat Data` | Sunday 03:00 UTC | Full source refresh with delta checks, schema/content validation, build, and protected auto-merge queueing |
| `Automated Source Imports` | Monday 03:21 UTC | Full source refresh with freshness checks, build, and a review PR |

Both workflows use the shared concurrency group `threat-data-import` with
`cancel-in-progress: false`. A manual run waits for an existing import instead
of running a second copy concurrently.

Use `Weekly Threat Data` for a phase-specific diagnostic run. Its dispatch
inputs are:

- `source`: optional source key, such as `malpedia` or `threatfox`.
- `phase`: `fetch`, `plan`, `import`, or `all`.

`fetch` creates a snapshot only. `plan` reads an existing snapshot without
applying it. `import` applies an existing snapshot with `--no-fetch`. `all` is
the normal end-to-end path.

## Secrets and environments

Secrets belong in the GitHub `data-import` environment, not in repository
files, workflow literals, snapshots, logs, or pull requests.

Required environment secret for live ThreatFox access:

```text
THREATFOX_API_KEY
```

The environment should permit deployments from `main` only. The import jobs
must declare `environment: data-import` before the environment secret is
available to their steps. A missing ThreatFox key is safe: the importer writes
a deterministic `no_auth_key` snapshot and marks the source unavailable rather
than inventing data.

Malpedia currently uses its public API endpoints and does not require a
repository secret for this importer. If Malpedia credentials are introduced,
use a separate environment secret and update the importer documentation before
wiring it into a workflow.

## Malpedia request policy

The Malpedia importer performs three collection requests and, when details are
enabled, one detail request per actor. It therefore uses the following guardrails:

- Requests are serialized with a 2-second interval (at most 30 requests per
  minute).
- The first HTTP 429 raises a typed rate-limit error and stops the actor loop;
  it is not swallowed and followed by more requests.
- The response's `Retry-After` value is included in diagnostics when supplied.
- The weekly workflow does not retry a run after an HTTP 429. Retrying the full
  source immediately would amplify the upstream rate limit.
- The two import workflows cannot overlap because of the shared concurrency
  group.

Do not use repeated manual dispatches to test Malpedia. For a targeted live
run, use one dispatch with `source=malpedia`, then wait for the run and inspect
its artifact and summary.

## Responding to a Malpedia 429

1. Stop manual reruns and let the current run finish its diagnostic upload.
2. Open the run summary and artifact; confirm the response URL and any
   `Retry-After` value.
3. Check that no Malpedia import PR was created from the incomplete fetch.
4. Wait for the upstream cooldown. Do not bypass the importer pacing or run
   parallel jobs.
5. Use the next scheduled run, or perform one targeted `fetch` run after the
   cooldown.
6. If the source remains unavailable, keep the last known good snapshot and
   document the degraded source in the run/PR notes. Do not delete existing
   actor enrichment merely because the latest fetch was rate-limited.

## Inspecting a run

List recent weekly runs:

```bash
gh run list --workflow weekly-data.yml --limit 5
```

View a run and its failed log sections:

```bash
gh run view RUN_ID
gh run view RUN_ID --log-failed
```

The uploaded artifact contains source snapshots, import reports, the health
summary, the import log, and failure diagnostics. Never print secret values
while inspecting logs or workflow configuration.

## Local verification

Before changing importer or workflow behavior, run the focused checks:

```bash
ruby test/import_malpedia_rate_limit_test.rb
ruby test/verify_weekly_data_workflow_test.rb
ruby test/verify_workflow_dependency_policy_test.rb
ruby scripts/verify-weekly-data-workflow.rb
git diff --check
```

For a normal local import, prefer a source-only plan before applying anything:

```bash
ruby scripts/import-automated-sources.rb --source malpedia --plan-only
ruby scripts/import-automated-sources.rb --source malpedia --apply
```

Review generated actor, page, API, and snapshot changes together. See
[Keeping actor pages current](keeping-actor-pages-current.md) for the commit
surface and regeneration rules.
