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