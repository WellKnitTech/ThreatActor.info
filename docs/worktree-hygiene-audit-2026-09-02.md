# ThreatActor.info worktree hygiene audit

Audit timestamp: 2026-09-02T17:13:49Z (UTC)

## Scope and method

This audit inspected `git status`, `git worktree list --porcelain`, local branch tracking, recent history, PR #109 metadata, and the dirty durable checkout at `/var/home/jwellnitz/projects/ThreatActor.info`. No checkout, branch, file, or Git reference was deleted, reset, overwritten, or pruned.

## Findings

### Durable checkout is not safe as an integration checkout

`/var/home/jwellnitz/projects/ThreatActor.info` is on `kanban/durable-importer-integration` at `72255188` (`fix: reuse ThreatFox snapshot without credentials`). Its upstream is `origin/fix/mitre-plan-validator`, which is gone. The checkout has 21 tracked files modified and many untracked paths (105 status lines including tracked changes). The tracked diff is large (63,141 insertions and 188,645 deletions), including generated indexes, actor/page output, a layout, CSS, attribution/API docs, `.gitignore`, and `scripts/generate-indexes.rb`.

This is branch drift plus an active dirty workstream, not harmless build noise. The tracked and untracked paths are not safe to discard without identifying the owner and preserving a snapshot.

### The dirty content is an OCD ransomware ecosystem workstream

The untracked implementation and fixtures include:

- `scripts/import-ocd-ransomware-map.rb`
- `scripts/ocd_entity_reconciler.py`
- `scripts/reconcile_cli.py`
- `test/ocd_*`, `test/test_ocd_entity_reconciler.py`, and OCD fixture trees
- `_data/generated/ocd_ransomware_ecosystem.json`
- `api/ocd_ransomware_ecosystem.json`
- `data/imports/ocd-ransomware-map/`

These paths match the files in the already-merged OCD ecosystem history (`d2a752f7`, `3d918c5d`, merge `f6a26196`, PR #105). The modified layout, generator, CSS, attribution, and API documentation also overlap that feature. Treat this as recoverable active/review material or a partially regenerated copy until its owner confirms otherwise; do not clean it with `git clean` or `git reset`.

The empty untracked files `import` and `plan`, plus `scripts/__pycache__/`, are likely command/prototyping residue. They are safe candidates for removal only after the active OCD workstream has been snapshotted or otherwise confirmed preserved. They are not currently ignored.

### Nested worktree directory is a major storage and hygiene risk

The durable checkout reports untracked `.worktrees/`, which consumes approximately 6.9G. The canonical Git worktree registry already contains dozens of worktrees under `/var/home/jwellnitz/projects/ThreatActor.info/.worktrees/`; the nested directory should not be treated as repository content. It is not ignored by the current `.gitignore`. Inspect and archive/remove only the nested directory after confirming it is not an independently referenced worktree location.

### Other registered worktrees

Several `/var/home/jwellnitz/projects/ThreatActor.info/.worktrees/t_*` worktrees contain uncommitted user/worker changes, notably `t_014d030e`, `t_17574f1c`, `t_2c65893c`, `t_2f70dcda`, `t_3b00332d`, `t_639ddd02`, `t_7512ea7e`, `t_7e0c7b66`, `t_81c04320`, `t_8916c732`, `t_8fee6f96`, `t_96ef948b`, `t_9be57a69`, `t_d3ad68c5`, `t_f5470440`, `t_f903001d`, and `t_ffd6596c`. The `/var/home/jwellnitz/.hermes/kanban/boards/threatactor-review/workspaces/` tree also contains dirty `t_b01690f8`. These must be handled per task/owner, not bulk-pruned.

There are two registered worktrees marked prunable because their gitdir files point at missing locations: `/tmp/threatactor-ocd-pr-68c967c3` and `/var/home/jwellnitz/.hermes/kanban/boards/threatactor-review/workspaces/t_73db6564`. Their registry entries should be pruned only after confirming the paths are no longer needed; this is a reversible metadata cleanup but was intentionally not performed here.

### Clean main worktree exists but is stale

`/var/home/jwellnitz/projects/ThreatActor.info/.worktrees/t_89081330` is a clean `main` worktree at `526c7e47`, but local `main` is 12 commits behind the locally known `origin/main`. The known remote tip includes PR #109's later integration history and subsequent PRs through the 2026-09-02 daily update. It is therefore the correct isolation point for the next integration PR only after a normal, reviewed fast-forward/update from the current remote; do not build the next PR from the dirty durable checkout.

PR #109 is verified merged: https://github.com/WellKnitTech/ThreatActor.info/pull/109 (merge commit `858ad124`, merged 2026-08-31T18:50:13Z).

## Non-destructive isolation plan

1. Announce/record that `/var/home/jwellnitz/projects/ThreatActor.info` is occupied by the dirty OCD ecosystem workstream. Freeze it; do not run generators or imports there.
2. Preserve the workstream before cleanup: have its owner commit it on a named branch, or create a patch covering both staged and unstaged changes plus a tar archive of untracked OCD files. A temporary local commit/ref is also acceptable if it is recorded and not pushed. Record hashes and archive paths outside the repository. Do not use `git bundle` as the backup for uncommitted changes: bundles contain committed objects reachable from refs, not the index or worktree diff. Do not use `git stash -u` as the sole backup because it is easy to lose track of untracked/generated material.
3. Separately inspect `.worktrees/` at the durable checkout. If it is only an accidental nested copy, archive it or move it outside the repository, then add `.worktrees/` (or the precise intended path) to `.gitignore` in a dedicated hygiene change. Do not add a broad ignore until its ownership is confirmed.
4. Remove only confirmed residue (`import`, `plan`, and Python bytecode) after preservation. Keep OCD snapshots, fixtures, generated API output, and source changes until the owner confirms disposition.
5. For each dirty registered worktree, ask the corresponding Kanban task/owner to complete, preserve, or explicitly abandon it. Only then remove its worktree and prune stale registry entries.
6. Update the clean `main` worktree from remote using the repository's normal PR workflow, verify `git status --short --branch` is clean and that `git diff --exit-code origin/main`, then create the next integration branch/worktree from that clean tip.

## Safe-use conclusion

The main checkout itself is not the dirty durable path; a clean main worktree exists and can be used after synchronization. The durable checkout and the broad worktree set are not safe for bulk cleanup. The only safe immediate action is isolation and owner-confirmed preservation; cleanup should be a separate, reversible change with an evidence log.
