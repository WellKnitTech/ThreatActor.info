# Automated import performance baseline

Captured 2026-09-01 UTC from three sequential, non-apply runs on the current `main` checkout. Each run fetched and planned MITRE ATT&CK, Wiz Cloud Threat Landscape, and MISP Galaxy (MISP capped at 50 records), in the existing priority order. No importer writes, regeneration, threshold bypass, timeout change, or auth change was used.

Raw per-run evidence is kept in `docs/import-performance-baseline/run-{1,2,3}.json`. The command was:

```text
BUNDLE_PATH=/tmp/threatactor-bundle BUNDLE_APP_CONFIG=/tmp/threatactor-bundle-config bundle exec ruby scripts/import-automated-sources.rb --source mitre-attack --source misp-galaxy --source wiz-cloud-threat-landscape --limit 50 --metrics-json tmp/baseline-run-N.json --report-dir tmp/baseline-reports-N --date 2026-09-01
```

## Observed timings

| Source / phase | Run 1 (ms) | Run 2 (ms) | Run 3 (ms) | Mean (ms) | Snapshot bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| MITRE fetch | 2701.4 | 1558.2 | 1185.5 | 1815.0 | 63,644,456 |
| MITRE plan | 1534.1 | 1496.3 | 1504.3 | 1511.5 | 63,644,456 |
| Wiz fetch | 735.0 | 624.9 | 657.4 | 672.4 | 994,958 |
| Wiz plan | 932.5 | 916.0 | 912.1 | 920.2 | 994,958 |
| MISP fetch | 1748.0 | 865.5 | 1089.9 | 1234.4 | 406,764 |
| MISP plan | 1410.1 | 1400.9 | 1391.0 | 1400.6 | 406,764 |
| Whole run | 9061.9 | 6862.6 | 6741.0 | 7555.1 | - |

All six commands exited 0. The repeated `bundle exec` command timings include Ruby/Bundler process setup; `bundle check` was used to install the locked dependencies before measurement, but no separate setup benchmark was inferred. The instrumented workflow now emits the same metrics as `tmp/import-reports/performance-metrics.json` and uploads it with the source evidence.

Request counts are intentionally `null`: the subprocess wrapper cannot safely infer HTTP requests made inside source-specific clients. Workflow-level retries are recorded separately in the existing failure diagnostic; source-level retries in these runs were 0. Snapshot byte totals are recursive file sizes and are safe payload-size proxies, not wire-byte counts.

## Bottleneck assessment

- MITRE fetch is the largest single phase (1,815 ms mean) and has the highest payload (60.7 MiB); it is the first optimization target, but its fetch variance is also high.
- MITRE planning (1,512 ms mean) and MISP planning (1,401 ms mean) are the next largest deterministic CPU/process contributors.
- The three-source measured work totals about 7.6 seconds mean. This excludes import and regeneration because this baseline intentionally used the fail-closed default non-apply mode; those phases must be measured in a separately approved canary before concurrency changes.

## Initial guardrails

1. Preserve source priority ordering and the fetch → plan → validation → import → regeneration gates.
2. Start any future concurrency experiment at a limit of **1 concurrent source** (the current serial behavior); test 2 only after an apply-mode canary demonstrates unchanged plans, source freshness, quality gates, and generated output.
3. A candidate optimization is acceptable only if all selected source plans remain accepted, no source is silently skipped, request/retry diagnostics remain attributable, and generated-output validation is unchanged.
4. Baseline acceptance thresholds for this representative set: whole-run wall time ≤ **11,333 ms** (mean + 50%), MITRE fetch ≤ **2,723 ms**, MITRE plan ≤ **2,267 ms**, Wiz fetch ≤ **1,009 ms**, Wiz plan ≤ **1,380 ms**, MISP fetch ≤ **1,852 ms**, and MISP plan ≤ **2,101 ms**. A threshold breach is diagnostic, not permission to weaken timeouts or quality gates.
5. Before declaring an optimization successful, capture at least three apply-mode runs with import and regeneration timings and compare plan/report payloads and source evidence byte totals.
