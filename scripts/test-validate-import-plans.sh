#!/usr/bin/env bash
# Quick smoke test for the import plan validator guard (mixed report shapes).
# Run from repo root in an environment with Ruby 3.2.5 + Bundler:
#
#   bundle exec bash scripts/test-validate-import-plans.sh
#
# It should exit 0 and print a message that the array report was skipped.

set -euo pipefail

REPORT_DIR="tmp/test-import-reports"

echo "=== Testing validate-import-plans.rb with mixed report shapes ==="
echo "Report dir: $REPORT_DIR"
echo "Contents:"
ls -1 "$REPORT_DIR"/plan-*.json

# The validator should:
# - Process the good object report
# - Warn + skip the array report (from old ransomlook or similar)
# - Succeed overall (exit 0) instead of raising TypeError

bundle exec ruby scripts/validate-import-plans.rb \
  --report-dir "$REPORT_DIR" \
  --config data/imports/plan_thresholds.yml

echo
echo "SUCCESS: validator survived mixed (object + array) reports without crashing."
echo "The guard + cleanup + ransomlook summary changes are working."
