#!/bin/bash

set -euo pipefail

echo "Starting ThreatActor.info validation pipeline..."
echo "=================================================="

check_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name"
    exit 1
  fi
}

check_file() {
  local file_path="$1"

  if [ ! -f "$file_path" ]; then
    echo "Missing required file: $file_path"
    exit 1
  fi
}

check_dir() {
  local dir_path="$1"

  if [ ! -d "$dir_path" ]; then
    echo "Missing required directory: $dir_path"
    exit 1
  fi
}

check_command ruby
check_command bundle

check_dir "_data/actors"
check_file "_config.yml"
check_file "scripts/generate-pages.rb"
check_file "scripts/generate-indexes.rb"
check_file "scripts/evaluate-source-deltas.rb"
check_file "scripts/validate-content.rb"
check_file "scripts/validate-json-schemas.rb"
check_file "scripts/check-persona-content.rb"

check_file "scripts/check-source-freshness.rb"
check_file "scripts/verify-weekly-data-workflow.rb"
check_file "scripts/verify-import-sources-workflow.rb"
check_file "scripts/test-import-runner-contract.rb"

echo "Running source freshness check (warning mode for local validation)..."
ruby scripts/check-source-freshness.rb --mode warn --report-json tmp/source-freshness-report.json

echo "Checking scheduled workflow merge safety..."
ruby scripts/verify-weekly-data-workflow.rb
ruby scripts/verify-import-sources-workflow.rb
ruby scripts/test-import-runner-contract.rb

echo "Running import deadline and soft-fail regression tests..."
bundle exec ruby test/import_deadline_phases_test.rb
bundle exec ruby test/bounded_source_runner_critical_test.rb
bundle exec ruby scripts/test-import-health.rb
bundle exec ruby test/validate_import_plans_test.rb
bundle exec ruby test/plan_anomaly_quarantine_test.rb
bundle exec ruby scripts/test-observable-importers.rb
bundle exec ruby test/alias_resolver_disambiguation_test.rb
bundle exec ruby test/actor_store_data_path_test.rb
bundle exec ruby test/malware_actor_urls_test.rb
bundle exec ruby test/import_dragos_unit42_data_path_test.rb
bundle exec ruby test/verify_weekly_data_workflow_test.rb
bundle exec ruby test/liquid_safe_text_test.rb
bundle exec ruby test/import_mitre_group_slug_map_test.rb

echo "Checking for removed persona content..."
ruby scripts/check-persona-content.rb

echo "Running page and index generators..."
echo "(Indexes are regenerated here so _data/generated/ and api/ stay aligned before validation and build.)"
ruby scripts/generate-pages.rb --force
ruby scripts/generate-indexes.rb
ruby scripts/repair-malware-actor-urls.rb --drop-unresolved

echo "Running JSON Schema validator..."
ruby scripts/validate-json-schemas.rb

echo "Running content validator..."
ruby scripts/validate-content.rb

echo "Running Jekyll doctor..."
if ! bundle exec jekyll doctor; then
  echo "Jekyll doctor reported warnings; continuing with build verification..."
fi

echo "Building site in safe mode..."
bundle exec jekyll build --safe

echo "Validating built API payloads..."
ruby -e "require 'json'; Dir.glob('_site/api/**/*.json').each { |path| JSON.parse(File.read(path)) }"

echo "Validation pipeline completed successfully."
echo "=================================================="
