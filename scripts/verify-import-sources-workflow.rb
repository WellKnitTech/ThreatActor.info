#!/usr/bin/env ruby
# frozen_string_literal: true

workflow_path = ARGV.fetch(0) { File.expand_path('../.github/workflows/import-sources.yml', __dir__) }
workflow = File.read(workflow_path)
failures = []

failures << 'workflow must preserve importer exit status through tee' unless workflow.match?(/set -o pipefail/) && workflow.match?(/ruby scripts\/import-automated-sources\.rb .*\| tee tmp\/import\.log/)
failures << 'workflow must not hide importer failures' if workflow.match?(/--continue-on-error/)
failures << 'freshness and build must be success-gated' unless workflow.scan(/if: \$\{\{ success\(\) \}\}/).length >= 2
failures << 'evidence upload must always run' unless workflow.match?(/Upload source snapshots, reports, and diagnostics/) && workflow.match?(/if: \$\{\{ always\(\) \}\}/) && workflow.match?(/actions\/upload-artifact@v4/)
failures << 'pull request creation must be success-gated' unless workflow.match?(/if: \$\{\{ success\(\) &&/)

if failures.empty?
  puts 'Automated source workflow safety checks passed.'
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end