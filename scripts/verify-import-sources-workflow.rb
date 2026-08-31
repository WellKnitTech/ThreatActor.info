#!/usr/bin/env ruby
# frozen_string_literal: true

# Exact safety checks for the production automated-import workflow.
workflow_path = ARGV.fetch(0) { File.expand_path('../.github/workflows/import-sources.yml', __dir__) }
workflow = File.read(workflow_path)
failures = []

failures << 'workflow must not continue after import failures' if workflow.match?(/--continue-on-error/)
failures << 'workflow must use the hardened automated runner' unless workflow.match?(/scripts\/import-automated-sources\.rb/)
failures << 'workflow must pass an explicit report directory' unless workflow.match?(/--report-dir\s+tmp\/import-reports/)
failures << 'workflow must run the source freshness check' unless workflow.match?(/scripts\/check-source-freshness\.rb/)
failures << 'workflow must upload source evidence after failures' unless workflow.match?(/if:\s+always\(\)/) && workflow.match?(/actions\/upload-artifact@v4/)
failures << 'workflow must not use an admin merge bypass' if workflow.match?(/gh\s+pr\s+merge[^\n]*--admin\b/)
failures << 'workflow must build only after imports pass' unless workflow.index('- name: Build site') && workflow.index('- name: Run automated source imports') < workflow.index('- name: Build site')

if failures.empty?
  puts 'Import sources workflow safety checks passed.'
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end