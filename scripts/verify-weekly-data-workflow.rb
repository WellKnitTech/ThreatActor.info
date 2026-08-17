#!/usr/bin/env ruby

# Failure-mode test for the scheduled data workflow. This intentionally checks
# the rendered workflow text so a future edit cannot quietly restore an admin
# merge or broaden the default token permissions.

workflow_path = ARGV.fetch(0) { File.expand_path("../.github/workflows/weekly-data.yml", __dir__) }
workflow = File.read(workflow_path)
failures = []

failures << "workflow must not contain an admin merge bypass" if workflow.match?(/gh\s+pr\s+merge[^\n]*--admin\b/)
failures << "workflow must queue a normal protected auto-merge" unless workflow.match?(/gh\s+pr\s+merge\s+\"\$branch\"\s+--auto\s+--squash\s+--delete-branch/)
failures << "workflow default permissions must be read-only for repository contents" unless workflow.match?(/^permissions:\s*\n\s+contents:\s+read\s*$/)
failures << "write permissions must be scoped to the update-data job" unless workflow.match?(/update-data:\s*\n(?:\s+[^\n]+\n)*?\s+permissions:\s*\n\s+contents:\s+write\s*\n\s+pull-requests:\s+write/)
failures << "weekly imports must continue past an unavailable source" unless workflow.match?(/import-automated-sources\.rb\s+--continue-on-error\s+--apply/)
failures << "workflow must validate before opening the pull request" unless workflow.index("- name: Validate JSON schemas") && workflow.index("- name: Open weekly data pull request") && workflow.index("- name: Validate JSON schemas") < workflow.index("- name: Open weekly data pull request")

if failures.empty?
  puts "Weekly data workflow safety checks passed."
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end