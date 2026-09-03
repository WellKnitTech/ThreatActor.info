#!/usr/bin/env ruby

# Failure-mode test for the scheduled data workflow. This intentionally checks
# the rendered workflow text so a future edit cannot quietly restore an admin
# merge, hide source failures, or omit run evidence.

workflow_path = ARGV.fetch(0) { File.expand_path("../.github/workflows/weekly-data.yml", __dir__) }
workflow = File.read(workflow_path)
failures = []

def update_data_job_has_write_permissions?(workflow)
  lines = workflow.lines
  job_start = lines.index { |line| line.match?(/\A  update-data:\s*\z/) }
  return false unless job_start

  job_lines = lines[(job_start + 1)..].take_while { |line| !line.match?(/\A  \S/) }
  permissions_start = job_lines.index { |line| line.match?(/\A    permissions:\s*\z/) }
  return false unless permissions_start

  job_lines[(permissions_start + 1)..]&.take(2) == ["      contents: write\n", "      pull-requests: write\n"]
end

failures << "workflow must not contain an admin merge bypass" if workflow.match?(/gh\s+pr\s+merge[^\n]*--admin\b/)
failures << "workflow must queue a normal protected auto-merge" unless workflow.match?(/gh\s+pr\s+merge\s+\"\$branch\"\s+--auto\s+--squash\s+--delete-branch/)
failures << "workflow default permissions must be read-only for repository contents" unless workflow.match?(/^permissions:\s*\n\s+contents:\s+read\s*$/)
failures << "write permissions must be scoped to the update-data job" unless update_data_job_has_write_permissions?(workflow)
failures << "workflow must not use continue-on-error to hide source failures" if workflow.match?(/continue-on-error/)
failures << "workflow must retry failed imports with a bounded attempt count" unless workflow.match?(/max_attempts=3/) && workflow.match?(/sleep \"\$delay\"/)
failures << "workflow must expose source-level manual reruns" unless workflow.match?(/inputs:\s*\n\s+source:/) && workflow.match?(/--source \"\$REQUESTED_SOURCE\"/)
failures << "workflow must expose phase-level manual reruns" unless workflow.match?(/phase:/) && workflow.match?(/fetch\) args\+=\(--fetch-only\)/) && workflow.match?(/plan\) args\+=\(--plan-only\)/)
failures << "workflow must always upload source evidence" unless workflow.match?(/Upload source snapshots, reports, and diagnostics/) && workflow.match?(/if: \$\{\{ always\(\) \}\}/) && workflow.match?(/actions\/upload-artifact@v4/)
failures << "workflow must summarize source health" unless workflow.match?(/summarize-import-health\.rb/) && workflow.match?(/GITHUB_STEP_SUMMARY/)
failures << "performance metrics must be outside the source-health report glob" if workflow.match?(/--metrics-json\s+\"?\$IMPORT_REPORT_DIR/)
failures << "workflow must upload performance metrics" unless workflow.match?(/tmp\/performance-metrics\.json/)
failures << "workflow must validate before opening the pull request" unless workflow.index("- name: Validate JSON schemas") && workflow.index("- name: Open weekly data pull request") && workflow.index("- name: Validate JSON schemas") < workflow.index("- name: Open weekly data pull request")
failures << "workflow must not allow quarantined/anomalous plans to be applied" if workflow.match?(/--allow-plan-anomalies/)

if failures.empty?
  puts "Weekly data workflow safety checks passed."
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end
