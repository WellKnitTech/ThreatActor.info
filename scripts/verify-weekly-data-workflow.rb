#!/usr/bin/env ruby

# Failure-mode test for the scheduled data workflow. This intentionally checks
# the rendered workflow text so a future edit cannot quietly restore an admin
# merge, hide source failures, or omit run evidence.

workflow_path = ARGV.fetch(0) { File.expand_path("../.github/workflows/weekly-data.yml", __dir__) }
workflow = File.read(workflow_path)
pipeline_path = if File.basename(workflow_path).start_with?('weekly-data')
                  File.expand_path('../.github/workflows/import-pipeline.yml', __dir__)
                else
                  workflow_path
                end
pipeline = File.exist?(pipeline_path) ? File.read(pipeline_path) : workflow
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

combined = "#{workflow}\n#{pipeline}"
failures << "workflow must not contain an admin merge bypass" if combined.match?(/gh\s+pr\s+merge[^\n]*--admin\b/)
failures << "workflow must queue a normal protected auto-merge" unless combined.match?(/gh\s+pr\s+merge\s+\"\$branch\"\s+--auto\s+--squash\s+--delete-branch/)
failures << "workflow default permissions must be read-only for repository contents" unless workflow.match?(/^permissions:\s*\n\s+contents:\s+read\s*$/)
failures << "write permissions must be scoped to the update-data job" unless update_data_job_has_write_permissions?(workflow)
failures << "workflow must not use continue-on-error to hide source failures" if workflow.match?(/continue-on-error/)
failures << "workflow must not retry the full import universe" if pipeline.match?(/while \(\( attempt <= max_attempts \)\)/)
failures << "workflow must bound per-source retries" unless pipeline.match?(/IMPORT_SOURCE_MAX_ATTEMPTS:\s*'3'/) && pipeline.match?(/IMPORT_SOURCE_DEADLINE_SECONDS:/)
failures << "canonical job must keep an explicit timeout" unless pipeline.match?(/timeout-minutes:\s*45/)
failures << "workflow must expose source-level manual reruns" unless workflow.match?(/inputs:\s*\n\s+source:/) && pipeline.match?(/--source \"\$REQUESTED_SOURCE\"/)
failures << "workflow must expose phase-level manual reruns" unless workflow.match?(/phase:/) && pipeline.match?(/fetch\) args\+=\(--fetch-only\)/) && pipeline.match?(/plan\) args\+=\(--plan-only\)/)
failures << "workflow must always upload source evidence" unless pipeline.match?(/Upload source snapshots, reports, and diagnostics/) && pipeline.match?(/if: \$\{\{ always\(\) \}\}/) && pipeline.match?(/actions\/upload-artifact@v4/)
failures << "workflow must summarize source health" unless pipeline.match?(/summarize-import-health\.rb/) && pipeline.match?(/GITHUB_STEP_SUMMARY/)
failures << "performance metrics must be outside the source-health report glob" if pipeline.match?(/--metrics-json\s+\"?\$IMPORT_REPORT_DIR/)
failures << "workflow must upload performance metrics" unless pipeline.match?(/tmp\/performance-metrics\.json/)
failures << "workflow must validate before opening the pull request" unless pipeline.index("- name: Validate JSON schemas") && pipeline.index("- name: Open weekly data pull request") && pipeline.index("- name: Validate JSON schemas") < pipeline.index("- name: Open weekly data pull request")
failures << "workflow must not allow quarantined/anomalous plans to be applied" if combined.match?(/--allow-plan-anomalies/)

if failures.empty?
  puts "Weekly data workflow safety checks passed."
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end
