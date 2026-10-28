#!/usr/bin/env ruby

# Failure-mode test for the scheduled data workflow. This intentionally checks
# the rendered workflow text so a future edit cannot quietly restore an admin
# merge, hide source failures, or omit run evidence.

require 'open3'

workflow_path = ARGV.fetch(0) { File.expand_path("../.github/workflows/weekly-data.yml", __dir__) }
repo_root = File.expand_path('..', __dir__)
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

  granted = job_lines[(permissions_start + 1)..]&.take_while { |line| line.match?(/\A      \S/) } || []
  required = [
    "      contents: write\n",
    "      pull-requests: write\n",
    "      actions: write\n"
  ]
  required.all? { |line| granted.include?(line) }
end

# Extract concrete path arguments from `git add` / `git add --` in the open-PR
# step. Ignores shell arrays/variables so temporary fixture workflows still work.
def git_add_paths(pipeline_text)
  open_pr = pipeline_text[%r{- name: Open weekly data pull request\n.*?(?=\n      - name: |\z)}m]
  return [] unless open_pr

  paths = []
  open_pr.scan(/^\s*git add(?:\s+--)?\s+(.+)$/) do |args|
    args[0].split(/\s+/).each do |token|
      next if token.empty? || token.start_with?('$', '"$', "'$")
      next if token.include?('${') || token.include?('"') || token.include?("'")
      paths << token
    end
  end
  paths.uniq
end

def gitignored_paths(repo_root, paths)
  return [] if paths.empty?

  ignored = []
  paths.each do |path|
    _stdout, _stderr, status = Open3.capture3(
      'git', '-C', repo_root, 'check-ignore', '-q', '--', path
    )
    ignored << path if status.success?
  end
  ignored
end

combined = "#{workflow}\n#{pipeline}"
failures << "workflow must not contain an admin merge bypass" if combined.match?(/gh\s+pr\s+merge[^\n]*--admin\b/)
failures << "workflow must queue a normal protected auto-merge" unless combined.match?(/gh\s+pr\s+merge\s+\"\$branch\"\s+--auto\s+--squash\s+--delete-branch/)
failures << "workflow default permissions must be read-only for repository contents" unless workflow.match?(/^permissions:\s*\n\s+contents:\s+read\s*$/)
failures << "write permissions must be scoped to the update-data job" unless update_data_job_has_write_permissions?(workflow)
failures << "update-data job must grant actions: write for post-merge workflow dispatch" unless workflow.match?(/actions:\s*write/) && pipeline.match?(/actions:\s*write/)
failures << "open-PR step must wait for PR checks before enabling auto-merge" unless pipeline.match?(/Waiting for pull request checks to register/) &&
                                                                                    pipeline.match?(/gh\s+pr\s+checks/) &&
                                                                                    pipeline.index("Waiting for pull request checks to register") < pipeline.index('gh pr merge "$branch" --auto --squash --delete-branch')
failures << "open-PR step must dispatch Pages after a GITHUB_TOKEN merge" unless pipeline.match?(/gh\s+workflow\s+run\s+\"Deploy GitHub Pages\"\s+--ref\s+main/)
failures << "open-PR step must dispatch Content Validation after a GITHUB_TOKEN merge" unless pipeline.match?(/gh\s+workflow\s+run\s+\"Content Validation\"\s+--ref\s+main/)
failures << "open-PR step must only dispatch post-merge workflows for github-actions merges" unless pipeline.match?(/github-actions\[bot\]/) &&
                                                                                                  pipeline.match?(/mergedBy\.login/)
failures << "pages.yml must support workflow_dispatch for manual and post-merge deploys" unless File.read(File.expand_path('../.github/workflows/pages.yml', __dir__)).match?(/workflow_dispatch:/)
failures << "validate.yml must support workflow_dispatch for manual and post-merge runs" unless File.read(File.expand_path('../.github/workflows/validate.yml', __dir__)).match?(/workflow_dispatch:/)
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
failures << "workflow must write standardized evidence before upload" unless pipeline.match?(/Write standardized import evidence/) && pipeline.match?(/write-import-evidence\.rb tmp\/import-evidence\.json/) && pipeline.match?(/job\.status == 'failure'/) && pipeline.match?(/tmp\/(?:cache-manifest|performance-metrics)\.json/)
failures << "workflow artifacts must fail when required evidence is absent" unless pipeline.match?(/if-no-files-found: error/) && pipeline.match?(/retention-days: 90/)
failures << "workflow must validate before opening the pull request" unless pipeline.index("- name: Validate JSON schemas") && pipeline.index("- name: Open weekly data pull request") && pipeline.index("- name: Validate JSON schemas") < pipeline.index("- name: Open weekly data pull request")
failures << "open-PR step must detect untracked changes with git status --porcelain" unless pipeline.match?(/git status --porcelain/)
failures << "open-PR step must not stage gitignored tmp/ reports" if pipeline.match?(/git add[^\n]*\btmp\//)
failures << "open-PR step must soft-warn when Actions cannot create PRs" unless pipeline.match?(/GitHub Actions is not permitted to create or approve pull requests/) &&
                                                                              pipeline.match?(/already exists/) &&
                                                                              pipeline.match?(/::warning::/)
failures << "open-PR step must include a manual compare URL when PR create is blocked" unless pipeline.match?(%r{https://github\.com/\$\{GITHUB_REPOSITORY\}/pull/new/\$\{branch\}})
failures << "open-PR step must still fail on unexpected gh pr create errors" unless pipeline.match?(/exit \"\$pr_create_status\"/) ||
                                                                                   pipeline.match?(/exit "\$pr_create_status"/)
# Scheduled path must quarantine anomalous plans by default. A manual
# workflow_dispatch may opt into --allow-plan-anomalies only when gated by the
# allow_anomalies input; never pass the flag unconditionally in default args.
unconditional_allow = pipeline.match?(/args=\(.*--allow-plan-anomalies/) &&
                      !pipeline.match?(/ALLOW_PLAN_ANOMALIES/)
failures << "workflow must not unconditionally apply anomalous plans" if unconditional_allow
failures << "workflow allow_anomalies input must gate --allow-plan-anomalies" if pipeline.match?(/--allow-plan-anomalies/) &&
                                                                              !pipeline.match?(/ALLOW_PLAN_ANOMALIES/) &&
                                                                              !workflow.match?(/allow_anomalies:/)

add_paths = git_add_paths(pipeline)
# stage_paths array is the source of truth when git add uses a shell variable.
if add_paths.empty? && pipeline.match?(/stage_paths=\(/)
  array_block = pipeline[/stage_paths=\((.*?)\)/m, 1].to_s
  add_paths = array_block.scan(/^\s*([A-Za-z0-9_\/.\-]+)\s*$/).flatten
end
ignored_add_paths = gitignored_paths(repo_root, add_paths)
unless ignored_add_paths.empty?
  failures << "open-PR git add must not reference gitignored paths: #{ignored_add_paths.join(', ')}"
end
%w[_campaigns _techniques _tactics _mitigations].each do |collection|
  unless add_paths.include?(collection) || pipeline.match?(/stage_paths=\([\s\S]*?\b#{Regexp.escape(collection)}\b/)
    failures << "open-PR staging must include regenerated MITRE collection #{collection}"
  end
end

if failures.empty?
  puts "Weekly data workflow safety checks passed."
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end
