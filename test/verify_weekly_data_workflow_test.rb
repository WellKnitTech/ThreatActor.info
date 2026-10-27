# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require 'rbconfig'
require 'tempfile'
require 'timeout'

class VerifyWeeklyDataWorkflowTest < Minitest::Test
  SCRIPT = File.expand_path('../scripts/verify-weekly-data-workflow.rb', __dir__)
  WORKFLOW = File.expand_path('../.github/workflows/weekly-data.yml', __dir__)
  PIPELINE = File.expand_path('../.github/workflows/import-pipeline.yml', __dir__)

  def run_checker(contents)
    Tempfile.create(['weekly-data', '.yml']) do |file|
      file.write(contents)
      file.flush
      Timeout.timeout(3) { Open3.capture3(RbConfig.ruby, SCRIPT, file.path) }
    end
  end

  def test_current_workflow_passes
    _stdout, stderr, status = run_checker(File.read(WORKFLOW))

    assert status.success?, stderr
  end

  def test_performance_metrics_are_not_mistaken_for_a_source_health_report
    workflow = File.read(PIPELINE)

    refute_match(/--metrics-json\s+\"?\$IMPORT_REPORT_DIR/, workflow)
    assert_match(/--metrics-json\s+tmp\/performance-metrics\.json/, workflow)
    assert_match(/tmp\/performance-metrics\.json/, workflow)
  end

  def test_pipeline_does_not_retry_the_full_import_universe
    workflow = File.read(PIPELINE)

    refute_match(/while \(\( attempt <= max_attempts \)\)/, workflow)
    assert_match(/IMPORT_SOURCE_MAX_ATTEMPTS:\s*'3'/, workflow)
    assert_match(/IMPORT_SOURCE_DEADLINE_SECONDS:/, workflow)
  end

  def test_malformed_permissions_input_is_rejected_without_backtracking
    workflow = "jobs:\n  update-data:\n    runs-on: ubuntu-latest\n" + ("\t\t\n" * 10_000)

    _stdout, stderr, status = run_checker(workflow)

    refute status.success?, stderr
  end

  def test_open_pr_git_add_must_not_stage_gitignored_tmp_paths
    pipeline = File.read(PIPELINE)
    poisoned = pipeline.sub(
      /git add -- "\$\{add_paths\[@\]\}"/,
      'git add _data/actors tmp/source-delta-report.json'
    )
    refute_equal pipeline, poisoned, 'expected to locate the open-PR git add command'

    Tempfile.create(['import-pipeline', '.yml']) do |file|
      file.write(poisoned)
      file.flush
      _stdout, stderr, status = Timeout.timeout(3) do
        Open3.capture3(RbConfig.ruby, SCRIPT, file.path)
      end

      refute status.success?, stderr
      assert_match(/gitignored paths|must not stage gitignored tmp/i, stderr)
    end
  end

  def test_open_pr_step_uses_porcelain_and_mitre_collections
    pipeline = File.read(PIPELINE)

    assert_match(/git status --porcelain/, pipeline)
    %w[_campaigns _techniques _tactics _mitigations].each do |collection|
      assert_match(/#{Regexp.escape(collection)}/, pipeline[/stage_paths=\((.*?)\)/m, 1].to_s)
    end
    refute_match(/git add[^\n]*\btmp\//, pipeline)
  end

  def test_open_pr_step_soft_warns_when_actions_cannot_create_prs
    pipeline = File.read(PIPELINE)

    assert_match(/GitHub Actions is not permitted to create or approve pull requests/, pipeline)
    assert_match(/already exists/, pipeline)
    assert_match(/::warning::/, pipeline)
    assert_match(%r{https://github\.com/\$\{GITHUB_REPOSITORY\}/pull/new/\$\{branch\}}, pipeline)
    assert_match(/exit \"\$pr_create_status\"/, pipeline)
    assert_match(/gh\s+pr\s+merge\s+\"\$branch\"\s+--auto\s+--squash\s+--delete-branch/, pipeline)
  end

  def test_open_pr_step_without_create_soft_warn_is_rejected
    pipeline = File.read(PIPELINE)
    stripped = pipeline
      .gsub(/GitHub Actions is not permitted to create or approve pull requests/, 'permission denied')
      .gsub(/::warning::/, '::notice::')
      .gsub(%r{https://github\.com/\$\{GITHUB_REPOSITORY\}/pull/new/\$\{branch\}}, 'https://example.test/pr')
    refute_equal pipeline, stripped, 'expected to remove Actions PR soft-warn markers'

    Tempfile.create(['import-pipeline', '.yml']) do |file|
      file.write(stripped)
      file.flush
      _stdout, stderr, status = Timeout.timeout(3) do
        Open3.capture3(RbConfig.ruby, SCRIPT, file.path)
      end

      refute status.success?, stderr
      assert_match(/soft-warn when Actions cannot create PRs|manual compare URL/i, stderr)
    end
  end
end
