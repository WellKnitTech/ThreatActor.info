# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'

class ValidateImportPlansTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  VALIDATOR = File.join(ROOT, 'scripts', 'validate-import-plans.rb')
  CONFIG = File.join(ROOT, 'data', 'imports', 'plan_thresholds.yml')

  def run_validator(reports)
    Dir.mktmpdir('plan-reports') do |dir|
      reports.each do |name, payload|
        File.write(File.join(dir, "plan-#{name}-report.json"), JSON.generate(payload))
      end
      Open3.capture3('ruby', VALIDATOR, '--report-dir', dir, '--config', CONFIG)
    end
  end

  def run_raw_validator(files)
    Dir.mktmpdir('plan-reports') do |dir|
      files.each { |name, content| File.write(File.join(dir, "plan-#{name}-report.json"), content) }
      Open3.capture3('ruby', VALIDATOR, '--report-dir', dir, '--config', CONFIG)
    end
  end

  def test_ransomlook_evaluation_array_is_normalized_without_actor_thresholds
    stdout, stderr, status = run_validator(
      'ransomlook' => [
        { 'action' => 'create' },
        { 'action' => 'review' },
        { 'action' => 'update' },
        { 'action' => 'skip' }
      ]
    )

    assert status.success?, "expected success, got #{status.exitstatus}: #{stdout}\n#{stderr}"
    refute_includes stdout, 'non-summary reports skipped'
  end

  def test_empty_ransomlook_evaluation_array_is_a_legitimate_zero_record_result
    stdout, stderr, status = run_validator('ransomlook' => [])

    assert status.success?, "expected success, got #{status.exitstatus}: #{stdout}\n#{stderr}"
  end

  def test_explicitly_empty_source_passes_without_fake_match_ratio
    stdout, stderr, status = run_validator(
      'dragos' => {
        'source' => 'dragos',
        'status' => 'source_empty',
        'empty_reason' => 'upstream catalog contains no threat-group profiles'
      }
    )

    assert status.success?, "expected success, got #{status.exitstatus}: #{stdout}\n#{stderr}"
  end

  def test_zero_match_report_with_records_still_fails_closed
    stdout, _stderr, status = run_validator(
      'unit42' => {
        'source' => 'unit42',
        'total_records' => 4,
        'matched' => 0,
        'new_candidates' => 4
      }
    )

    refute status.success?
    assert_includes stdout, 'match ratio'
  end

  def test_non_ransomlook_array_is_rejected_instead_of_bypassing_thresholds
    stdout, _stderr, status = run_validator('unit42' => [{ 'action' => 'create' }])

    refute status.success?
    assert_includes stdout, 'RansomLook evaluation array'
  end

  def test_quarantine_status_is_not_treated_as_a_success
    stdout, _stderr, status = run_validator(
      'unit42' => { 'source' => 'unit42', 'status' => 'quarantine', 'matched' => 10, 'total_records' => 10 }
    )

    refute status.success?
    assert_includes stdout, 'failure status'
  end

  def test_source_empty_without_reason_is_rejected
    stdout, _stderr, status = run_validator('ransomlook' => { 'source' => 'ransomlook', 'status' => 'source_empty' })

    refute status.success?
    assert_includes stdout, 'empty_reason'
  end

  def test_source_empty_reason_must_be_a_non_empty_string
    stdout, _stderr, status = run_validator(
      'dragos' => { 'source' => 'dragos', 'status' => 'source_empty', 'empty_reason' => [] }
    )

    refute status.success?
    assert_includes stdout, 'non-empty string empty_reason'
  end

  def test_source_failure_status_is_not_treated_as_an_empty_success
    stdout, stderr, status = run_validator(
      'ransomlook' => {
        'source' => 'ransomlook',
        'status' => 'retryable_error',
        'error' => 'upstream unavailable'
      }
    )

    refute status.success?
    assert_includes stdout, 'failure status'
    assert_includes stderr, 'Threshold violations found'
  end

  def test_malformed_evaluation_array_is_rejected_not_skipped
    stdout, stderr, status = run_validator('ransomlook' => [{ 'action' => 'unexpected' }])

    refute status.success?
    assert_includes stdout, 'unknown action'
    assert_includes stderr, 'Threshold violations found'
  end

  def test_malformed_candidate_is_rejected_with_source_diagnostic
    stdout, _stderr, status = run_validator(
      'unit42' => { 'source' => 'unit42', 'total_records' => 1, 'matched' => 1, 'candidates' => ['bad'] }
    )

    refute status.success?
    assert_includes stdout, 'candidates must be an array of objects'
  end

  def test_malformed_json_is_rejected_with_source_diagnostic
    stdout, _stderr, status = run_raw_validator('unit42' => '{"source":"unit42",')

    refute status.success?
    assert_includes stdout, 'unit42'
    assert_includes stdout, 'malformed JSON'
  end

  def test_no_auth_key_status_is_not_treated_as_success
    stdout, _stderr, status = run_validator(
      'threatfox' => { 'source' => 'threatfox', 'status' => 'no_auth_key' }
    )

    refute status.success?
    assert_includes stdout, 'failure status'
  end
end
