#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'

class ValidateImportPlansTest < Minitest::Test
  VALIDATOR = File.expand_path('../scripts/validate-import-plans.rb', __dir__)
  CONFIG = File.expand_path('../data/imports/plan_thresholds.yml', __dir__)

  def run_validator(reports)
    Dir.mktmpdir do |dir|
      reports.each { |name, payload| File.write(File.join(dir, "plan-#{name}-report.json"), JSON.generate(payload)) }
      Open3.capture3('ruby', VALIDATOR, '--report-dir', dir, '--config', CONFIG)
    end
  end

  def test_action_style_report_uses_updates_as_matches
    output, _error, status = run_validator('generic' => { 'total_candidates' => 4, 'updates' => 4, 'creates' => 0 })
    assert status.success?, output
  end

  def test_zero_candidate_report_is_a_no_op
    output, _error, status = run_validator('generic' => { 'total_candidates' => 0, 'updates' => 0, 'creates' => 0 })
    assert status.success?, output
  end

  def test_no_auth_report_fails_closed
    output, _error, status = run_validator('threatfox' => { 'query_status' => 'no_auth_key', 'record_count' => 0 })
    refute status.success?
    assert_includes output, 'no_auth_key'
  end

  def test_threatfox_report_uses_actual_ioc_counters
    output, _error, status = run_validator('threatfox' => {
      'query_status' => 'ok', 'ioc_rows' => 4, 'matched_actors' => 4, 'unmatched' => 0
    })
    assert status.success?, output
  end

  def test_explicit_failure_flag_fails_closed
    output, _error, status = run_validator('generic' => { 'available' => false, 'record_count' => 0 })
    refute status.success?
    assert_includes output, 'failure status'
  end

  def test_real_unmatched_ratio_anomaly_still_fails
    output, _error, status = run_validator('aptmap' => { 'apt_records' => 10, 'matched' => 1, 'new_candidates' => 9 })
    refute status.success?
    assert_includes output, 'unmatched/new ratio'
  end
end
