#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'
require_relative '../scripts/import-threatfox'

class ValidateImportPlansTest < Minitest::Test
  VALIDATOR = File.expand_path('../scripts/validate-import-plans.rb', __dir__)
  CONFIG = File.expand_path('../data/imports/plan_thresholds.yml', __dir__)

  def run_validator(reports)
    Dir.mktmpdir do |dir|
      reports.each { |name, payload| File.write(File.join(dir, "plan-#{name}-report.json"), JSON.generate(payload)) }
      Open3.capture3('ruby', VALIDATOR, '--report-dir', dir, '--config', CONFIG)
    end
  end

  def test_threatfox_rows_and_matched_actors_are_supported
    output, _error, status = run_validator('threatfox' => {
      'ioc_rows' => 10, 'matched_actors' => 8, 'unmatched' => 2
    })
    assert status.success?, output
  end

  def test_mitre_plan_counters_are_supported
    output, _error, status = run_validator('mitre-attack' => {
      'intrusion_sets' => 10, 'actors_merge' => 8, 'actors_create' => 1, 'actors_review' => 1
    })
    assert status.success?, output
  end

  def test_mitre_plan_counters_still_enforce_thresholds
    output, _error, status = run_validator('mitre-attack' => {
      'intrusion_sets' => 10, 'actors_merge' => 1, 'actors_create' => 8, 'actors_review' => 1
    })
    refute status.success?
    assert_includes output, 'match ratio'
  end

  def test_action_style_report_uses_updates_as_matches
    output, _error, status = run_validator('generic' => { 'total_candidates' => 4, 'updates' => 4, 'creates' => 0 })
    assert status.success?, output
  end

  def test_zero_canonical_counter_does_not_mask_nonzero_action
    output, _error, status = run_validator('generic' => {
      'total_candidates' => 4, 'matched' => 0, 'updates' => 4
    })
    assert status.success?, output
  end

  def test_legitimate_empty_report_is_a_no_op
    output, _error, status = run_validator('generic' => {
      'status' => 'source_empty', 'empty_reason' => 'No records published today', 'record_count' => 0
    })
    assert status.success?, output
    assert_includes output, 'no-op'
  end

  def test_zero_candidate_report_is_a_no_op
    output, _error, status = run_validator('generic' => { 'total_candidates' => 0, 'updates' => 0, 'creates' => 0 })
    assert status.success?, output
    assert_includes output, 'no-op'
  end

  def test_empty_action_list_is_a_no_op
    output, _error, status = run_validator('generic' => { 'actions' => [] })
    assert status.success?, output
    assert_includes output, 'no-op'
  end

  def test_failure_metadata_fails_closed
    output, _error, status = run_validator('generic' => { 'total_candidates' => 0, 'failed' => true })
    refute status.success?
    assert_includes output, 'failure metadata'
  end

  def test_no_auth_and_query_failure_reports_fail_closed
    %w[no_auth_key query_failed].each do |query_status|
      output, _error, status = run_validator('threatfox' => { 'query_status' => query_status, 'record_count' => 0 })
      refute status.success?
      assert_includes output, query_status
    end
  end

  def test_real_unmatched_ratio_anomaly_still_fails
    output, _error, status = run_validator('aptmap' => { 'apt_records' => 10, 'matched' => 1, 'new_candidates' => 9 })
    refute status.success?
    assert_includes output, 'unmatched/new ratio'
  end

  def test_threatfox_import_rejects_failed_query_before_reading_rows
    Dir.mktmpdir do |dir|
      snapshot = File.join(dir, 'get_iocs.json')
      File.write(snapshot, JSON.generate('query_status' => 'query_failed', 'data' => []))
      importer = ThreatFoxImporter.new([])
      importer.instance_variable_set(:@options, snapshot: snapshot, limit: nil, report_json: nil)

      error = assert_raises(RuntimeError) { importer.send(:run_plan_or_import, write: true) }
      assert_includes error.message, 'query_failed'
    end
  end
end
