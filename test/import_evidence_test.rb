# frozen_string_literal: true

require 'json'
require 'open3'
require 'tmpdir'
require 'minitest/autorun'

SCRIPT = File.expand_path('../scripts/write-import-evidence.rb', __dir__)

class ImportEvidenceTest < Minitest::Test
  def run_evidence(env)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'evidence.json')
      stdout, stderr, status = Open3.capture3(env, 'ruby', SCRIPT, path)
      raise "#{stdout}\n#{stderr}" unless status.success?

      return JSON.parse(File.read(path))
    end
  end

  def test_failed_before_import_has_complete_safe_evidence
    evidence = run_evidence(
      'REQUESTED_SOURCE' => 'malpedia', 'REQUESTED_PHASE' => 'all',
      'IMPORT_STATUS' => 'failed', 'IMPORT_ATTEMPTS' => '1',
      'IMPORT_ERROR_CLASS' => 'Open3::Process::Status', 'REQUEST_COUNT' => '0'
    )

    expected = %w[requested_source requested_phase source_version cache_decision attempts status
                  started_at finished_at elapsed_seconds request_count fallback_status
                  error_classification run_id schema_version]
    assert_equal expected.sort, evidence.keys.sort
    assert_equal 'failed', evidence['status']
    assert_equal 'Status', evidence['error_classification']
    refute evidence.to_s.match?(/secret|payload|token/i)
  end

  def test_timeout_and_cancellation_are_distinguishable
    timeout = run_evidence('IMPORT_STATUS' => 'timeout', 'IMPORT_ATTEMPTS' => '3')
    cancelled = run_evidence('IMPORT_STATUS' => 'failed', 'GITHUB_JOB_STATUS' => 'cancelled')

    assert_equal 'timeout', timeout['status']
    assert_equal 'cancelled', cancelled['status']
  end
end