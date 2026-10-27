# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'

class PlanAnomalyQuarantineTest < Minitest::Test
  VALIDATOR = File.expand_path('../scripts/validate-import-plans.rb', __dir__)
  CONFIG = File.expand_path('../data/imports/plan_thresholds.yml', __dir__)
  RUNNER = File.expand_path('../scripts/import-automated-sources.rb', __dir__)

  def test_validator_writes_anomalies_and_allow_continues
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'plan-aptmap-report.json'), JSON.generate(
        'apt_records' => 10, 'matched' => 1, 'new_candidates' => 9
      ))
      File.write(File.join(dir, 'plan-healthy-report.json'), JSON.generate(
        'total_candidates' => 4, 'updates' => 4, 'creates' => 0
      ))
      anomalies = File.join(dir, 'anomalies.json')
      output, _error, status = Open3.capture3(
        'ruby', VALIDATOR,
        '--report-dir', dir,
        '--config', CONFIG,
        '--anomalies-json', anomalies,
        '--allow-anomalies'
      )
      assert status.success?, output
      payload = JSON.parse(File.read(anomalies))
      sources = payload.fetch('anomalies').map { |item| item['source'] }
      assert_includes sources, 'aptmap'
      refute_includes sources, 'healthy'
    end
  end

  def test_runner_quarantines_anomalies_helper_is_present
    source = File.read(RUNNER)
    assert_includes source, 'def quarantine_plan_anomalies!'
    assert_includes source, 'write_quarantine_report'
    assert_includes source, '--anomalies-json'
    assert_match(/command << '--allow-anomalies'/, source)
  end
end
