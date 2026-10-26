# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'
require 'rbconfig'

class ImportHealthTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  SUMMARIZE = File.join(ROOT, 'scripts/summarize-import-health.rb')
  EVIDENCE = File.join(ROOT, 'scripts/write-import-evidence.rb')

  def summarize(report_dir, health_path, diagnostics_dir, env: {})
    merged = ENV.to_h.merge(env)
    Open3.capture2e(merged,
                    RbConfig.ruby, SUMMARIZE,
                    report_dir, health_path, diagnostics_dir)
  end

  def test_command_failure_is_reported_as_failed_and_not_healthy
    Dir.mktmpdir do |dir|
      reports = File.join(dir, 'reports')
      diagnostics = File.join(dir, 'failure-diagnostics')
      FileUtils.mkdir_p([reports, diagnostics])
      File.write(File.join(reports, 'failure-fetch-urlhaus-report.json'), JSON.pretty_generate(
        'source' => 'urlhaus', 'status' => 'failed', 'failure_stage' => 'fetch',
        'error' => 'HTTP 401', 'diagnostic' => 'abuse.ch URLhaus: HTTP 401'
      ))
      output, status = summarize(reports, File.join(dir, 'health.md'), diagnostics,
                                 env: { 'FAIL_ON_SOURCE_FAILURE' => '1' })

      refute status.success?, output
      assert_includes output, '`urlhaus` | failed'
      assert_includes output, '0 healthy'
      assert_includes output, '1 failed'
      assert_includes File.read(File.join(dir, 'health.md')), 'HTTP 401'
    end
  end

  def test_degraded_enrichment_does_not_fail_health_summary
    Dir.mktmpdir do |dir|
      reports = File.join(dir, 'reports')
      diagnostics = File.join(dir, 'failure-diagnostics')
      FileUtils.mkdir_p([reports, diagnostics])
      File.write(File.join(reports, 'degraded-malpedia-report.json'), JSON.pretty_generate(
        'source' => 'malpedia', 'status' => 'degraded',
        'error' => 'source deadline exceeded', 'diagnostic' => 'source deadline exceeded'
      ))
      File.write(File.join(reports, 'plan-mitre-attack-report.json'), JSON.pretty_generate(
        'source' => 'mitre-attack', 'status' => 'completed', 'record_count' => 10
      ))
      output, status = summarize(reports, File.join(dir, 'health.md'), diagnostics,
                                 env: { 'FAIL_ON_SOURCE_FAILURE' => '1' })

      assert status.success?, output
      assert_includes output, '`malpedia` | degraded'
      assert_includes output, '**1 healthy**'
      assert_includes output, '**1 degraded**'
      assert_includes output, '**0 failed**'
    end
  end

  def test_standardized_evidence_names_failed_sources
    Dir.mktmpdir do |dir|
      reports = File.join(dir, 'reports')
      FileUtils.mkdir_p(reports)
      File.write(File.join(reports, 'failure-urlhaus-report.json'), JSON.generate('source' => 'urlhaus', 'status' => 'failed'))
      output = File.join(dir, 'evidence.json')
      system(ENV.to_h.merge('IMPORT_REPORT_DIR' => reports, 'IMPORT_STATUS' => 'failed'),
             RbConfig.ruby, EVIDENCE, output)
      assert_equal ['urlhaus'], JSON.parse(File.read(output)).fetch('failed_sources')
    end
  end

  def test_command_failure_diagnostic_is_reported_by_health_and_evidence
    Dir.mktmpdir do |dir|
      reports = File.join(dir, 'reports')
      diagnostics = File.join(dir, 'failure-diagnostics')
      FileUtils.mkdir_p(diagnostics)
      diagnostic = {
        'phase' => 'fetch',
        'source' => '',
        'retry_scope' => 'per-source',
        'attempts' => 1,
        'exit_code' => '1'
      }
      File.write(File.join(diagnostics, 'import-run.json'), JSON.pretty_generate(diagnostic))

      FileUtils.mkdir_p(reports)
      %w[urlhaus threatfox].each do |source|
        File.write(File.join(reports, "#{source}-report.json"), JSON.generate(
          'source' => source, 'status' => 'completed', 'record_count' => 1
        ))
      end

      health_output, health_status = summarize(reports, File.join(dir, 'health.md'), diagnostics,
                                               env: { 'FAIL_ON_SOURCE_FAILURE' => '1' })

      refute health_status.success?, health_output
      assert_includes health_output, '`import-run` | failed'
      assert_includes health_output, 'import command exited with 1'
      assert_includes health_output, '2 healthy'
      assert_includes health_output, '1 failed'

      evidence_path = File.join(dir, 'evidence.json')
      evidence_output, evidence_status = Open3.capture2e(
        ENV.to_h.merge('IMPORT_REPORT_DIR' => reports, 'FAILURE_DIAGNOSTICS_DIR' => diagnostics,
                       'IMPORT_STATUS' => 'failed'),
        RbConfig.ruby, EVIDENCE, evidence_path
      )

      assert evidence_status.success?, evidence_output
      evidence = JSON.parse(File.read(evidence_path))
      assert_equal ['import-run'], evidence.fetch('failed_sources')
      assert_equal [{
        'source' => 'import-run',
        'diagnostic' => 'import command exited with 1'
      }], evidence.fetch('failure_diagnostics')
    end
  end

  def test_canonical_pipeline_keeps_health_and_evidence_on_failure
    workflow = File.read(File.join(ROOT, '.github/workflows/import-pipeline.yml'))

    assert_includes workflow, "FAIL_ON_SOURCE_FAILURE: '1'"
    assert_includes workflow, 'if: ${{ always() }}'
    assert_includes workflow, 'ruby scripts/summarize-import-health.rb "$IMPORT_REPORT_DIR" tmp/import-health.md "$FAILURE_DIAGNOSTICS_DIR"'
    assert_includes workflow, 'ruby scripts/write-import-evidence.rb tmp/import-evidence.json'
    assert_includes workflow, '${{ env.FAILURE_DIAGNOSTICS_DIR }}/**'
    assert_includes workflow, 'tmp/import-evidence.json'
    assert_includes workflow, 'FAILED_SOURCE="$REQUESTED_SOURCE"'
    assert_includes workflow, 'FAILED_SOURCE=$(ruby -e'
    assert_includes workflow, 'log.scan'
  end
end
