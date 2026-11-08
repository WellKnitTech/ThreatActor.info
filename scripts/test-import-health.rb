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

  def spawn_ruby(env, *args)
    clean = {
      'PATH' => ENV.fetch('PATH', ''),
      'HOME' => ENV.fetch('HOME', ''),
      'LANG' => ENV['LANG'],
      'LC_ALL' => ENV['LC_ALL'],
      'TMPDIR' => ENV['TMPDIR']
    }.merge(env).compact
    # Avoid leaking BUNDLE_* into children: under `bundle exec` that can make a
    # plain ruby script exit non-zero with empty stdout/stderr.
    Open3.capture2e(clean, RbConfig.ruby, *args)
  end

  def summarize(report_dir, health_path, diagnostics_dir, env: {})
    spawn_ruby(env, SUMMARIZE, report_dir, health_path, diagnostics_dir)
  end

  def test_command_failure_is_reported_as_failed_and_not_healthy
    Dir.mktmpdir do |dir|
      reports = File.join(dir, 'reports')
      diagnostics = File.join(dir, 'failure-diagnostics')
      FileUtils.mkdir_p(reports)
      FileUtils.mkdir_p(diagnostics)
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
      FileUtils.mkdir_p(reports)
      FileUtils.mkdir_p(diagnostics)
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
      _out, status = spawn_ruby({ 'IMPORT_REPORT_DIR' => reports, 'IMPORT_STATUS' => 'failed' },
                                EVIDENCE, output)
      assert status.success?, _out
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
      evidence_output, evidence_status = spawn_ruby(
        { 'IMPORT_REPORT_DIR' => reports, 'FAILURE_DIAGNOSTICS_DIR' => diagnostics,
          'IMPORT_STATUS' => 'failed' },
        EVIDENCE, evidence_path
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

  # Regression for weekly PR bodies that listed every source twice (plan+import)
  # plus a stray plan-anomalies.json row, and then over-counted quarantined.
  def test_duplicate_plan_import_and_ancillary_json_dedupe_to_distinct_sources
    Dir.mktmpdir do |dir|
      reports = File.join(dir, 'reports')
      diagnostics = File.join(dir, 'failure-diagnostics')
      FileUtils.mkdir_p(reports)
      FileUtils.mkdir_p(diagnostics)

      {
        'aptmap' => 'aptmap',
        'malwarebazaar' => 'malwarebazaar',
        'dragos-threat-groups' => 'Dragos Threat Groups',
        'unit42-threat-actor-groups' => 'Palo Alto Networks Unit 42 Threat Actor Groups',
        'threatfox' => 'threatfox',
        'urlhaus' => 'urlhaus',
        'wiz-cloud-threat-landscape' => 'Wiz Cloud Threat Landscape'
      }.each do |key, label|
        File.write(File.join(reports, "plan-#{key}-report.json"), JSON.generate(
          'source' => label, 'status' => 'completed', 'record_count' => 1
        ))
        File.write(File.join(reports, "import-#{key}-report.json"), JSON.generate(
          'source' => label, 'status' => 'completed', 'record_count' => 2
        ))
      end

      # Deferred IOC source reports quarantined=true on both plan and import.
      File.write(File.join(reports, 'plan-malwarebazaar-report.json'), JSON.generate(
        'source' => 'malwarebazaar', 'status' => 'quarantined', 'quarantined' => true,
        'records' => 13
      ))
      File.write(File.join(reports, 'import-malwarebazaar-report.json'), JSON.generate(
        'source' => 'malwarebazaar', 'status' => 'quarantined', 'quarantined' => true,
        'records' => 13
      ))

      # Plan-threshold quarantine replaces plan reports for these sources.
      FileUtils.rm_f(File.join(reports, 'plan-threatfox-report.json'))
      FileUtils.rm_f(File.join(reports, 'import-threatfox-report.json'))
      FileUtils.rm_f(File.join(reports, 'plan-urlhaus-report.json'))
      FileUtils.rm_f(File.join(reports, 'import-urlhaus-report.json'))
      File.write(File.join(reports, 'quarantine-threatfox-report.json'), JSON.generate(
        'source' => 'threatfox', 'status' => 'quarantined', 'quarantined' => true,
        'diagnostic' => 'match ratio 0.00 < 0.35; unmatched/new ratio 1.00 > 0.55'
      ))
      File.write(File.join(reports, 'quarantine-urlhaus-report.json'), JSON.generate(
        'source' => 'urlhaus', 'status' => 'quarantined', 'quarantined' => true,
        'diagnostic' => 'match ratio 0.00 < 0.45; unmatched/new ratio 1.00 > 0.50'
      ))

      # Quality-gate side reports must not create a second row under a short key.
      File.write(File.join(reports, 'quality-dragos-threat-groups.json'), JSON.generate(
        'source' => 'dragos', 'status' => 'accepted', 'record_count' => 26
      ))
      File.write(File.join(reports, 'quality-unit42-threat-actor-groups.json'), JSON.generate(
        'source' => 'unit42', 'status' => 'accepted', 'record_count' => 70
      ))

      # Aggregate anomaly payload is not a source health report.
      File.write(File.join(reports, 'plan-anomalies.json'), JSON.generate(
        'generated_at' => '2026-11-08T00:00:00Z',
        'checked' => 7,
        'anomalies' => [
          { 'source' => 'threatfox', 'issues' => ['match ratio 0.00 < 0.35'] },
          { 'source' => 'urlhaus', 'issues' => ['match ratio 0.00 < 0.45'] }
        ]
      ))

      output, status = summarize(reports, File.join(dir, 'health.md'), diagnostics)

      assert status.success?, output
      refute_includes output, '`anomalies.json`'
      refute_includes output, '`plan-anomalies`'
      refute_match(/\| `dragos` \|/, output)
      refute_match(/\| `unit42` \|/, output)

      source_rows = output.lines.select { |line| line.match?(/^\s*\| `[^`]+` \|/) }
      sources = source_rows.map { |line| line[/\| `([^`]+)` \|/, 1] }
      assert_equal sources, sources.uniq, "duplicate source rows:\n#{output}"

      assert_equal 1, sources.count('malwarebazaar')
      assert_equal 1, sources.count('threatfox')
      assert_equal 1, sources.count('urlhaus')
      assert_equal 1, sources.count('Dragos Threat Groups')
      assert_equal 1, sources.count('aptmap')

      assert_includes output, '**4 healthy**'
      assert_includes output, '**0 degraded**'
      assert_includes output, '**3 quarantined**'
      assert_includes output, '**0 failed**'
      assert_includes output, '`malwarebazaar` | quarantined | 13'
      assert_includes output, 'Quarantined sources are diagnostic-only'
    end
  end
end
