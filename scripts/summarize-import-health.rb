#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'fileutils'

report_dir = ARGV.fetch(0, 'tmp/import-reports')
output_path = ARGV.fetch(1, 'tmp/import-health.md')
diagnostics_dir = ARGV.fetch(2, File.join(File.dirname(report_dir), 'failure-diagnostics'))

def report_source(filename, payload)
  payload['source'] || payload['source_key'] ||
    filename.sub(/^(?:failure-(?:fetch|plan|import)|(?:fetch|plan|import))-/, '')
           .sub(/-report\.json\z/, '')
end

def report_status(filename, payload)
  explicit = payload['status'].to_s
  return explicit unless explicit.empty?
  return 'failed' if filename.start_with?('failure-') ||
                     payload['error'] || payload['reason'] || payload['failure_stage']

  payload['quarantined'] ? 'quarantined' : 'completed'
end

reports = Dir[File.join(report_dir, '*.json')].sort.map do |path|
  begin
    payload = JSON.parse(File.read(path))
    payload = payload.first if payload.is_a?(Array)
    raise JSON::ParserError, 'report is not a JSON object' unless payload.is_a?(Hash)
    [File.basename(path), payload]
  rescue JSON::ParserError => e
    [File.basename(path), { 'status' => 'invalid', 'error' => e.message }]
  end
end

# The runner writes this diagnostic even when it fails before a source adapter
# can emit its normal report. Treat a non-zero command exit as a source failure;
# otherwise the empty report set is misleadingly healthy.
Dir[File.join(diagnostics_dir, '*.json')].sort.each do |path|
  begin
    payload = JSON.parse(File.read(path))
    next unless payload.is_a?(Hash) && payload['exit_code'].to_i.nonzero?

    source = payload['source'].to_s
    source = payload['requested_source'].to_s if source.empty?
    source = 'import-run' if source.empty?
    next if reports.any? { |_filename, report| report_source('', report) == source }

    reports << [File.basename(path), payload.merge(
      'source' => source,
      'status' => 'failed',
      'diagnostic' => payload['error'] || "import command exited with #{payload['exit_code']}"
    )]
  rescue JSON::ParserError
    # The invalid diagnostic is still represented by the importer report when
    # available; do not turn an ancillary artifact into a second failure row.
    next
  end
end

rows = reports.map do |filename, payload|
  source = report_source(filename, payload)
  status = report_status(filename, payload)
  count = payload['record_count'] || payload['records'] || payload['count'] || '-'
  diagnostic = payload['diagnostic'] || payload['error'] || payload['reason'] || ''
  escaped_diagnostic = diagnostic.to_s.gsub('\\', '\\\\').gsub('|', '\\|').gsub(/\s+/, ' ').strip
  "| `#{source}` | #{status} | #{count} | #{escaped_diagnostic} |"
end

quarantined = reports.count { |filename, payload| payload['quarantined'] == true || report_status(filename, payload) == 'quarantined' }
degraded = reports.count { |_filename, payload| payload['status'].to_s == 'stale_fallback' }
failed = reports.count { |filename, payload| %w[failed error invalid].include?(report_status(filename, payload)) }
healthy = reports.length - quarantined - failed - degraded

body = <<~MARKDOWN
  ## Automated source health

  | Source | Status | Records | Diagnostic |
  | --- | --- | ---: | --- |
  #{rows.empty? ? '| _No reports produced_ | - | - | Check the workflow diagnostics artifact. |' : rows.join("\n  ")}

  Summary: **#{healthy} healthy**, **#{degraded} degraded**, **#{quarantined} quarantined**, **#{failed} failed**.

  Quarantined sources are diagnostic-only and are not applied automatically. A failed
  workflow remains failed; a stale fallback is applied with degraded health and visible provenance.
MARKDOWN

FileUtils.mkdir_p(File.dirname(output_path))
File.write(output_path, body)
puts body
exit 1 if failed.positive? && ENV['FAIL_ON_SOURCE_FAILURE'] == '1'
