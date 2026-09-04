#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'

output = ARGV.fetch(0, 'tmp/import-evidence.json')
started_at = ENV['IMPORT_STARTED_AT']
finished_at = ENV.fetch('IMPORT_FINISHED_AT', Time.now.utc.iso8601)
elapsed = started_at ? [Time.parse(finished_at) - Time.parse(started_at), 0].max.round(3) : nil
status = ENV.fetch('IMPORT_STATUS', 'unknown')
status = 'cancelled' if ENV['GITHUB_JOB_STATUS'] == 'cancelled'
safe_error = ENV['IMPORT_ERROR_CLASS'].to_s.split('::').last.to_s
safe_error = 'unknown' unless safe_error.match?(/\A[A-Za-z][A-Za-z0-9_]*\z/)
report_dir = ENV['IMPORT_REPORT_DIR']
failure_reports = report_dir ? Dir[File.join(report_dir, '*.json')].sort.filter_map do |path|
  payload = JSON.parse(File.read(path))
  payload = payload.first if payload.is_a?(Array)
  next unless payload.is_a?(Hash)
  next unless %w[failed error invalid].include?(payload['status'].to_s)

  source = payload['source'] || payload['source_key'] ||
           File.basename(path).sub(/^(?:failure-(?:fetch|plan|import)|(?:fetch|plan|import))-/, '')
           .sub(/-report\.json\z/, '')
  diagnostic = payload['diagnostic'] || payload['error'] || payload['reason']
  {
    'source' => source,
    'failure_stage' => payload['failure_stage'],
    'diagnostic' => diagnostic.to_s
  }.compact
rescue JSON::ParserError
  {
    'source' => File.basename(path).sub(/-report\.json\z/, ''),
    'diagnostic' => 'invalid JSON report'
  }
end : []
failed_sources = failure_reports.map { |failure| failure['source'] }.compact.uniq.sort
diagnostics_dir = ENV['FAILURE_DIAGNOSTICS_DIR']
if diagnostics_dir
  Dir[File.join(diagnostics_dir, '*.json')].sort.each do |path|
    begin
      payload = JSON.parse(File.read(path))
      next unless payload.is_a?(Hash) && payload['exit_code'].to_i.nonzero?

      source = payload['source'].to_s
      source = payload['requested_source'].to_s if source.empty?
      source = ENV.fetch('REQUESTED_SOURCE', '') if source.empty?
      source = 'import-run' if source.empty?
      next if failed_sources.include?(source)

      failure_reports << {
        'source' => source,
        'diagnostic' => payload['error'] || "import command exited with #{payload['exit_code']}"
      }
      failed_sources << source
    rescue JSON::ParserError
      next
    end
  end
  failed_sources = failed_sources.uniq.sort
end

evidence = {
  'schema_version' => 1,
  'requested_source' => ENV.fetch('REQUESTED_SOURCE', ''),
  'requested_phase' => ENV.fetch('REQUESTED_PHASE', 'all'),
  'source_version' => ENV.fetch('SOURCE_VERSION', ENV.fetch('GITHUB_SHA', 'unknown')),
  'cache_decision' => ENV.fetch('CACHE_DECISION', 'unknown'),
  'attempts' => Integer(ENV.fetch('IMPORT_ATTEMPTS', '0'), 10),
  'status' => status,
  'started_at' => started_at,
  'finished_at' => finished_at,
  'elapsed_seconds' => elapsed,
  'request_count' => Integer(ENV.fetch('REQUEST_COUNT', '0'), 10),
  'fallback_status' => ENV.fetch('FALLBACK_STATUS', 'not_used'),
  'error_classification' => safe_error,
  'failed_sources' => failed_sources,
  'failure_diagnostics' => failure_reports,
  'run_id' => ENV.fetch('GITHUB_RUN_ID', 'local')
}

FileUtils.mkdir_p(File.dirname(output))
File.write(output, JSON.pretty_generate(evidence) + "\n")
File.write(File.join(File.dirname(output), 'cache-manifest.json'), JSON.pretty_generate(
  'schema_version' => 1,
  'source_version' => evidence['source_version'],
  'cache_decision' => evidence['cache_decision'],
  'fallback_status' => evidence['fallback_status']
) + "\n")
File.write(File.join(File.dirname(output), 'performance-metrics.json'), JSON.pretty_generate(
  'schema_version' => 1,
  'attempts' => evidence['attempts'],
  'elapsed_seconds' => evidence['elapsed_seconds'],
  'request_count' => evidence['request_count']
) + "\n")
puts "Import evidence written to #{output}"