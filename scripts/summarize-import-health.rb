#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'fileutils'

report_dir = ARGV.fetch(0, 'tmp/import-reports')
output_path = ARGV.fetch(1, 'tmp/import-health.md')
diagnostics_dir = ARGV.fetch(2, File.join(File.dirname(report_dir), 'failure-diagnostics'))

# Ancillary JSON that lives beside per-source reports but is not itself a source
# health record (aggregate plan-threshold output, metrics, etc.).
NON_SOURCE_BASENAMES = %w[
  plan-anomalies.json
  anomalies.json
  performance-metrics.json
].freeze

# Filename shapes written by the import runner / quality gate / failure helpers.
SOURCE_REPORT_BASENAME = /
  \A
  (?:
    quality-.+
    |
    (?:failure-(?:fetch|plan|import)|failure|degraded|quarantine|import|plan|fetch)-.+-report
    |
    .+?-report
  )
  \.json
  \z
/x

REPORT_PRIORITY = {
  'quarantine' => 100,
  'failure' => 90,
  'degraded' => 80,
  'import' => 70,
  'bare' => 60,
  'plan' => 50,
  'quality' => 20
}.freeze

STATUS_PRIORITY = {
  'failed' => 100,
  'error' => 100,
  'invalid' => 100,
  'quarantined' => 90,
  'degraded' => 80,
  'stale_fallback' => 80,
  'accepted' => 40,
  'completed' => 30,
  'ok' => 30,
  'partial' => 20
}.freeze

def source_report_file?(filename)
  return false if NON_SOURCE_BASENAMES.include?(filename)

  filename.match?(SOURCE_REPORT_BASENAME)
end

def report_kind(filename)
  case filename
  when /\Aquarantine-/ then 'quarantine'
  when /\Afailure-/ then 'failure'
  when /\Adegraded-/ then 'degraded'
  when /\Aimport-/ then 'import'
  when /\Aplan-/ then 'plan'
  when /\Aquality-/ then 'quality'
  when /\Afetch-/ then 'bare'
  else 'bare'
  end
end

def source_key_from_filename(filename)
  name = filename.sub(/\.json\z/, '')
  name = name.sub(/-report\z/, '')
  name.sub(/\A(?:failure-(?:fetch|plan|import)|failure|degraded|quarantine|import|plan|quality|fetch)-/, '')
end

def report_source(filename, payload)
  explicit = payload['source'] || payload['source_key']
  return explicit unless explicit.to_s.strip.empty?

  source_key_from_filename(filename)
end

def dedupe_key(filename, payload)
  # Prefer the stable key encoded in the report filename so plan/import/quality
  # artifacts for the same importer collapse even when payloads use a display
  # label (e.g. "Dragos Threat Groups") or a short quality-gate key ("dragos").
  key = source_key_from_filename(filename)
  return key unless key.empty?

  report_source(filename, payload).to_s
end

def report_status(filename, payload)
  explicit = payload['status'].to_s
  return explicit unless explicit.empty?
  return 'failed' if filename.start_with?('failure-') ||
                     payload['error'] || payload['reason'] || payload['failure_stage']

  payload['quarantined'] ? 'quarantined' : 'completed'
end

def better_report?(candidate_filename, candidate_payload, existing_filename, existing_payload)
  cand_kind = REPORT_PRIORITY.fetch(report_kind(candidate_filename), 0)
  exist_kind = REPORT_PRIORITY.fetch(report_kind(existing_filename), 0)
  return true if cand_kind > exist_kind
  return false if cand_kind < exist_kind

  cand_status = STATUS_PRIORITY.fetch(report_status(candidate_filename, candidate_payload), 0)
  exist_status = STATUS_PRIORITY.fetch(report_status(existing_filename, existing_payload), 0)
  return true if cand_status > exist_status
  return false if cand_status < exist_status

  # Stable tie-break: prefer the lexicographically greater basename so the
  # choice does not depend on Dir glob order.
  candidate_filename > existing_filename
end

raw_reports = Dir[File.join(report_dir, '*.json')].sort.filter_map do |path|
  filename = File.basename(path)
  next unless source_report_file?(filename)

  begin
    payload = JSON.parse(File.read(path))
    payload = payload.first if payload.is_a?(Array)
    raise JSON::ParserError, 'report is not a JSON object' unless payload.is_a?(Hash)
    [filename, payload]
  rescue JSON::ParserError => e
    [filename, { 'status' => 'invalid', 'error' => e.message }]
  end
end

# Keep one row per distinct source. Prefer quarantine/failure/import outcomes
# over plan snapshots and quality-gate side reports.
reports_by_source = {}
raw_reports.each do |filename, payload|
  key = dedupe_key(filename, payload)
  next if key.empty?

  existing = reports_by_source[key]
  if existing.nil? || better_report?(filename, payload, existing[0], existing[1])
    reports_by_source[key] = [filename, payload]
  end
end

# The runner writes this diagnostic even when it fails before a source adapter
# can emit its normal report. Treat a non-zero command exit as a source failure;
# otherwise the empty report set is misleadingly healthy. When a successful plan
# report already exists for the same source key, upgrade that row to failed
# rather than skipping the diagnostic (plan succeeded + import aborted).
Dir[File.join(diagnostics_dir, '*.json')].sort.each do |path|
  begin
    payload = JSON.parse(File.read(path))
    next unless payload.is_a?(Hash) && payload['exit_code'].to_i.nonzero?

    source = payload['source'].to_s
    source = payload['requested_source'].to_s if source.empty?
    source = 'import-run' if source.empty?
    filename = File.basename(path)
    failure_payload = payload.merge(
      'source' => source,
      'status' => 'failed',
      'diagnostic' => payload['error'] || "import command exited with #{payload['exit_code']}"
    )
    entry = [filename, failure_payload]

    existing_key = if reports_by_source.key?(source)
                     source
                   else
                     reports_by_source.keys.find do |key|
                       report_source(*reports_by_source[key]) == source
                     end
                   end

    if existing_key
      existing = reports_by_source[existing_key]
      next unless better_report?(filename, failure_payload, existing[0], existing[1])

      reports_by_source.delete(existing_key)
      reports_by_source[source] = entry
    else
      reports_by_source[source] = entry
    end
  rescue JSON::ParserError
    # The invalid diagnostic is still represented by the importer report when
    # available; do not turn an ancillary artifact into a second failure row.
    next
  end
end

reports = reports_by_source.values.sort_by { |filename, payload| report_source(filename, payload).to_s.downcase }

rows = reports.map do |filename, payload|
  source = report_source(filename, payload)
  status = report_status(filename, payload)
  count = payload['record_count'] || payload['records'] || payload['count'] || '-'
  diagnostic = payload['diagnostic'] || payload['error'] || payload['reason'] || ''
  escaped_diagnostic = diagnostic.to_s.gsub('\\', '\\\\').gsub('|', '\\|').gsub(/\s+/, ' ').strip
  "| `#{source}` | #{status} | #{count} | #{escaped_diagnostic} |"
end

quarantined = reports.count { |filename, payload| payload['quarantined'] == true || report_status(filename, payload) == 'quarantined' }
degraded = reports.count do |filename, payload|
  %w[stale_fallback degraded].include?(payload['status'].to_s) ||
    report_status(filename, payload) == 'degraded'
end
failed = reports.count { |filename, payload| %w[failed error invalid].include?(report_status(filename, payload)) }
healthy = reports.length - quarantined - failed - degraded

body = <<~MARKDOWN
  ## Automated source health

  | Source | Status | Records | Diagnostic |
  | --- | --- | ---: | --- |
  #{rows.empty? ? '| _No reports produced_ | - | - | Check the workflow diagnostics artifact. |' : rows.join("\n  ")}

  Summary: **#{healthy} healthy**, **#{degraded} degraded**, **#{quarantined} quarantined**, **#{failed} failed**.

  Quarantined sources are diagnostic-only and are not applied automatically. Non-critical
  enrichment sources may finish as degraded without failing the weekly pipeline; a failed
  critical source or validation gate still fails the workflow. A stale fallback is applied
  with degraded health and visible provenance.
MARKDOWN

FileUtils.mkdir_p(File.dirname(output_path))
File.write(output_path, body)
$stdout.sync = true
puts body
$stdout.flush
# Soft-degraded enrichment must not fail the job; only hard failures do.
exit 1 if failed.positive? && ENV['FAIL_ON_SOURCE_FAILURE'] == '1'
