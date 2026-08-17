#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'fileutils'

report_dir = ARGV.fetch(0, 'tmp/import-reports')
output_path = ARGV.fetch(1, 'tmp/import-health.md')

reports = Dir[File.join(report_dir, '*.json')].sort.map do |path|
  begin
    payload = JSON.parse(File.read(path))
    payload = payload.first if payload.is_a?(Array)
    [File.basename(path), payload]
  rescue JSON::ParserError => e
    [File.basename(path), { 'status' => 'invalid', 'error' => e.message }]
  end
end

rows = reports.map do |filename, payload|
  source = payload['source'] || payload['source_key'] || filename.sub(/-(?:plan|import)-report\.json$/, '')
  status = payload['status'] || (payload['quarantined'] ? 'quarantined' : 'completed')
  count = payload['record_count'] || payload['records'] || payload['count'] || '-'
  diagnostic = payload['diagnostic'] || payload['error'] || payload['reason'] || ''
  escaped_diagnostic = diagnostic.to_s.gsub('\\', '\\\\').gsub('|', '\\|').gsub(/\s+/, ' ').strip
  "| `#{source}` | #{status} | #{count} | #{escaped_diagnostic} |"
end

quarantined = reports.count { |_filename, payload| payload['quarantined'] == true || payload['status'].to_s == 'quarantined' }
failed = reports.count { |_filename, payload| %w[failed error invalid].include?(payload['status'].to_s) }
healthy = reports.length - quarantined - failed

body = <<~MARKDOWN
  ## Automated source health

  | Source | Status | Records | Diagnostic |
  | --- | --- | ---: | --- |
  #{rows.empty? ? '| _No reports produced_ | - | - | Check the workflow diagnostics artifact. |' : rows.join("\n  ")}

  Summary: **#{healthy} healthy**, **#{quarantined} quarantined**, **#{failed} failed**.

  Quarantined sources are diagnostic-only and are not applied automatically. A failed
  workflow remains failed even when diagnostics and artifacts are uploaded.
MARKDOWN

FileUtils.mkdir_p(File.dirname(output_path))
File.write(output_path, body)
puts body
exit 1 if failed.positive? && ENV['FAIL_ON_SOURCE_FAILURE'] == '1'
