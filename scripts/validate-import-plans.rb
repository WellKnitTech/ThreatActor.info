#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'yaml'
require 'optparse'

DEFAULT_THRESHOLDS = {
  'min_match_ratio' => 0.5,
  'max_unmatched_ratio' => 0.35,
  'max_alias_additions_per_actor' => 12
}.freeze

options = {
  report_dir: 'tmp/import-reports',
  config: 'data/imports/plan_thresholds.yml',
  allow_anomalies: false
}

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby scripts/validate-import-plans.rb [options]'
  opts.on('--report-dir DIR', 'Directory containing plan-*.json reports') { |v| options[:report_dir] = v }
  opts.on('--config PATH', 'Threshold config YAML path') { |v| options[:config] = v }
  opts.on('--allow-anomalies', 'Do not fail when thresholds are exceeded') { options[:allow_anomalies] = true }
end.parse!

config = if File.exist?(options[:config])
           YAML.safe_load(File.read(options[:config]), permitted_classes: [], aliases: false) || {}
         else
           {}
         end

def numeric(payload, keys)
  keys.each do |key|
    value = payload[key]
    return value.to_f if value.is_a?(Numeric)
  end
  nil
end

def max_alias_additions(payload)
  max_from_changes = Array(payload['candidates']).filter_map do |candidate|
    size = candidate.dig('changes', 'new_aliases')
    size.is_a?(Array) ? size.length : nil
  end.max

  explicit = numeric(payload, %w[max_new_aliases_per_actor max_alias_additions_per_actor])
  [max_from_changes, explicit].compact.max
end

def source_key_from_file(path)
  File.basename(path).sub(/^plan-/, '').sub(/-report\.json$/, '').sub(/\.json$/, '')
end

def report_source(payload, path)
  source = payload.is_a?(Hash) ? payload['source'].to_s.strip : ''
  source.empty? ? source_key_from_file(path) : source
end

def report_counts(payload, source)
  unless payload.is_a?(Hash) || (payload.is_a?(Array) && source == 'ransomlook')
    return [nil, false, 'report must be a JSON object or a RansomLook evaluation array']
  end

  if payload.is_a?(Array)
    return [{ 'total_records' => 0, 'matched' => 0, 'unmatched' => 0, 'new_candidates' => 0 }, false, nil] if payload.empty?

    return [nil, false, 'evaluation array contains a non-object item'] unless payload.all? { |item| item.is_a?(Hash) }

    actions = payload.group_by { |item| item['action'].to_s }
    known_actions = %w[create update skip review]
    unknown = actions.keys - known_actions
    return [nil, false, "evaluation array contains unknown action(s): #{unknown.join(', ')}"] unless unknown.empty?

    # RansomLook emits per-record evaluations, not actor-match counters. Keep
    # the report useful for observability without applying unrelated ratios.
    return [{ 'total_records' => payload.length,
              'matched' => actions.fetch('update', []).length,
              'unmatched' => actions.fetch('review', []).length,
              'new_candidates' => actions.fetch('create', []).length }, false, nil]
  end

  status = payload['status'].to_s
  candidates = payload['candidates']
  if candidates && (!candidates.is_a?(Array) || candidates.any? { |candidate| !candidate.is_a?(Hash) })
    return [nil, false, 'report candidates must be an array of objects']
  end
  if candidates&.any? { |candidate| candidate.key?('changes') && !candidate['changes'].is_a?(Hash) }
    return [nil, false, 'report candidate changes must be an object']
  end

  failure_signal = payload['error'].to_s.strip
  failure_signal = 'unavailable' if payload['available'] == false || payload['outage'] == true || payload['authenticated'] == false
  if %w[retryable_error fatal_error rejected quarantine quarantined error failed no_auth no_auth_key auth_missing unauthorized unauthenticated auth_required unavailable outage source_unavailable upstream_unavailable].include?(status) || !failure_signal.empty?
    detail = status.empty? ? failure_signal : "failure status #{status.inspect}"
    return [nil, false, "source report has #{detail}"]
  end

  if status == 'source_empty' || payload['source_empty'] == true
    reason = payload['empty_reason']
    return [{ 'total_records' => 0, 'matched' => 0, 'unmatched' => 0, 'new_candidates' => 0 }, false, nil] if reason.is_a?(String) && !reason.strip.empty?

    return [nil, false, 'source-empty report requires a non-empty string empty_reason']
  end

  [payload, true, nil]
end

report_files = Dir.glob(File.join(options[:report_dir], 'plan-*.json')).sort
if report_files.empty?
  puts "No plan reports found in #{options[:report_dir]}; skipping anomaly checks."
  exit 0
end

anomalies = []
processed = 0

report_files.each do |path|
  begin
    payload = JSON.parse(File.read(path))
  rescue JSON::ParserError => e
    processed += 1
    anomalies << { 'source' => source_key_from_file(path), 'issues' => ["malformed JSON: #{e.message}"], 'summary' => 'invalid report JSON' }
    next
  end
  source = report_source(payload, path)
  counts, metrics_applicable, shape_error = report_counts(payload, source)

  processed += 1
  if shape_error
    anomalies << { 'source' => source, 'issues' => [shape_error], 'summary' => 'invalid report shape' }
    next
  end

  thresholds = DEFAULT_THRESHOLDS.merge(config.fetch('defaults', {})).merge(config.fetch('sources', {}).fetch(source, {}))

  matched = numeric(counts, %w[matched matched_existing_actors]) || 0.0
  unmatched = numeric(counts, %w[unmatched unmatched_actors unmatched_reports]) || 0.0
  new_candidates = numeric(counts, %w[new_candidates]) || 0.0
  total = numeric(counts, %w[total_records total_candidates apt_records records_count record_count]) || (matched + unmatched + new_candidates)
  denominator = [total, matched + unmatched + new_candidates].max
  denominator = 1.0 if denominator <= 0

  match_ratio = matched / denominator
  unmatched_ratio = (unmatched + new_candidates) / denominator
  alias_max = max_alias_additions(counts) || 0

  source_issues = []
  if metrics_applicable
    source_issues << format('match ratio %.2f < %.2f', match_ratio, thresholds['min_match_ratio']) if match_ratio < thresholds['min_match_ratio']
    source_issues << format('unmatched/new ratio %.2f > %.2f', unmatched_ratio, thresholds['max_unmatched_ratio']) if unmatched_ratio > thresholds['max_unmatched_ratio']
    source_issues << format('max alias additions/actor %d > %d', alias_max, thresholds['max_alias_additions_per_actor']) if alias_max > thresholds['max_alias_additions_per_actor']
  end

  next if source_issues.empty?

  anomalies << {
    'source' => source,
    'issues' => source_issues,
    'summary' => format('match=%.2f unmatched+new=%.2f alias_max=%d', match_ratio, unmatched_ratio, alias_max)
  }
end

if anomalies.empty?
  checked = processed
  skipped = report_files.length - processed
  msg = "Plan threshold checks passed across #{checked} source report(s)."
  msg += " (#{skipped} non-summary reports skipped)" if skipped > 0
  puts msg
  exit 0
end

puts "Plan anomalies detected (checked #{processed} of #{report_files.length} reports):"
anomalies.each do |item|
  puts "- #{item['source']}: #{item['summary']}"
  item['issues'].each { |issue| puts "    • #{issue}" }
end

if options[:allow_anomalies]
  warn 'Continuing because --allow-anomalies was set.'
  exit 0
end

abort 'Threshold violations found. Re-run with --allow-anomalies to proceed manually.'
