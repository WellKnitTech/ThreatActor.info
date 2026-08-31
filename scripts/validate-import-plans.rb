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

def first_numeric(payload, *key_groups)
  key_groups.each do |keys|
    value = numeric(payload, keys)
    return value unless value.nil?
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

def report_source(_payload, path)
  # Filenames carry the stable key used by plan_thresholds.yml; report source
  # fields are human labels in several legacy importers.
  source_key_from_file(path)
end

def report_counts(payload)
  return [nil, false, 'report must be a JSON object'] unless payload.is_a?(Hash)

  status = payload['status'].to_s
  status = payload['query_status'].to_s if status.empty?
  failed_flags = payload['available'] == false || payload['authenticated'] == false || payload['outage'] == true
  if %w[retryable_error fatal_error rejected quarantine quarantined error failed no_auth no_auth_key auth_missing unauthorized unauthenticated auth_required unavailable outage].include?(status) || failed_flags || !payload['error'].to_s.strip.empty?
    return [nil, false, "source report has failure status #{status.inspect}"]
  end

  if status == 'source_empty' || payload['source_empty'] == true
    return [{ 'total_records' => 0, 'matched' => 0, 'unmatched' => 0, 'new_candidates' => 0 }, false, nil] if payload['empty_reason'].is_a?(String) && !payload['empty_reason'].strip.empty?
    return [nil, false, 'source-empty report requires a non-empty string empty_reason']
  end

  matched = first_numeric(payload, %w[matched matched_existing_actors], %w[matched_actors], %w[updates actors_with_updates])
  unmatched = first_numeric(payload, %w[unmatched unmatched_actors unmatched_reports], %w[review skipped])
  new_candidates = first_numeric(payload, %w[new_candidates], %w[creates])
  total = first_numeric(payload, %w[total_records total_candidates apt_records records_count record_count], %w[ioc_rows])
  unmatched ||= [total - matched - (new_candidates || 0), 0].max if total && matched
  measurable = [matched, unmatched, new_candidates, total].any?
  no_op = measurable && [matched, unmatched, new_candidates, total].compact.all?(&:zero?)
  counts = payload.merge('matched' => matched, 'unmatched' => unmatched,
                         'new_candidates' => new_candidates, 'total_records' => total)
  [counts, !no_op && measurable, nil]
end

report_files = Dir.glob(File.join(options[:report_dir], 'plan-*.json')).sort
if report_files.empty?
  puts "No plan reports found in #{options[:report_dir]}; skipping anomaly checks."
  exit 0
end

anomalies = []
processed = 0

report_files.each do |path|
  payload = JSON.parse(File.read(path))
  unless payload.is_a?(Hash)
    warn "Skipping non-summary report (array or unexpected shape from ransomlook or similar): #{path}"
    next
  end

  source = report_source(payload, path)

  processed += 1
  thresholds = DEFAULT_THRESHOLDS.merge(config.fetch('defaults', {})).merge(config.fetch('sources', {}).fetch(source, {}))

  counts, metrics_applicable, shape_error = report_counts(payload)
  if shape_error
    anomalies << { 'source' => source, 'issues' => [shape_error], 'summary' => 'invalid report shape' }
    next
  end

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
