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

FAILURE_STATUSES = %w[
  auth_missing auth_required error failed failure fatal_error http_error
  invalid_auth_key malformed_response no_auth no_auth_key query_error query_failed
  rate_limited rejected retryable_error timeout unauthenticated unauthorized unavailable
].freeze

def numeric(payload, keys)
  values = keys.filter_map { |key| payload[key].to_f if payload[key].is_a?(Numeric) }
  # Some importers emit both canonical and legacy/action counters. A zero
  # canonical value must not hide a nonzero alias emitted by the same run.
  values.find(&:positive?) || values.first
end

def outcome_count(payload, canonical_keys, fallback_keys)
  return canonical_keys.sum { |key| payload[key].is_a?(Numeric) ? payload[key].to_f : 0.0 } if canonical_keys.any? { |key| payload[key].is_a?(Numeric) }

  numeric(payload, fallback_keys)
end

def numeric_sum(payload, keys)
  keys.sum { |key| payload[key].is_a?(Numeric) ? payload[key].to_f : 0.0 }
end
def failure_issue(payload)
  statuses = %w[status query_status].filter_map do |key|
    value = payload[key].to_s.strip.downcase
    value unless value.empty?
  end
  return "source report has failure metadata" if %w[failure failed query_failed].any? { |key| payload[key] == true }
  return "source report has failure status #{statuses.join(', ').inspect}" if (statuses & FAILURE_STATUSES).any?
  return 'source report has failure metadata' if payload['error'].to_s.strip != ''

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

def report_counts(payload)
  return [nil, false, 'report must be a JSON object'] unless payload.is_a?(Hash)
  if (issue = failure_issue(payload))
    return [nil, false, issue]
  end

  explicit_empty = payload['status'].to_s == 'source_empty' || payload['source_empty'] == true
  if explicit_empty
    reason = payload['empty_reason'].to_s.strip
    return [nil, false, 'source-empty report requires a non-empty empty_reason'] if reason.empty?

    return [{ 'total_records' => 0, 'matched' => 0, 'unmatched' => 0, 'new_candidates' => 0 }, false, nil]
  end

  matched = numeric(payload, %w[matched matched_iocs matched_existing_actors matched_actors matched_reports actors_with_updates updates actors_merge])
  unmatched = outcome_count(payload, %w[ambiguous_reports unmatched_reports ambiguous_iocs unknown_iocs], %w[unmatched unmatched_actors unmatched_reports review skipped actors_review])
  disjoint_unmatched = numeric_sum(payload, %w[review skipped actors_review])
  if %w[review skipped actors_review].any? { |key| payload[key].is_a?(Numeric) }
    unmatched = disjoint_unmatched
  end
  new_candidates = numeric(payload, %w[new_candidates creates actors_create])
  total = numeric(payload, %w[total_records total_candidates total_rows total_detections event_count apt_records records_count record_count ioc_rows parsed_records intrusion_sets source_records])
  if payload['actor_updates'].is_a?(Array)
    matched_labels = payload['actor_updates'].sum do |entry|
      entry.is_a?(Hash) ? Array(entry['source_labels']).length : 0
    end
    matched = matched_labels.to_f if matched_labels.positive?
  end
  if payload['unmatched_labels'].is_a?(Array) || payload['review_labels'].is_a?(Array)
    label_unmatched = Array(payload['unmatched_labels']).length + Array(payload['review_labels']).length
    unmatched = label_unmatched.to_f
  end
  if payload['actions'].is_a?(Array)
    actions = payload['actions'].filter_map { |action| action.is_a?(Hash) ? action['action'].to_s : action.to_s }
    matched ||= actions.count { |action| %w[add update updated].include?(action) }
    unmatched ||= actions.count { |action| %w[review skip skipped unmatched].include?(action) }
    new_candidates ||= actions.count { |action| %w[new_candidate new candidates].include?(action) }
    total ||= actions.length
  end
  measurable = [matched, unmatched, new_candidates, total].any?
  return [nil, false, 'report has no supported counters or explicit empty status'] unless measurable

  unmatched ||= [total - matched - (new_candidates || 0), 0].max if total && matched
  counts = payload.merge('matched' => matched, 'unmatched' => unmatched,
                         'new_candidates' => new_candidates, 'total_records' => total)
  return [nil, false, 'all-zero report requires explicit source_empty metadata'] if
    [matched, unmatched, new_candidates, total].compact.all?(&:zero?)

  [counts, true, nil]
end

report_files = Dir.glob(File.join(options[:report_dir], 'plan-*.json')).sort
if report_files.empty?
  puts "No plan reports found in #{options[:report_dir]}; skipping anomaly checks."
  exit 0
end

anomalies = []
processed = 0
no_ops = 0

report_files.each do |path|
  payload = JSON.parse(File.read(path))
  unless payload.is_a?(Hash)
    warn "Skipping non-summary report (array or unexpected shape from ransomlook or similar): #{path}"
    next
  end

  source = source_key_from_file(path)

  processed += 1
  thresholds = DEFAULT_THRESHOLDS.merge(config.fetch('defaults', {})).merge(config.fetch('sources', {}).fetch(source, {}))

  counts, metrics_applicable, shape_error = report_counts(payload)
  if shape_error
    anomalies << { 'source' => source, 'issues' => [shape_error], 'summary' => 'invalid report shape' }
    next
  end

  no_ops += 1 unless metrics_applicable
  matched = numeric(counts, %w[matched matched_iocs matched_existing_actors matched_actors matched_reports actors_with_updates updates actors_merge]) || 0.0
  unmatched = outcome_count(counts, %w[ambiguous_reports unmatched_reports ambiguous_iocs unknown_iocs], %w[unmatched unmatched_actors unmatched_reports review skipped actors_review]) || 0.0
  disjoint_unmatched = numeric_sum(counts, %w[review skipped actors_review])
  if %w[review skipped actors_review].any? { |key| counts[key].is_a?(Numeric) }
    unmatched = disjoint_unmatched
  end
  if counts['unmatched_labels'].is_a?(Array) || counts['review_labels'].is_a?(Array)
    label_unmatched = Array(counts['unmatched_labels']).length + Array(counts['review_labels']).length
    unmatched = label_unmatched.to_f
  end
  new_candidates = numeric(counts, %w[new_candidates creates actors_create]) || 0.0
  total = numeric(counts, %w[total_records total_candidates total_rows total_detections event_count apt_records records_count record_count ioc_rows parsed_records intrusion_sets source_records]) || (matched + unmatched + new_candidates)
  if counts['actor_updates'].is_a?(Array)
    matched_labels = counts['actor_updates'].sum do |entry|
      entry.is_a?(Hash) ? Array(entry['source_labels']).length : 0
    end
    matched = matched_labels.to_f if matched_labels.positive?
  end
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
  msg += " (#{no_ops} legitimate no-op report(s))" if no_ops.positive?
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
