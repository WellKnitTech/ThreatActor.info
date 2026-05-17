#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'optparse'
require 'time'
require 'yaml'
require 'fileutils'

options = {
  config: 'data/imports/source_freshness.yml',
  imports_root: 'data/imports',
  output_json: '_data/generated/source_freshness.json',
  report_json: 'tmp/source-freshness-report.json',
  mode: 'strict'
}

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby scripts/check-source-freshness.rb [options]'
  opts.on('--config PATH', 'Freshness config YAML path') { |v| options[:config] = v }
  opts.on('--imports-root PATH', 'Root path containing source snapshot directories') { |v| options[:imports_root] = v }
  opts.on('--output-json PATH', 'Write generated freshness API payload') { |v| options[:output_json] = v }
  opts.on('--report-json PATH', 'Write machine-readable CI report') { |v| options[:report_json] = v }
  opts.on('--mode MODE', 'strict (default) or warn') { |v| options[:mode] = v }
end.parse!

abort "Missing config: #{options[:config]}" unless File.exist?(options[:config])
abort "Missing imports root: #{options[:imports_root]}" unless Dir.exist?(options[:imports_root])

config = YAML.safe_load(File.read(options[:config]), permitted_classes: [], aliases: false) || {}
defaults = config['defaults'] || {}
source_rules = config['sources'] || {}

now = Time.now.utc
entries = Dir.children(options[:imports_root]).select { |name| File.directory?(File.join(options[:imports_root], name)) }.sort

results = entries.map do |source_key|
  source_path = File.join(options[:imports_root], source_key)
  snapshots = Dir.children(source_path)
                 .map { |name| File.join(source_path, name) }
                 .select { |path| File.directory?(path) }

  latest_snapshot_path = snapshots.max_by { |path| File.mtime(path) }
  latest_snapshot_name = latest_snapshot_path ? File.basename(latest_snapshot_path) : nil
  latest_snapshot_time = latest_snapshot_path ? File.mtime(latest_snapshot_path).utc : nil

  effective = defaults.merge(source_rules[source_key] || {})
  max_age_days = Integer(effective['max_age_days'] || 30)
  criticality_tier = effective['criticality_tier'] || 'medium'
  fallback_behavior = effective['fallback_behavior'] || 'use-last-snapshot'

  age_days = latest_snapshot_time ? ((now - latest_snapshot_time) / 86_400.0) : Float::INFINITY
  stale = !latest_snapshot_time || age_days > max_age_days

  {
    source_key: source_key,
    latest_snapshot: latest_snapshot_name,
    latest_snapshot_timestamp: latest_snapshot_time&.iso8601,
    age_days: latest_snapshot_time ? age_days.round(2) : nil,
    max_age_days: max_age_days,
    is_stale: stale,
    criticality_tier: criticality_tier,
    fallback_behavior: fallback_behavior,
    status: stale ? 'stale' : 'fresh'
  }
end

stale_results = results.select { |row| row[:is_stale] }
summary = {
  checked_sources: results.length,
  stale_sources: stale_results.length,
  fresh_sources: results.length - stale_results.length,
  mode: options[:mode]
}

payload = {
  generated_at: now.iso8601,
  config_path: options[:config],
  imports_root: options[:imports_root],
  summary: summary,
  sources: results
}

[options[:output_json], options[:report_json]].compact.each do |path|
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(payload) + "\n")
end

puts "Source freshness check completed: #{summary[:fresh_sources]} fresh, #{summary[:stale_sources]} stale."
stale_results.each do |row|
  age_label = row[:age_days] ? "#{format('%.2f', row[:age_days])}d" : 'unknown'
  warn "STALE #{row[:source_key]}: age=#{age_label} threshold=#{row[:max_age_days]}d tier=#{row[:criticality_tier]} fallback=#{row[:fallback_behavior]}"
end

if stale_results.empty? || options[:mode] == 'warn'
  exit 0
end

exit 2
