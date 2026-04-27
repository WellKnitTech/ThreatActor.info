#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'json'
require 'optparse'
require 'time'
require 'yaml'

HIGH_IMPACT_FIELDS = %w[name url description aliases source_name source_attribution source_record_url].freeze
VOLATILE_FIELDS = %w[
  source_retrieved_at
  generated_at
  fetched_at
  retrieved_at
  updated_at
  last_checked_at
].freeze

options = {
  current: '_data/actors',
  previous: nil,
  report_json: nil,
  max_change_ratio: 0.10,
  max_identity_change_ratio: 0.02,
  allow_mass_removal: false
}

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby scripts/evaluate-source-deltas.rb --previous PATH [options]'
  opts.on('--current PATH', 'Current actors path (dir or file)') { |v| options[:current] = v }
  opts.on('--previous PATH', 'Previous actors path (dir or file)') { |v| options[:previous] = v }
  opts.on('--report-json PATH', 'Write machine-readable report') { |v| options[:report_json] = v }
  opts.on('--max-change-ratio VALUE', Float, 'Max create+update+delete ratio (default 0.10)') { |v| options[:max_change_ratio] = v }
  opts.on('--max-identity-change-ratio VALUE', Float, 'Max name/url change ratio (default 0.02)') { |v| options[:max_identity_change_ratio] = v }
  opts.on('--allow-mass-removal', 'Allow actor removals without failing') { options[:allow_mass_removal] = true }
end.parse!

if options[:previous].to_s.strip.empty?
  warn 'Missing required --previous path'
  exit 1
end

def load_actor_collection(path)
  if File.directory?(path)
    Dir.glob(File.join(path, '*.yml')).sort.map do |file|
      YAML.safe_load(File.read(file), permitted_classes: [], aliases: true)
    end.compact
  else
    payload = if File.extname(path) == '.json'
                JSON.parse(File.read(path))
              else
                YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
              end
    payload.is_a?(Array) ? payload : []
  end
end

def canonical_hash(actor)
  stable = scrub_volatile(actor)
  Digest::SHA256.hexdigest(JSON.generate(stable))
end

def scrub_volatile(value)
  case value
  when Hash
    value.keys.sort.each_with_object({}) do |key, memo|
      next if VOLATILE_FIELDS.include?(key.to_s)

      memo[key] = scrub_volatile(value[key])
    end
  when Array
    value.map { |entry| scrub_volatile(entry) }
  else
    value
  end
end

current = load_actor_collection(options[:current])
previous = load_actor_collection(options[:previous])

current_by_url = current.each_with_object({}) { |actor, memo| memo[actor['url']] = actor if actor['url'] }
previous_by_url = previous.each_with_object({}) { |actor, memo| memo[actor['url']] = actor if actor['url'] }

created_urls = current_by_url.keys - previous_by_url.keys
deleted_urls = previous_by_url.keys - current_by_url.keys
common_urls = current_by_url.keys & previous_by_url.keys

updated_urls = []
high_impact_changes = []
identity_changes = []

common_urls.each do |url|
  current_actor = current_by_url[url]
  previous_actor = previous_by_url[url]
  next if canonical_hash(current_actor) == canonical_hash(previous_actor)

  updated_urls << url
  changed_fields = (current_actor.keys | previous_actor.keys).select do |field|
    next false if VOLATILE_FIELDS.include?(field)

    scrub_volatile(current_actor[field]) != scrub_volatile(previous_actor[field])
  end
  high_impact = changed_fields & HIGH_IMPACT_FIELDS
  high_impact_changes << { url: url, fields: high_impact } unless high_impact.empty?
  identity_changes << url if high_impact.include?('name') || high_impact.include?('url')
end

baseline_count = [previous.length, 1].max
change_ratio = (created_urls.length + updated_urls.length + deleted_urls.length).to_f / baseline_count
identity_change_ratio = identity_changes.length.to_f / baseline_count
mass_removal = deleted_urls.any?

report = {
  current_path: options[:current],
  previous_path: options[:previous],
  generated_at: Time.now.utc.iso8601,
  totals: {
    previous: previous.length,
    current: current.length,
    created: created_urls.length,
    updated: updated_urls.length,
    deleted: deleted_urls.length
  },
  ratios: {
    change_ratio: change_ratio.round(6),
    identity_change_ratio: identity_change_ratio.round(6)
  },
  threshold: {
    max_change_ratio: options[:max_change_ratio],
    max_identity_change_ratio: options[:max_identity_change_ratio],
    allow_mass_removal: options[:allow_mass_removal]
  },
  violations: {
    change_ratio_exceeded: change_ratio > options[:max_change_ratio],
    identity_change_ratio_exceeded: identity_change_ratio > options[:max_identity_change_ratio],
    mass_removal_detected: mass_removal && !options[:allow_mass_removal]
  },
  changed_urls: {
    created: created_urls.sort,
    updated: updated_urls.sort,
    deleted: deleted_urls.sort
  },
  high_impact_changes: high_impact_changes.sort_by { |entry| entry[:url] }
}

if options[:report_json]
  File.write(options[:report_json], JSON.pretty_generate(report) + "\n")
end

puts "Previous actors: #{previous.length}"
puts "Current actors: #{current.length}"
puts "Created: #{created_urls.length}, Updated: #{updated_urls.length}, Deleted: #{deleted_urls.length}"
puts "Change ratio: #{format('%.4f', change_ratio)} (limit #{format('%.4f', options[:max_change_ratio])})"
puts "Identity change ratio: #{format('%.4f', identity_change_ratio)} (limit #{format('%.4f', options[:max_identity_change_ratio])})"

violations = report[:violations].select { |_k, v| v }.keys
if violations.empty?
  puts 'Delta evaluation passed.'
  exit 0
end

warn "Delta evaluation failed: #{violations.join(', ')}"
exit 2
