#!/usr/bin/env ruby

# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'set'
require 'time'
require 'uri'
require 'yaml'
require_relative 'actor_store'

class EternalLibertyImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/eternal-liberty'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/eternal-liberty/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'EternalLiberty'.freeze
  SOURCE_REPOSITORY = 'https://github.com/StrangerealIntel/EternalLiberty'.freeze
  SOURCE_URL = 'https://raw.githubusercontent.com/StrangerealIntel/EternalLiberty/main/EternalLiberty.json'.freeze
  SOURCE_ATTRIBUTION = 'Alias cross-reference data was reviewed from EternalLiberty (https://github.com/StrangerealIntel/EternalLiberty). EternalLiberty is used here as a secondary alias crosswalk, not as a sole authoritative source.'.freeze
  UNKNOWN_COUNTRIES = %w[Unknown Worldwide].freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      output: nil,
      snapshot: nil,
      actor_filters: [],
      limit: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false
    }
    @overrides = {
      excluded_records: [],
      match_overrides: {},
      country_overrides: {},
      alias_drop_list: []
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      load_overrides
      import_snapshot
    when 'import'
      parse_import_options
      @options[:write] = true
      load_overrides
      import_snapshot
    else
      puts usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage:
        ruby scripts/import-eternal-liberty.rb fetch [options]
        ruby scripts/import-eternal-liberty.rb plan --snapshot PATH [options]
        ruby scripts/import-eternal-liberty.rb import --snapshot PATH [options]

      Notes:
        - This importer treats EternalLiberty as a reviewed alias crosswalk.
        - It enriches existing actors only; it does not create actors or import descriptions.
        - EternalLiberty is the repository's only approved no-upstream-license import exception.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-eternal-liberty.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-eternal-liberty.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or EternalLiberty.json file') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict to a specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N records') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write a machine-readable report') { |value| @options[:report_json] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
    return if @options[:snapshot]

    warn 'A snapshot path is required for plan/import.'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    json = http_get(URI.parse(SOURCE_URL))
    payload = JSON.parse(json)
    json_path = File.join(@options[:output], 'EternalLiberty.json')
    File.write(json_path, JSON.pretty_generate(payload) + "\n")

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_repository' => SOURCE_REPOSITORY,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'version' => payload['version'],
      'record_count' => Array(payload['data']).length,
      'authors' => Array(payload['author']),
      'license_status' => 'No explicit upstream license; approved as the sole no-license import exception.',
      'checksums_sha256' => {
        'EternalLiberty.json' => Digest::SHA256.hexdigest(File.read(json_path))
      }
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{manifest['record_count']} EternalLiberty records into #{@options[:output]}"
  rescue JSON::ParserError => e
    warn "Invalid EternalLiberty JSON: #{e.message}"
    exit 1
  end

  def import_snapshot
    records, manifest = load_snapshot
    existing_actors = ActorStore.load_all
    existing_lookup, external_id_lookup, existing_by_name = build_existing_indexes(existing_actors)
    candidates = build_candidates(records, existing_lookup, external_id_lookup, existing_by_name, manifest)
    candidates.select! { |candidate| actor_filter_match?(candidate[:existing_actor_name] || candidate[:name]) } unless @options[:actor_filters].empty?
    candidates = candidates.first(@options[:limit]) if @options[:limit]

    report = build_report(candidates, manifest)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(candidates)

    return unless @options[:write]

    apply_candidates(candidates, existing_actors, manifest)
    ActorStore.save_all(existing_actors)
    puts "Applied EternalLiberty enrichments to #{candidates.count { |candidate| candidate[:action] == 'update' }} actors"
  end

  def http_get(uri, limit = 5)
    raise "Too many redirects for #{uri}" if limit <= 0

    response = Net::HTTP.get_response(uri)
    case response
    when Net::HTTPSuccess
      response.body
    when Net::HTTPRedirection
      location = response['location']
      raise "Redirect without location for #{uri}" if location.to_s.empty?

      http_get(URI.parse(location), limit - 1)
    else
      raise "HTTP #{response.code} for #{uri}"
    end
  end

  def load_snapshot
    json_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], 'EternalLiberty.json') : @options[:snapshot]
    manifest_path = File.join(File.dirname(json_path), 'manifest.yml')
    payload = JSON.parse(File.read(json_path))
    manifest = File.exist?(manifest_path) ? safe_load_yaml_file(manifest_path) : {}
    [Array(payload['data']).filter_map { |record| normalize_record(record) }, manifest]
  rescue Errno::ENOENT => e
    warn "Snapshot file not found: #{e.message}"
    exit 1
  rescue JSON::ParserError => e
    warn "Invalid EternalLiberty JSON: #{e.message}"
    exit 1
  end

  def normalize_record(record)
    name = sanitize_text(record['official_name'])
    return nil if name.empty?

    record_key = normalize_key(name)
    return nil if @overrides[:excluded_records].include?(record_key)

    aliases_by_entity = Array(record['alias']).each_with_object({}) do |entry, memo|
      entity = sanitize_text(entry['entity'])
      alias_name = sanitize_text(entry['name'])
      next if entity.empty? || alias_name.empty?
      next if @overrides[:alias_drop_list].include?(normalize_key(alias_name))

      memo[entity] ||= []
      memo[entity] << alias_name
    end

    aliases = ([name] + aliases_by_entity.values.flatten).flat_map { |value| split_aliases(value) }
    aliases.reject! { |value| @overrides[:alias_drop_list].include?(normalize_key(value)) }
    aliases.uniq!

    country = @overrides[:country_overrides][record_key] || sanitize_text(record['country'])
    country = nil if country.empty? || UNKNOWN_COUNTRIES.include?(country)

    {
      record_key: record_key,
      name: name,
      aliases: aliases,
      aliases_by_entity: aliases_by_entity.transform_values(&:uniq),
      mitre_ids: aliases.grep(/\AG\d{4}\z/i).map(&:upcase).uniq,
      country: country,
      confidence: sanitize_text(record['confidence']),
      actor_type: sanitize_text(record['type'])
    }
  end

  def build_existing_indexes(existing_actors)
    existing_lookup = Hash.new { |hash, key| hash[key] = Set.new }
    external_id_lookup = {}
    existing_by_name = {}

    existing_actors.each do |actor|
      name = actor['name']
      next if name.to_s.empty?

      existing_by_name[name] = actor
      ([actor['name']] + Array(actor['aliases']) + [actor['url'].to_s.sub(%r{^/}, '')]).each do |value|
        key = normalize_key(value)
        next if key.empty?

        existing_lookup[key] << name
      end

      %w[external_id mitre_id].each do |field|
        external_id = sanitize_text(actor[field]).upcase
        external_id_lookup[external_id] = name unless external_id.empty?
      end
    end

    [existing_lookup, external_id_lookup, existing_by_name]
  end

  def build_candidates(records, existing_lookup, external_id_lookup, existing_by_name, manifest)
    records.map do |record|
      explicit_match = @overrides[:match_overrides][record[:record_key]]
      matched_names = if explicit_match
                        [explicit_match]
                      else
                        infer_matches(record, existing_lookup, external_id_lookup).to_a.sort
                      end

      action = if matched_names.empty?
                 'skip'
               elsif matched_names.length == 1 && existing_by_name.key?(matched_names.first)
                 'update'
               else
                 'review'
               end

      record.merge(
        action: action,
        matched_actor_names: matched_names,
        existing_actor_name: matched_names.first,
        source_version: manifest['version']
      )
    end
  end

  def infer_matches(record, existing_lookup, external_id_lookup)
    matches = Set.new
    record[:mitre_ids].each do |mitre_id|
      matches << external_id_lookup[mitre_id] if external_id_lookup[mitre_id]
    end

    (record[:aliases] + [record[:name]]).each do |value|
      existing_lookup[normalize_key(value)].each { |actor_name| matches << actor_name }
    end

    matches
  end

  def build_report(candidates, manifest)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      source_repository: SOURCE_REPOSITORY,
      source_url: SOURCE_URL,
      source_version: manifest['version'],
      license_status: manifest['license_status'] || 'No explicit upstream license; approved exception.',
      total_records: candidates.length,
      updates: candidates.count { |candidate| candidate[:action] == 'update' },
      review: candidates.count { |candidate| candidate[:action] == 'review' },
      skipped: candidates.count { |candidate| candidate[:action] == 'skip' },
      actions: candidates.map do |candidate|
        {
          name: candidate[:name],
          action: candidate[:action],
          matched_actor_names: candidate[:matched_actor_names],
          alias_count: candidate[:aliases].length,
          mitre_ids: candidate[:mitre_ids],
          confidence: candidate[:confidence],
          type: candidate[:actor_type],
          country: candidate[:country]
        }
      end
    }
  end

  def print_report(candidates)
    puts "\n=== EternalLiberty Import Plan ==="
    puts "Total records: #{candidates.length}"
    puts "Updates: #{candidates.count { |candidate| candidate[:action] == 'update' }}"
    puts "Review: #{candidates.count { |candidate| candidate[:action] == 'review' }}"
    puts "Skipped: #{candidates.count { |candidate| candidate[:action] == 'skip' }}"
    puts 'License: no explicit upstream license; approved as the sole no-license import exception.'

    candidates.select { |candidate| candidate[:action] == 'update' }.first(20).each do |candidate|
      puts "\nUPDATE: #{candidate[:name]}"
      puts "  Match: #{candidate[:existing_actor_name]}"
      puts "  Aliases: #{candidate[:aliases].first(8).join(', ')}" unless candidate[:aliases].empty?
      puts "  MITRE IDs: #{candidate[:mitre_ids].join(', ')}" unless candidate[:mitre_ids].empty?
      puts "  Country: #{candidate[:country]}" if candidate[:country]
    end

    puts "\n=== Run with import to apply reviewed enrichments ===" unless @options[:write]
  end

  def apply_candidates(candidates, existing_actors, manifest)
    existing_by_name = existing_actors.each_with_object({}) { |actor, memo| memo[actor['name']] = actor }

    candidates.each do |candidate|
      next unless candidate[:action] == 'update'

      actor = existing_by_name[candidate[:existing_actor_name]]
      next unless actor

      merge_array_field(actor, 'aliases', candidate[:aliases])
      actor['country'] ||= candidate[:country] if candidate[:country]
      actor['external_id'] ||= candidate[:mitre_ids].first if candidate[:mitre_ids].length == 1

      actor['provenance'] ||= {}
      actor['provenance']['eternal_liberty'] = {
        'source_retrieved_at' => manifest['retrieved_at'] || Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_dataset_url' => SOURCE_REPOSITORY,
        'source_version' => manifest['version'],
        'source_record_id' => candidate[:record_key],
        'license_status' => manifest['license_status'] || 'No explicit upstream license; approved exception.',
        'confidence' => candidate[:confidence],
        'type' => candidate[:actor_type],
        'aliases_by_entity' => candidate[:aliases_by_entity]
      }
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
    end
  end

  def merge_array_field(actor, field, values)
    return if values.nil? || values.empty?

    actor[field] = (Array(actor[field]) + values).map { |value| sanitize_text(value) }.reject(&:empty?).uniq
  end

  def actor_filter_match?(actor_name)
    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    filters.include?(normalize_key(actor_name))
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_records] = Array(payload['excluded_records']).map { |value| normalize_key(value) }.uniq
    @overrides[:match_overrides] = normalize_override_hash(payload['match_overrides'], preserve_values: true)
    @overrides[:country_overrides] = normalize_override_hash(payload['country_overrides'], preserve_values: true)
    @overrides[:alias_drop_list] = Array(payload['alias_drop_list']).map { |value| normalize_key(value) }.uniq
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = normalize_key(key)
      next if normalized_key.empty?

      memo[normalized_key] = preserve_values ? mapped_value : normalize_key(mapped_value)
    end
  end

  def split_aliases(value)
    sanitize_text(value).split(%r{\s*/\s*}).map { |entry| sanitize_text(entry) }.reject(&:empty?)
  end

  def normalize_key(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]/, '')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  end
end

EternalLibertyImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
