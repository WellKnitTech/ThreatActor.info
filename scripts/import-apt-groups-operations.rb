#!/usr/bin/env ruby

# frozen_string_literal: true

require 'csv'
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

class AptGroupsOperationsImporter
  SHEET_ID = '1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/apt-groups-operations'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/apt-groups-operations/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'APT Groups & Operations Spreadsheet'.freeze
  SOURCE_URL = 'https://apt.threattracking.com/'.freeze
  SOURCE_ATTRIBUTION = 'Alias and operation cross-reference data were reviewed from the public APT Groups & Operations spreadsheet (https://apt.threattracking.com/). The spreadsheet is used here as a secondary research aid and crosswalk, not as a sole authoritative source.'.freeze
  TAB_CONFIG = {
    'russia' => { gid: '1636225066', country: 'Russia' },
    'china' => { gid: '361554658', country: 'China' },
    'north-korea' => { gid: '1905351590', country: 'North Korea' },
    'iran' => { gid: '376438690', country: 'Iran' },
    'israel' => { gid: '300065512', country: 'Israel' },
    'others' => { gid: '438782970', country: nil },
    'unknown' => { gid: '1121522397', country: nil }
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      output: nil,
      snapshot: nil,
      actor_filters: [],
      limit: nil,
      tabs: [],
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false
    }
    @overrides = {
      excluded_rows: [],
      match_overrides: {},
      country_overrides: {},
      alias_drop_list: []
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      load_overrides
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
        ruby scripts/import-apt-groups-operations.rb fetch [options]
        ruby scripts/import-apt-groups-operations.rb plan --snapshot PATH [options]
        ruby scripts/import-apt-groups-operations.rb import --snapshot PATH [options]

      Notes:
        - This importer enriches existing actors only.
        - It additively merges aliases, malware names, operation labels, and provenance.
        - It does not overwrite curated descriptions or create new actors.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-apt-groups-operations.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--tab NAME', "Restrict to a specific tab: #{TAB_CONFIG.keys.join(', ')}") { |value| @options[:tabs] << value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-apt-groups-operations.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict to a specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N matched actors') { |value| @options[:limit] = value }
      opts.on('--tab NAME', "Restrict to a specific tab: #{TAB_CONFIG.keys.join(', ')}") { |value| @options[:tabs] << value }
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
    tabs = selected_tabs
    tabs.each do |tab_name, config|
      csv = http_get(build_tab_uri(config[:gid]))
      File.write(File.join(@options[:output], "#{tab_name}.csv"), csv)
    end

    tab_checksums = tabs.keys.sort.each_with_object({}) do |tab_name, memo|
      csv_path = File.join(@options[:output], "#{tab_name}.csv")
      memo[tab_name] = Digest::SHA256.hexdigest(File.read(csv_path))
    end

    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump({
                                                                         'source_name' => SOURCE_NAME,
                                                                         'source_url' => SOURCE_URL,
                                                                         'sheet_id' => SHEET_ID,
                                                                         'retrieved_at' => Time.now.utc.iso8601,
                                                                         'tabs' => tabs.transform_values { |config| config[:gid] },
                                                                         'tab_checksums_sha256' => tab_checksums
                                                                       }))
    puts "Fetched #{tabs.length} spreadsheet tabs into #{@options[:output]}"
  end

  def import_snapshot
    rows = load_snapshot_rows
    existing_actors = ActorStore.load_all
    existing_lookup, external_id_lookup, existing_by_name = build_existing_indexes(existing_actors)
    candidates = build_candidates(rows, existing_lookup, external_id_lookup, existing_by_name)
    candidates.select! { |candidate| actor_filter_match?(candidate[:existing_actor_name] || candidate[:name]) } unless @options[:actor_filters].empty?
    candidates = candidates.first(@options[:limit]) if @options[:limit]

    report = build_report(candidates)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(candidates)

    return unless @options[:write]

    apply_candidates(candidates, existing_actors)
    ActorStore.save_all(existing_actors)
    puts "Applied spreadsheet enrichments to #{candidates.count { |candidate| candidate[:action] == 'update' }} actors"
  end

  def selected_tabs
    return TAB_CONFIG if @options[:tabs].empty?

    @options[:tabs].each_with_object({}) do |tab_name, memo|
      config = TAB_CONFIG[tab_name]
      next unless config

      memo[tab_name] = config
    end
  end

  def build_tab_uri(gid)
    URI.parse("https://docs.google.com/spreadsheets/d/#{SHEET_ID}/export?format=csv&gid=#{gid}")
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

  def load_snapshot_rows
    tabs = selected_tabs
    tabs.flat_map do |tab_name, config|
      csv_path = File.join(@options[:snapshot], "#{tab_name}.csv")
      parse_country_tab(File.read(csv_path), tab_name, config[:country])
    end
  rescue Errno::ENOENT => e
    warn "Snapshot file not found: #{e.message}"
    exit 1
  end

  def parse_country_tab(csv_text, tab_name, default_country)
    rows = CSV.parse(csv_text)
    header_index = rows.find_index { |row| row.include?('Common Name') }
    return [] unless header_index

    headers = rows[header_index]
    rows[(header_index + 1)..].to_a.filter_map do |row|
      next if row.compact.all? { |value| sanitize_text(value).empty? }

      data = headers.each_with_index.each_with_object({}) do |(header, index), memo|
        memo[header] = row[index]
      end

      common_name = sanitize_text(data['Common Name'])
      next if common_name.empty? || common_name == '???'

      row_key = normalize_key("#{tab_name}:#{common_name}")
      next if @overrides[:excluded_rows].include?(row_key)

      aliases = headers.grep(/^Other Name/).map { |header| sanitize_text(data[header]) }
      aliases << sanitize_text(data['Secureworks'])
      aliases << common_name
      aliases = aliases.flat_map { |value| split_aliases(value) }
      aliases.reject! { |value| value.empty? || @overrides[:alias_drop_list].include?(normalize_key(value)) }
      aliases.uniq!

      operation_headers = headers.grep(/^Operation /)
      operations = operation_headers.map { |header| sanitize_text(data[header]) }.reject(&:empty?).uniq
      malware = parse_malware_list(data['Toolset / Malware'])
      mitre_ids = sanitize_text(data['MITRE ATT&CK']).scan(/G\d{4}/i).map(&:upcase).uniq
      country = @overrides[:country_overrides][row_key] || default_country

      {
        row_key: row_key,
        tab_name: tab_name,
        name: common_name,
        aliases: aliases,
        country: country,
        mitre_ids: mitre_ids,
        operations: operations,
        malware: malware,
        source_links: headers.grep(/^Link/).map { |header| sanitize_link(data[header]) }.compact.uniq.first(20)
      }
    end
  end

  def split_aliases(value)
    sanitize_text(value).split(/[\n,]/).map { |entry| sanitize_text(entry) }.reject(&:empty?)
  end

  def parse_malware_list(value)
    sanitize_text(value).split(/[\n,]/).map { |entry| sanitize_text(entry) }.reject(&:empty?).uniq.first(25)
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

      external_id = sanitize_text(actor['external_id']).upcase
      external_id_lookup[external_id] = name unless external_id.empty?
    end

    [existing_lookup, external_id_lookup, existing_by_name]
  end

  def build_candidates(rows, existing_lookup, external_id_lookup, existing_by_name)
    rows.map do |row|
      explicit_match = @overrides[:match_overrides][row[:row_key]]
      matched_names = if explicit_match
                        [explicit_match]
                      else
                        infer_matches(row, existing_lookup, external_id_lookup).to_a.sort
                      end

      action = if matched_names.empty?
                 'skip'
               elsif matched_names.length == 1 && existing_by_name.key?(matched_names.first)
                 'update'
               else
                 'review'
               end

      row.merge(action: action, matched_actor_names: matched_names, existing_actor_name: matched_names.first)
    end
  end

  def infer_matches(row, existing_lookup, external_id_lookup)
    matches = Set.new
    row[:mitre_ids].each do |mitre_id|
      matches << external_id_lookup[mitre_id] if external_id_lookup[mitre_id]
    end

    (row[:aliases] + [row[:name]]).each do |value|
      existing_lookup[normalize_key(value)].each { |actor_name| matches << actor_name }
    end

    matches
  end

  def build_report(candidates)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      source_url: SOURCE_URL,
      total_rows: candidates.length,
      updates: candidates.count { |candidate| candidate[:action] == 'update' },
      review: candidates.count { |candidate| candidate[:action] == 'review' },
      skipped: candidates.count { |candidate| candidate[:action] == 'skip' },
      actions: candidates.map do |candidate|
        {
          name: candidate[:name],
          tab_name: candidate[:tab_name],
          action: candidate[:action],
          matched_actor_names: candidate[:matched_actor_names],
          mitre_ids: candidate[:mitre_ids],
          operation_count: candidate[:operations].length,
          malware_count: candidate[:malware].length
        }
      end
    }
  end

  def print_report(candidates)
    puts "\n=== APT Groups & Operations Import Plan ==="
    puts "Total rows: #{candidates.length}"
    puts "Updates: #{candidates.count { |candidate| candidate[:action] == 'update' }}"
    puts "Review: #{candidates.count { |candidate| candidate[:action] == 'review' }}"
    puts "Skipped: #{candidates.count { |candidate| candidate[:action] == 'skip' }}"

    candidates.select { |candidate| candidate[:action] == 'update' }.first(20).each do |candidate|
      puts "\nUPDATE: #{candidate[:name]}"
      puts "  Match: #{candidate[:existing_actor_name]}"
      puts "  Tab: #{candidate[:tab_name]}"
      puts "  MITRE IDs: #{candidate[:mitre_ids].join(', ')}" unless candidate[:mitre_ids].empty?
      puts "  Operations: #{candidate[:operations].first(5).join(', ')}" unless candidate[:operations].empty?
      puts "  Malware: #{candidate[:malware].first(5).join(', ')}" unless candidate[:malware].empty?
    end

    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def apply_candidates(candidates, existing_actors)
    existing_by_name = existing_actors.each_with_object({}) { |actor, memo| memo[actor['name']] = actor }

    candidates.each do |candidate|
      next unless candidate[:action] == 'update'

      actor = existing_by_name[candidate[:existing_actor_name]]
      next unless actor

      merge_array_field(actor, 'aliases', candidate[:aliases])
      actor['country'] ||= candidate[:country] if candidate[:country]
      actor['external_id'] ||= candidate[:mitre_ids].first if candidate[:mitre_ids].length == 1
      merge_array_field(actor, 'operations', candidate[:operations])
      merge_malware(actor, candidate[:malware])

      actor['provenance'] ||= {}
      actor['provenance']['apt_groups_operations'] = {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_dataset_url' => SOURCE_URL,
        'sheet_id' => SHEET_ID,
        'tab_name' => candidate[:tab_name],
        'matched_mitre_ids' => candidate[:mitre_ids],
        'source_links' => candidate[:source_links]
      }
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
    end
  end

  def merge_array_field(actor, field, values)
    return if values.nil? || values.empty?

    actor[field] = (Array(actor[field]) + values).map { |value| sanitize_text(value) }.reject(&:empty?).uniq
  end

  def merge_malware(actor, malware_names)
    return if malware_names.nil? || malware_names.empty?

    existing = Array(actor['malware'])
    existing_names = existing.filter_map { |entry| entry['name']&.downcase }.to_set
    malware_names.each do |name|
      next if existing_names.include?(name.downcase)

      existing << { 'name' => name }
      existing_names << name.downcase
    end
    actor['malware'] = existing
  end

  def actor_filter_match?(actor_name)
    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    filters.include?(normalize_key(actor_name))
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_rows] = Array(payload['excluded_rows']).map { |value| normalize_key(value) }.uniq
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

  def normalize_key(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]/, '')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def sanitize_link(value)
    link = sanitize_text(value)
    return nil unless link.match?(%r{\Ahttps?://}i)

    link
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  end
end

AptGroupsOperationsImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
