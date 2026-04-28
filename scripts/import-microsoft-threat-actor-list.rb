#!/usr/bin/env ruby

# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'open3'
require 'optparse'
require 'rexml/document'
require 'set'
require 'time'
require 'uri'
require 'yaml'
require_relative 'actor_store'

class MicrosoftThreatActorListImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/microsoft-threat-actor-list'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/microsoft-threat-actor-list/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'Microsoft Threat Actor List'.freeze
  SOURCE_URL = 'https://download.microsoft.com/download/4/5/2/45208247-c1e9-432d-a9a2-1554d81074d9/microsoft-threat-actor-list.xlsx'.freeze
  SOURCE_ATTRIBUTION = 'Alias cross-reference data was reviewed from the Microsoft Threat Actor List. The spreadsheet is used here as a secondary vendor naming crosswalk, not as a sole authoritative source.'.freeze
  XLSX_FILE = 'microsoft-threat-actor-list.xlsx'.freeze
  XML_NS = { 'main' => 'http://schemas.openxmlformats.org/spreadsheetml/2006/main' }.freeze
  COUNTRY_NAMES = Set.new([
    'Austria',
    'Belarus',
    'China',
    'Iran',
    'Israel',
    'Lebanon',
    'North Korea',
    'Pakistan',
    'Russia',
    'Singapore',
    'Türkiye',
    'Ukraine',
    'United Arab Emirates',
    'United States',
    'Vietnam'
  ]).freeze
  NON_COUNTRY_CATEGORIES = Set.new([
    'Covert network',
    'Financially motivated',
    'Group in development',
    'Influence operations',
    'Private sector offensive actor'
  ]).freeze

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
        ruby scripts/import-microsoft-threat-actor-list.rb fetch [options]
        ruby scripts/import-microsoft-threat-actor-list.rb plan --snapshot PATH [options]
        ruby scripts/import-microsoft-threat-actor-list.rb import --snapshot PATH [options]

      Notes:
        - This importer enriches existing actors only.
        - It additively merges Microsoft names and aliases, blank-country fills, and provenance.
        - It does not create actors or import descriptions, IOCs, malware, or risk levels.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-microsoft-threat-actor-list.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-microsoft-threat-actor-list.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or XLSX file') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict to a specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N rows') { |value| @options[:limit] = value }
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
    xlsx_path = File.join(@options[:output], XLSX_FILE)
    File.binwrite(xlsx_path, http_get(URI.parse(SOURCE_URL)))
    records = parse_xlsx(xlsx_path)

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => records.length,
      'license_status' => 'No explicit license was found in the downloaded workbook metadata; import is limited to attribution-preserving crosswalk metadata.',
      'checksums_sha256' => {
        XLSX_FILE => Digest::SHA256.file(xlsx_path).hexdigest
      }
    }

    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{records.length} Microsoft threat actor rows into #{@options[:output]}"
  end

  def import_snapshot
    records, manifest = load_snapshot
    records = records.first(@options[:limit]) if @options[:limit]

    existing_actors = ActorStore.load_all
    existing_lookup, external_id_lookup, existing_by_name = build_existing_indexes(existing_actors)
    candidates = build_candidates(records, existing_lookup, external_id_lookup, existing_by_name)
    candidates.select! { |candidate| actor_filter_match?(candidate[:existing_actor_name] || candidate[:name]) } unless @options[:actor_filters].empty?

    report = build_report(candidates, manifest)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(candidates, manifest)

    return unless @options[:write]

    apply_candidates(candidates, existing_actors, manifest)
    ActorStore.save_all(existing_actors)
    puts "Applied Microsoft threat actor list enrichments to #{candidates.count { |candidate| candidate[:action] == 'update' }} actors"
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
    xlsx_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], XLSX_FILE) : @options[:snapshot]
    manifest_path = File.join(File.dirname(xlsx_path), 'manifest.yml')
    manifest = File.exist?(manifest_path) ? safe_load_yaml_file(manifest_path) : {}
    [parse_xlsx(xlsx_path), manifest]
  rescue Errno::ENOENT => e
    warn "Snapshot file not found: #{e.message}"
    exit 1
  end

  def parse_xlsx(path)
    shared_strings = parse_shared_strings(zip_entry(path, 'xl/sharedStrings.xml'))
    rows = parse_sheet_rows(zip_entry(path, 'xl/worksheets/sheet1.xml'), shared_strings)
    rows.filter_map { |row| normalize_row(row) }
  end

  def zip_entry(path, entry_name)
    stdout, stderr, status = Open3.capture3('unzip', '-p', path, entry_name)
    return stdout if status.success?

    raise "Unable to read #{entry_name} from #{path}: #{stderr.strip}"
  end

  def parse_shared_strings(xml)
    document = REXML::Document.new(xml)
    strings = []
    REXML::XPath.each(document, '//main:si', XML_NS) do |shared_item|
      text = +''
      REXML::XPath.each(shared_item, './/main:t', XML_NS) { |node| text << node.text.to_s }
      strings << text
    end
    strings
  end

  def parse_sheet_rows(xml, shared_strings)
    document = REXML::Document.new(xml)
    rows = []
    REXML::XPath.each(document, '//main:sheetData/main:row', XML_NS) do |row|
      values = {}
      REXML::XPath.each(row, 'main:c', XML_NS) do |cell|
        column = cell.attributes['r'].to_s[/[A-Z]+/]
        next unless column

        values[column] = cell_value(cell, shared_strings)
      end
      rows << values
    end
    rows
  end

  def cell_value(cell, shared_strings)
    value = REXML::XPath.first(cell, 'main:v', XML_NS)&.text.to_s
    return shared_strings[value.to_i].to_s if cell.attributes['t'] == 's'
    return REXML::XPath.first(cell, 'main:is/main:t', XML_NS)&.text.to_s if cell.attributes['t'] == 'inlineStr'

    value
  end

  def normalize_row(row)
    name = sanitize_text(row['B'])
    return nil if name.empty? || name == 'Threat actor name'

    row_key = normalize_key(name)
    return nil if @overrides[:excluded_rows].include?(row_key)

    aliases = ([name] + split_aliases(row['D'])).reject { |value| @overrides[:alias_drop_list].include?(normalize_key(value)) }.uniq
    country, categories = parse_origin_category(row['C'], row_key)

    {
      row_key: row_key,
      name: name,
      aliases: aliases,
      country: country,
      origin_category: sanitize_text(row['C']),
      categories: categories
    }
  end

  def parse_origin_category(value, row_key)
    override = @overrides[:country_overrides][row_key]
    tokens = sanitize_text(value).split(',').map { |entry| sanitize_text(entry) }.reject(&:empty?)
    country = override || infer_country(tokens)
    categories = tokens.reject { |token| token == country }
    [country, categories]
  end

  def infer_country(tokens)
    tokens.each do |token|
      return token if COUNTRY_NAMES.include?(token)
      return token unless NON_COUNTRY_CATEGORIES.include?(token)
    end
    nil
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
        existing_lookup[key] << name unless key.empty?
      end

      %w[external_id mitre_id].each do |field|
        external_id = sanitize_text(actor[field]).upcase
        external_id_lookup[external_id] = name unless external_id.empty?
      end
    end

    [existing_lookup, external_id_lookup, existing_by_name]
  end

  def build_candidates(records, existing_lookup, external_id_lookup, existing_by_name)
    records.map do |record|
      explicit_match = @overrides[:match_overrides][record[:row_key]]
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
        existing_actor_name: matched_names.first
      )
    end
  end

  def infer_matches(record, existing_lookup, external_id_lookup)
    matches = Set.new
    record[:aliases].each do |value|
      key = normalize_key(value)
      existing_lookup[key].each { |actor_name| matches << actor_name }
      external_id_lookup[value.upcase]&.then { |actor_name| matches << actor_name }
    end
    matches
  end

  def build_report(candidates, manifest)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      source_url: SOURCE_URL,
      source_retrieved_at: manifest['retrieved_at'],
      license_status: manifest['license_status'],
      total_rows: candidates.length,
      updates: candidates.count { |candidate| candidate[:action] == 'update' },
      review: candidates.count { |candidate| candidate[:action] == 'review' },
      skipped: candidates.count { |candidate| candidate[:action] == 'skip' },
      actions: candidates.map do |candidate|
        {
          name: candidate[:name],
          action: candidate[:action],
          matched_actor_names: candidate[:matched_actor_names],
          alias_count: candidate[:aliases].length,
          country: candidate[:country],
          categories: candidate[:categories]
        }
      end
    }
  end

  def print_report(candidates, manifest)
    puts "\n=== Microsoft Threat Actor List Import Plan ==="
    puts "Total rows: #{candidates.length}"
    puts "Updates: #{candidates.count { |candidate| candidate[:action] == 'update' }}"
    puts "Review: #{candidates.count { |candidate| candidate[:action] == 'review' }}"
    puts "Skipped: #{candidates.count { |candidate| candidate[:action] == 'skip' }}"
    puts "License: #{manifest['license_status'] || 'No explicit license found in snapshot metadata.'}"

    candidates.select { |candidate| candidate[:action] == 'update' }.first(20).each do |candidate|
      puts "\nUPDATE: #{candidate[:name]}"
      puts "  Match: #{candidate[:existing_actor_name]}"
      puts "  Aliases: #{candidate[:aliases].first(8).join(', ')}" unless candidate[:aliases].empty?
      puts "  Country: #{candidate[:country]}" if candidate[:country]
      puts "  Categories: #{candidate[:categories].join(', ')}" unless candidate[:categories].empty?
    end

    candidates.select { |candidate| candidate[:action] == 'review' }.first(20).each do |candidate|
      puts "\nREVIEW: #{candidate[:name]}"
      puts "  Matches: #{candidate[:matched_actor_names].join(', ')}"
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

      actor['provenance'] ||= {}
      actor['provenance']['microsoft_threat_actor_list'] = {
        'source_retrieved_at' => manifest['retrieved_at'] || Time.now.utc.iso8601,
        'source_dataset_url' => SOURCE_URL,
        'source_record_id' => candidate[:row_key],
        'license_status' => manifest['license_status'] || 'No explicit license found in snapshot metadata.',
        'microsoft_name' => candidate[:name],
        'origin_category' => candidate[:origin_category],
        'categories' => candidate[:categories]
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

  def split_aliases(value)
    sanitize_text(value).split(/[\n,;]/).map { |entry| sanitize_text(entry) }.reject(&:empty?)
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

MicrosoftThreatActorListImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
