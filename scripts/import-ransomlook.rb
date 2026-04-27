#!/usr/bin/env ruby

require 'fileutils'
require 'digest'
require 'json'
require 'net/http'
require 'optparse'
require 'time'
require 'uri'
require 'yaml'
require_relative 'actor_store'

class RansomLookImporter
  PAGE_DIR = '_threat_actors'.freeze
  DEFAULT_BASE_URL = 'https://www.ransomlook.io'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/ransomlook'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/ransomlook/mapping_overrides.yml'.freeze
  LICENSE_NAME = 'CC BY 4.0'.freeze
  LICENSE_URL = 'https://creativecommons.org/licenses/by/4.0/'.freeze
  SOURCE_NAME = 'RansomLook'.freeze
  SOURCE_REPOSITORY = 'https://github.com/RansomLook/RansomLook'.freeze
  REQUIRED_HEADINGS = [
    'Introduction',
    'Activities and Tactics',
    'Notable Campaigns',
    'Tactics, Techniques, and Procedures (TTPs)',
    'Notable Indicators of Compromise (IOCs)',
    'Malware and Tools',
    'Attribution and Evidence',
    'References'
  ].freeze
  EXCLUDED_GROUP_KEYS = %w[
    handala
    alp001
  ].freeze
  EXCLUDED_DESCRIPTION_PATTERNS = [
    /not a ransomware group/i,
    /appears unreliable/i,
    /remove entries/i
  ].freeze
  MATCH_OVERRIDES = {
    'clop' => 'cl0p',
    'coinbasecartel' => 'coinbasecartel',
    'coinbase cartel' => 'coinbasecartel',
    'inc ransom' => 'incransom',
    'incransom' => 'incransom',
    'lockbit3' => 'lockbit',
    'lockbit4' => 'lockbit',
    'lockbit5' => 'lockbit',
    'space bears' => 'spacebears',
    'spacebears' => 'spacebears',
    'silent ransom' => 'silentransomgroup',
    'silentransomgroup' => 'silentransomgroup',
    'the gentlemen' => 'thegentlemen',
    'thegentlemen' => 'thegentlemen'
  }.freeze
  DISPLAY_NAME_OVERRIDES = {
    'ailock' => 'AiLock',
    'coinbasecartel' => 'CoinbaseCartel',
    'incransom' => 'Inc Ransom',
    'qilin' => 'Qilin',
    'silentransomgroup' => 'SilentRansomGroup',
    'thegentlemen' => 'The Gentlemen'
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      base_url: DEFAULT_BASE_URL,
      output: nil,
      groups: [],
      limit: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      snapshot: nil,
      write: false,
      new_only: false,
      actor_filters: [],
      report_json: nil
    }
    @overrides = {
      excluded_group_keys: EXCLUDED_GROUP_KEYS.dup,
      excluded_description_patterns: EXCLUDED_DESCRIPTION_PATTERNS.dup,
      match_overrides: MATCH_OVERRIDES.dup,
      display_name_overrides: DISPLAY_NAME_OVERRIDES.dup
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      import_snapshot
    when 'import'
      parse_import_options
      @options[:write] = true
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
        ruby scripts/import-ransomlook.rb fetch [options]
        ruby scripts/import-ransomlook.rb plan --snapshot PATH [options]
        ruby scripts/import-ransomlook.rb import --snapshot PATH [options]

      Commands:
        fetch   Create a local RansomLook snapshot for later review/import.
        plan    Read a snapshot and print the changes that would be made.
        import  Apply a snapshot to `_data/actors/*.yml` and `_threat_actors/*.md`.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-ransomlook.rb fetch [options]'
      opts.on('--base-url URL', 'RansomLook base URL') { |value| @options[:base_url] = value }
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
      opts.on('--group NAME', 'Fetch a specific group name (repeatable)') { |value| @options[:groups] << value }
      opts.on('--limit N', Integer, 'Fetch only the first N groups') { |value| @options[:limit] = value }
      opts.on('--export', 'Use /api/export/0 with RANSOMLOOK_API_KEY if available') { @options[:use_export] = true }
    end

    parser.parse!(@argv)
    load_overrides
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-ransomlook.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or groups.json file') { |value| @options[:snapshot] = value }
      opts.on('--base-url URL', 'RansomLook base URL') { |value| @options[:base_url] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
      opts.on('--write', 'Apply the changes instead of previewing them') { @options[:write] = true }
      opts.on('--new-only', 'Only create new actors; do not update existing actors') { @options[:new_only] = true }
      opts.on('--actor NAME', 'Restrict import to a specific actor/group (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N candidate records') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write a machine-readable report') { |value| @options[:report_json] = value }
    end

    parser.parse!(@argv)
    load_overrides
    return if @options[:snapshot]

    warn 'A snapshot path is required for plan/import.'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])

    records = if @options[:use_export]
                fetch_export_records
              else
                fetch_public_group_records
              end

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_repository' => SOURCE_REPOSITORY,
      'source_license' => LICENSE_NAME,
      'source_license_url' => LICENSE_URL,
      'source_base_url' => @options[:base_url],
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => records.length,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(records)),
      'fetch_mode' => @options[:use_export] ? 'export' : 'public-api',
      'groups_file' => 'groups.json'
    }

    File.write(File.join(@options[:output], 'groups.json'), JSON.pretty_generate(records) + "\n")
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))

    puts "Fetched #{records.length} RansomLook group records into #{@options[:output]}"
  end

  def fetch_export_records
    api_key = ENV['RANSOMLOOK_API_KEY']
    if api_key.to_s.empty?
      warn 'RANSOMLOOK_API_KEY is required for --export mode.'
      exit 1
    end

    uri = build_uri('/api/export/0')
    payload = http_get_json(uri, 'Authorization' => api_key)
    Array(payload).map { |record| normalize_export_record(record) }.compact
  end

  def fetch_public_group_records
    group_names = @options[:groups]
    group_names = Array(http_get_json(build_uri('/api/groups'))) if group_names.empty?
    group_names = group_names.first(@options[:limit]) if @options[:limit]

    group_names.filter_map do |group_name|
      payload = http_get_json(build_uri("/api/group/#{URI.encode_www_form_component(group_name)}"))
      normalize_public_group_record(payload, group_name)
    rescue StandardError => e
      warn "Skipping #{group_name}: #{e.message}"
      nil
    end
  end

  def import_snapshot
    records = load_snapshot_records
    records = filter_records(records)
    records = records.first(@options[:limit]) if @options[:limit]

    existing_actors = ActorStore.load_all
    existing_pages = load_pages
    evaluation = evaluate_records(records, existing_actors)

    write_report(evaluation)
    print_report(evaluation)

    return unless @options[:write]

    apply_results(evaluation, existing_actors, existing_pages)
    puts "Applied #{evaluation.count { |item| item[:action] == 'create' }} new actors and #{evaluation.count { |item| item[:action] == 'update' }} updates"
  end

  def load_snapshot_records
    groups_path = if File.directory?(@options[:snapshot])
                    File.join(@options[:snapshot], 'groups.json')
                  else
                    @options[:snapshot]
                  end

    payload = JSON.parse(File.read(groups_path))
    Array(payload).map { |record| normalize_snapshot_record(record) }.compact
  rescue Errno::ENOENT
    warn "Snapshot file not found: #{groups_path}"
    exit 1
  end

  def filter_records(records)
    return records if @options[:actor_filters].empty?

    filters = @options[:actor_filters].map { |value| canonical_key(value) }
    records.select { |record| filters.include?(record[:canonical_key]) }
  end

  def evaluate_records(records, existing_actors)
    match_index = build_match_index(existing_actors)

    records.map do |record|
      match = match_record(record, match_index)
      build_evaluation(record, match, existing_actors)
    end
  end

  def build_match_index(existing_actors)
    index = {
      by_key: {},
      by_url: {}
    }

    existing_actors.each_with_index do |actor, position|
      keys_for_actor(actor).each do |key|
        index[:by_key][key] ||= []
        index[:by_key][key] << position
      end
      index[:by_url][actor['url']] = position
    end

    index
  end

  def keys_for_actor(actor)
    ([actor['name']] + Array(actor['aliases']) + [actor['url']]).filter_map do |value|
      canonical_key(value)
    end.uniq
  end

  def match_record(record, index)
    candidate_keys = [record[:canonical_key], canonical_key(record[:slug])]
    candidate_keys.concat(record[:aliases].map { |value| canonical_key(value) })
    candidate_keys.compact!
    candidate_keys.uniq!

    matches = candidate_keys.flat_map { |key| index[:by_key][key] || [] }.uniq
    return { confidence: 'high', position: matches.first } if matches.length == 1
    return { confidence: 'ambiguous', positions: matches } if matches.length > 1

    nil
  end

  def build_evaluation(record, match, existing_actors)
    if skip_record?(record)
      return {
        action: 'skip',
        reason: 'excluded-or-low-confidence',
        record: record
      }
    end

    unless match
      return {
        action: 'create',
        record: record,
        actor: build_new_actor(record)
      }
    end

    if match[:confidence] == 'ambiguous'
      return {
        action: 'review',
        reason: 'ambiguous-match',
        record: record,
        matches: match[:positions].map { |position| existing_actors[position]['name'] }
      }
    end

    existing_actor = existing_actors[match[:position]]
    updates = build_actor_updates(existing_actor, record)
    updates = {} if @options[:new_only]

    {
      action: updates.empty? ? 'skip' : 'update',
      reason: updates.empty? ? 'no-changes' : nil,
      record: record,
      match_position: match[:position],
      existing_name: existing_actor['name'],
      updates: updates
    }
  end

  def skip_record?(record)
    return true if @overrides[:excluded_group_keys].include?(record[:canonical_key])

    @overrides[:excluded_description_patterns].any? { |pattern| record[:description].match?(pattern) }
  end

  def build_new_actor(record)
    {
      'name' => record[:display_name],
      'aliases' => record[:aliases],
      'description' => build_description(record),
      'url' => record[:url],
      'last_activity' => record[:last_activity],
      'source_name' => SOURCE_NAME,
      'source_attribution' => source_attribution_text,
      'source_record_url' => record[:source_record_url],
      'source_license' => LICENSE_NAME,
      'source_license_url' => LICENSE_URL,
      'provenance' => build_provenance(record)
    }.reject { |_key, value| value.nil? || value == [] }
  end

  def build_actor_updates(existing_actor, record)
    updates = {}

    merged_aliases = (Array(existing_actor['aliases']) + record[:aliases]).uniq.sort
    updates['aliases'] = merged_aliases if merged_aliases != Array(existing_actor['aliases'])

    refreshed_description = build_description(record)
    if existing_actor['source_name'] == SOURCE_NAME && should_refresh_imported_description?(existing_actor['description'], refreshed_description)
      updates['description'] = refreshed_description
    end

    if record[:last_activity] && newer_year?(existing_actor['last_activity'], record[:last_activity])
      updates['last_activity'] = record[:last_activity]
    end

    if existing_actor['source_name'].to_s.empty?
      updates['source_name'] = SOURCE_NAME
      updates['source_attribution'] = source_attribution_text
      updates['source_license'] = LICENSE_NAME
      updates['source_license_url'] = LICENSE_URL
    end

    if record[:source_record_url] && (existing_actor['source_record_url'].to_s.empty? || existing_actor['source_name'] == SOURCE_NAME)
      updates['source_record_url'] = record[:source_record_url]
    end

    provenance = existing_actor['provenance'].is_a?(Hash) ? existing_actor['provenance'].dup : {}
    merged_provenance = provenance.merge(build_provenance(record))
    updates['provenance'] = merged_provenance if merged_provenance != provenance

    updates
  end

  def newer_year?(current_year, candidate_year)
    return true if current_year.to_s.empty?

    candidate_year.to_i > current_year.to_i
  end

  def build_provenance(record)
    {
      'source_dataset_url' => record[:source_dataset_url],
      'source_record_id' => record[:source_record_id],
      'source_retrieved_at' => record[:source_retrieved_at],
      'source_transforms' => record[:source_transforms]
    }.reject { |_key, value| value.nil? || value == [] || value == '' }
  end

  def build_description(record)
    cleaned = sanitize_text(record[:description])
    return cleaned unless cleaned.empty?

    if record[:raas]
      "#{record[:display_name]} is an active ransomware-as-a-service operation tracked by RansomLook."
    else
      "#{record[:display_name]} is an active extortion or ransomware group tracked by RansomLook."
    end
  end

  def source_attribution_text
    'Contains data derived from RansomLook, used under CC BY 4.0. Source: https://www.ransomlook.io/'
  end

  def apply_results(evaluation, existing_actors, existing_pages)
    evaluation.each do |item|
      case item[:action]
      when 'create'
        actor = item[:actor]
        existing_actors << actor
        write_page(page_path_for(actor['url']), build_front_matter(actor), build_new_page_body(actor))
      when 'update'
        actor = existing_actors[item[:match_position]]
        actor.merge!(item[:updates])
        synchronize_existing_page(actor, existing_pages)
      end
    end

    write_actor_yaml(existing_actors)
  end

  def synchronize_existing_page(actor, existing_pages)
    path = page_path_for(actor['url'])
    page = existing_pages[path] || parse_page(path)
    updated_front_matter = page[:front_matter].merge(build_front_matter(actor))
    write_page(path, updated_front_matter, page[:body])
  end

  def build_front_matter(actor)
    front_matter = {
      'layout' => 'threat_actor',
      'title' => actor['name'],
      'aliases' => actor['aliases'] || [],
      'description' => actor['description'],
      'permalink' => "#{actor['url']}/"
    }

    %w[country sector_focus first_seen last_activity risk_level source_name source_attribution source_record_url source_license source_license_url].each do |field|
      value = actor[field]
      front_matter[field] = value unless value.nil? || value == [] || value == ''
    end

    front_matter
  end

  def build_new_page_body(actor)
    display_name = actor['name']
    source_url = actor['source_record_url']

    <<~MARKDOWN.strip
      ## Introduction
      #{display_name} is tracked by RansomLook as an active extortion or ransomware actor. This page is an imported seed profile and should be expanded with additional source-backed reporting.

      ## Activities and Tactics
      #{display_name} has publicly tracked activity in RansomLook datasets. Additional operational detail should be added here as the profile is curated with higher-confidence reporting.

      ## Notable Campaigns
      1. **Public Disclosure Activity**: RansomLook has tracked public activity associated with this actor.
      2. **Seed Profile Import**: This entry was created from a RansomLook-derived snapshot and is intended as a starting point for further enrichment.

      ## Tactics, Techniques, and Procedures (TTPs)
      No ATT&CK-mapped TTP data was imported automatically for this actor. Add source-backed techniques here during later curation.

      ## Notable Indicators of Compromise (IOCs)
      No verified IOC data was imported automatically for #{display_name}. This section is intentionally reserved for stable, source-backed indicators specific to this actor.

      ## Malware and Tools
      No stable malware or tool data was imported automatically for this actor. Add source-backed malware and tooling details here during later curation.

      ## Attribution and Evidence
      Data for this seed profile was derived from RansomLook and adapted for this repository under CC BY 4.0. Any edits, normalization, and interpretation in this page are by this project and are not endorsed by RansomLook.

      ## References
      1. [RansomLook group profile](#{source_url})
      2. [RansomLook repository and license notice](#{SOURCE_REPOSITORY})

      ## External Links
      - [RansomLook](https://www.ransomlook.io/)
    MARKDOWN
  end

  def write_actor_yaml(actors)
    ActorStore.save_all(actors)
  end

  def serialize_actor(actor)
    lines = []
    lines << "- name: #{yaml_scalar(actor['name'])}"
    lines << "  aliases: #{yaml_inline_array(actor['aliases'] || [])}"
    lines << "  description: #{yaml_scalar(actor['description'])}"
    lines << "  url: #{yaml_scalar(actor['url'])}"

    %w[country first_seen last_activity risk_level attribution source_name source_attribution source_record_url source_license source_license_url].each do |field|
      next unless actor[field]

      lines << "  #{field}: #{yaml_scalar(actor[field])}"
    end

    lines << "  sector_focus: #{yaml_inline_array(actor['sector_focus'])}" if actor['sector_focus']

    if actor['provenance'].is_a?(Hash) && !actor['provenance'].empty?
      lines << '  provenance:'
      actor['provenance'].each do |key, value|
        next if value.nil? || value == [] || value == ''

        if value.is_a?(Array)
          lines << "    #{key}: #{yaml_inline_array(value)}"
        else
          lines << "    #{key}: #{yaml_scalar(value)}"
        end
      end
    end

    lines.join("\n") + "\n"
  end

  def yaml_inline_array(values)
    Array(values).map(&:to_s).uniq.to_json
  end

  def yaml_scalar(value)
    value.to_json
  end

  def write_page(path, front_matter, body)
    FileUtils.mkdir_p(File.dirname(path))

    content = []
    content << '---'
    front_matter.each do |key, value|
      next if value.nil? || value == ''

      content << if value.is_a?(Array)
                   "#{key}: #{yaml_inline_array(value)}"
                 else
                   "#{key}: #{yaml_scalar(value)}"
                 end
    end
    content << '---'
    content << ''
    content << body.strip
    content << ''

    File.write(path, content.join("\n"))
  end

  def load_pages
    Dir.glob(File.join(PAGE_DIR, '*.md')).each_with_object({}) do |path, pages|
      pages[path] = parse_page(path)
    end
  end

  def parse_page(path)
    content = File.read(path)
    match = content.match(/\A---\s*\n(.*?)\n---\s*\n?(.*)\z/m)
    raise "Invalid front matter in #{path}" unless match

    {
      front_matter: safe_load_yaml(match[1]) || {},
      body: match[2].strip
    }
  end

  def page_path_for(url)
    File.join(PAGE_DIR, "#{url.sub(%r{^/}, '')}.md")
  end

  def print_report(evaluation)
    grouped = evaluation.group_by { |item| item[:action] }
    puts "Create: #{grouped.fetch('create', []).length}"
    puts "Update: #{grouped.fetch('update', []).length}"
    puts "Skip: #{grouped.fetch('skip', []).length}"
    puts "Review: #{grouped.fetch('review', []).length}"

    evaluation.each do |item|
      case item[:action]
      when 'create'
        puts "[CREATE] #{item[:actor]['name']} -> #{item[:actor]['url']}"
      when 'update'
        puts "[UPDATE] #{item[:existing_name]} (#{item[:updates].keys.join(', ')})"
      when 'review'
        puts "[REVIEW] #{item[:record][:display_name]} -> #{item[:matches].join(', ')}"
      when 'skip'
        puts "[SKIP] #{item[:record][:display_name]} (#{item[:reason]})"
      end
    end
  end

  def write_report(evaluation)
    return unless @options[:report_json]

    payload = evaluation.map do |item|
      item.transform_values do |value|
        value.is_a?(Symbol) ? value.to_s : value
      end
    end
    File.write(@options[:report_json], JSON.pretty_generate(payload) + "\n")
  end

  def normalize_snapshot_record(record)
    if record.is_a?(Hash) && record['canonical_key']
      return {
        raw_name: record['raw_name'] || record['display_name'] || record['name'],
        display_name: record['display_name'] || prettify_name(record['raw_name'] || record['name']),
        canonical_key: record['canonical_key'],
        aliases: Array(record['aliases']).map { |value| sanitize_text(value) }.reject(&:empty?).uniq.sort,
        description: sanitize_text(record['description']),
        url: record['url'] || "/#{slugify(record['display_name'] || record['name'])}",
        last_activity: extract_year(record['last_activity']),
        raas: record['raas'],
        source_record_id: record['source_record_id'] || record['canonical_key'],
        source_record_url: record['source_record_url'],
        source_dataset_url: record['source_dataset_url'] || build_uri('/api/groups').to_s,
        source_retrieved_at: record['source_retrieved_at'] || Time.now.utc.iso8601,
        source_transforms: Array(record['source_transforms'])
      }
    end

    return normalize_public_group_record(record, record['name']) if record.is_a?(Hash)
    return normalize_public_group_record(record.first, record.first['name']) if record.is_a?(Array) && record.first.is_a?(Hash)

    nil
  end

  def normalize_export_record(record)
    group = record.is_a?(Array) ? record.first : record
    return nil unless group.is_a?(Hash)

    normalize_group_hash(group)
  end

  def normalize_public_group_record(payload, fallback_name)
    group = payload.is_a?(Array) ? payload.first : payload
    return nil unless group.is_a?(Hash)

    normalize_group_hash(group.merge('name' => fallback_name))
  end

  def normalize_group_hash(group)
    raw_name = group['name'].to_s.strip
    return nil if raw_name.empty?

    canonical = canonical_key(raw_name)
    mapped_key = canonical_map_key(canonical)
    display_name = @overrides[:display_name_overrides][mapped_key] || prettify_name(raw_name)
    source_record_url = group['source_record_url'] || group['url'] || build_uri("/group/#{URI.encode_www_form_component(mapped_key)}").to_s
    description = first_non_empty(group['meta'], group['description'])
    aliases = normalize_aliases(group, display_name)
    source_retrieved_at = group['source_retrieved_at'] || Time.now.utc.iso8601

    {
      raw_name: raw_name,
      display_name: display_name,
      canonical_key: mapped_key,
      aliases: aliases,
      description: sanitize_text(description),
      url: "/#{slugify(display_name)}",
      last_activity: extract_year(first_non_empty(group['date'], group['updated'], group['last_activity'])),
      raas: raas_value(group),
      source_record_id: mapped_key,
      source_record_url: source_record_url,
      source_dataset_url: build_uri('/api/groups').to_s,
      source_retrieved_at: source_retrieved_at,
      source_transforms: [
        'normalized-name',
        'deduplicated-aliases',
        'omitted-volatile-iocs',
        'adapted-for-threatactor-info'
      ]
    }
  end

  def normalize_aliases(group, display_name)
    aliases = []
    aliases.concat(Array(group['aliases']))
    aliases.concat(Array(group['altname']))
    aliases << group['slug'] if group['slug']
    aliases << group['group_name'] if group['group_name']

    aliases.map { |value| sanitize_text(value) }
           .reject(&:empty?)
           .reject { |value| canonical_key(value) == canonical_key(display_name) }
           .uniq
           .sort
  end

  def canonical_map_key(value)
    @overrides[:match_overrides][value] || value
  end

  def canonical_key(value)
    return nil if value.nil?

    value.to_s
         .downcase
         .tr('0$@', 'osa')
         .gsub(/[^a-z0-9]+/, '')
         .strip
  end

  def slugify(value)
    value.to_s
         .downcase
         .tr('0$@', 'osa')
         .gsub(/[^a-z0-9]+/, '-')
         .gsub(/\A-|-\z/, '')
         .gsub(/-+/, '-')
  end

  def prettify_name(value)
    mapped = @overrides[:display_name_overrides][canonical_map_key(canonical_key(value))]
    return mapped if mapped

    return value if value.match?(/[A-Z]/) && value.match?(/[a-z]/)

    value.split(/[^A-Za-z0-9]+/).reject(&:empty?).map do |part|
      part.match?(/\A[a-z]+\z/) ? part.capitalize : part
    end.join(' ')
  end

  def sanitize_text(value)
    value.to_s
         .gsub(/<br\s*\/?>/i, ' ')
         .gsub(/<[^>]+>/, ' ')
         .gsub(/&quot;/, '"')
         .gsub(/&#39;/, "'")
         .gsub(/&amp;/, '&')
         .gsub(/\s+/, ' ')
         .strip
  end

  def should_refresh_imported_description?(current_description, refreshed_description)
    return true if current_description.to_s.match?(/<[^>]+>/)

    current = sanitize_text(current_description)
    return true if current.empty?

    current != refreshed_description && current.start_with?('History and Origins')
  end

  def extract_year(value)
    match = value.to_s.match(/(20\d{2}|19\d{2})/)
    match && match[1]
  end

  def raas_value(group)
    return group['raas'] unless group['raas'].nil?
    return group.dig('type', 'raas') unless group['type'].nil?

    nil
  end

  def first_non_empty(*values)
    values.find { |value| !sanitize_text(value).empty? }
  end

  def build_uri(path)
    URI.join(@options[:base_url], path)
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}

    @overrides[:excluded_group_keys] = (@overrides[:excluded_group_keys] + Array(payload['excluded_group_keys']).map { |value| canonical_key(value) }).compact.uniq
    @overrides[:excluded_description_patterns] = @overrides[:excluded_description_patterns] + Array(payload['excluded_description_patterns']).map { |value| Regexp.new(value, Regexp::IGNORECASE) }
    @overrides[:match_overrides] = @overrides[:match_overrides].merge(normalize_override_hash(payload['match_overrides']))
    @overrides[:display_name_overrides] = @overrides[:display_name_overrides].merge(normalize_override_hash(payload['display_name_overrides'], preserve_values: true))
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = canonical_key(key)
      next if normalized_key.nil? || normalized_key.empty?

      memo[normalized_key] = preserve_values ? mapped_value : canonical_key(mapped_value)
    end
  end

  def http_get_json(uri, headers = {})
    request = Net::HTTP::Get.new(uri)
    headers.each { |key, value| request[key] = value }

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
      http.request(request)
    end

    unless response.is_a?(Net::HTTPSuccess)
      raise "HTTP #{response.code} for #{uri}"
    end

    JSON.parse(response.body)
  end

  def safe_load_yaml_file(path)
    safe_load_yaml(File.read(path))
  end

  def safe_load_yaml(content)
    YAML.safe_load(content, permitted_classes: [], aliases: true)
  end
end

RansomLookImporter.new(ARGV).run
