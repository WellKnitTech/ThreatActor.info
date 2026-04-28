#!/usr/bin/env ruby

# frozen_string_literal: true

require 'fileutils'
require 'digest'
require 'json'
require 'net/http'
require 'optparse'
require 'set'
require 'time'
require 'uri'
require 'yaml'
require_relative 'actor_store'
require_relative 'source_precedence'

class MalpediaImporter
  DEFAULT_BASE_URL = 'https://malpedia.caad.fkie.fraunhofer.de'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/malpedia'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/malpedia/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'Malpedia (Fraunhofer FKIE)'.freeze
  SOURCE_SITE = 'https://malpedia.caad.fkie.fraunhofer.de/'.freeze
  LICENSE_NAME = 'CC BY-NC-SA 3.0'.freeze
  LICENSE_URL = 'https://malpedia.caad.fkie.fraunhofer.de/legal'.freeze
  SOURCE_ATTRIBUTION = 'Contains metadata derived from Malpedia by Fraunhofer FKIE. Source: https://malpedia.caad.fkie.fraunhofer.de/'.freeze

  COUNTRY_CODE_MAP = {
    'AE' => 'United Arab Emirates',
    'AR' => 'Argentina',
    'AT' => 'Austria',
    'AU' => 'Australia',
    'BE' => 'Belgium',
    'BH' => 'Bahrain',
    'BO' => 'Bolivia',
    'BR' => 'Brazil',
    'BY' => 'Belarus',
    'CA' => 'Canada',
    'CH' => 'Switzerland',
    'CL' => 'Chile',
    'CN' => 'China',
    'CO' => 'Colombia',
    'CR' => 'Costa Rica',
    'CU' => 'Cuba',
    'CY' => 'Cyprus',
    'CZ' => 'Czech Republic',
    'DE' => 'Germany',
    'DK' => 'Denmark',
    'DO' => 'Dominican Republic',
    'EC' => 'Ecuador',
    'EG' => 'Egypt',
    'ES' => 'Spain',
    'FI' => 'Finland',
    'FR' => 'France',
    'GB' => 'United Kingdom',
    'GE' => 'Georgia',
    'GR' => 'Greece',
    'GT' => 'Guatemala',
    'HN' => 'Honduras',
    'HR' => 'Croatia',
    'HU' => 'Hungary',
    'ID' => 'Indonesia',
    'IE' => 'Ireland',
    'IL' => 'Israel',
    'IN' => 'India',
    'IQ' => 'Iraq',
    'IR' => 'Iran',
    'IT' => 'Italy',
    'JM' => 'Jamaica',
    'JO' => 'Jordan',
    'JP' => 'Japan',
    'KE' => 'Kenya',
    'KP' => 'North Korea',
    'KR' => 'South Korea',
    'KW' => 'Kuwait',
    'KZ' => 'Kazakhstan',
    'LB' => 'Lebanon',
    'LU' => 'Luxembourg',
    'LY' => 'Libya',
    'MA' => 'Morocco',
    'MX' => 'Mexico',
    'MY' => 'Malaysia',
    'NG' => 'Nigeria',
    'NI' => 'Nicaragua',
    'NL' => 'Netherlands',
    'NO' => 'Norway',
    'NZ' => 'New Zealand',
    'OM' => 'Oman',
    'PA' => 'Panama',
    'PE' => 'Peru',
    'PH' => 'Philippines',
    'PK' => 'Pakistan',
    'PL' => 'Poland',
    'PT' => 'Portugal',
    'PY' => 'Paraguay',
    'QA' => 'Qatar',
    'RO' => 'Romania',
    'RS' => 'Serbia',
    'RU' => 'Russia',
    'SA' => 'Saudi Arabia',
    'SE' => 'Sweden',
    'SG' => 'Singapore',
    'SI' => 'Slovenia',
    'SK' => 'Slovakia',
    'SV' => 'El Salvador',
    'SY' => 'Syria',
    'TH' => 'Thailand',
    'TN' => 'Tunisia',
    'TR' => 'Turkey',
    'TW' => 'Taiwan',
    'UA' => 'Ukraine',
    'US' => 'United States',
    'UY' => 'Uruguay',
    'VE' => 'Venezuela',
    'VN' => 'Vietnam',
    'YE' => 'Yemen',
    'ZA' => 'South Africa'
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      base_url: DEFAULT_BASE_URL,
      output: nil,
      snapshot: nil,
      limit: nil,
      actor_filters: [],
      include_details: true,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      write: false,
      report_json: nil
    }
    @overrides = {
      excluded_actor_ids: [],
      match_overrides: {},
      actor_id_overrides: {}
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
        ruby scripts/import-malpedia.rb fetch [options]
        ruby scripts/import-malpedia.rb plan --snapshot PATH [options]
        ruby scripts/import-malpedia.rb import --snapshot PATH [options]

      Notes:
        - This importer is enrichment-focused and only updates existing actors.
        - It does not create new actors or import narrative descriptions.
        - Malware family links are imported only from actor detail snapshots.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-malpedia.rb fetch [options]'
      opts.on('--base-url URL', 'Malpedia base URL') { |value| @options[:base_url] = value }
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--limit N', Integer, 'Fetch only the first N actor IDs') { |value| @options[:limit] = value }
      opts.on('--actor NAME', 'Fetch a specific actor ID (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--[no-]details', 'Fetch per-actor detail payloads (default: true)') { |value| @options[:include_details] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-malpedia.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or actors.json file') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict import to a specific actor name or ID (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N candidate records') { |value| @options[:limit] = value }
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

    actor_ids = Array(http_get_json(build_uri('/api/list/actors')))
    actor_ids = filter_actor_ids(actor_ids)
    actor_ids = actor_ids.first(@options[:limit]) if @options[:limit]

    all_actor_meta = http_get_json(build_uri('/api/get/actors'))
    actor_details = {}
    selected_actors = {}

    if @options[:include_details]
      actor_ids.each do |actor_id|
        detail = http_get_json(build_uri("/api/get/actor/#{URI.encode_www_form_component(actor_id)}"))
        actor_details[actor_id] = detail
        actor_name = detail['value']
        next if actor_name.to_s.empty?

        meta_record = all_actor_meta[actor_name] || {}
        selected_actors[actor_name] = deep_merge(meta_record, detail)
      rescue StandardError => e
        warn "Skipping detail for #{actor_id}: #{e.message}"
      end
    else
      selected_actors = filter_actor_meta_without_details(all_actor_meta, actor_ids)
    end

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_site' => SOURCE_SITE,
      'source_license' => LICENSE_NAME,
      'source_license_url' => LICENSE_URL,
      'source_base_url' => @options[:base_url],
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => selected_actors.length,
      'detail_count' => actor_details.length,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(selected_actors)),
      'details_included' => @options[:include_details],
      'actors_file' => 'actors.json',
      'actor_ids_file' => 'actor_ids.json',
      'actor_details_file' => 'actor_details.json'
    }

    File.write(File.join(@options[:output], 'actor_ids.json'), JSON.pretty_generate(actor_ids) + "\n")
    File.write(File.join(@options[:output], 'actors.json'), JSON.pretty_generate(selected_actors) + "\n")
    File.write(File.join(@options[:output], 'actor_details.json'), JSON.pretty_generate(actor_details) + "\n")
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))

    puts "Fetched #{selected_actors.length} Malpedia actor records into #{@options[:output]}"
  end

  def filter_actor_ids(actor_ids)
    selected = actor_ids.reject { |actor_id| @overrides[:excluded_actor_ids].include?(normalize_key(actor_id)) }
    return selected if @options[:actor_filters].empty?

    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    selected.select { |actor_id| filters.include?(normalize_key(actor_id)) }
  end

  def filter_actor_meta_without_details(all_actor_meta, actor_ids)
    allowed = actor_ids.map { |value| normalize_key(value) }.to_set

    all_actor_meta.each_with_object({}) do |(name, record), memo|
      canonical_name = normalize_key(name)
      actor_id = @overrides[:actor_id_overrides][canonical_name]
      actor_id ||= actor_ids.find { |candidate| normalize_key(candidate) == canonical_name }
      actor_id ||= actor_ids.find { |candidate| normalize_key(candidate).gsub(/\d+$/, '') == canonical_name }
      next unless actor_id && allowed.include?(normalize_key(actor_id))

      memo[name] = record.merge('source_actor_id' => actor_id)
    end
  end

  def import_snapshot
    actors, details = load_snapshot_payloads
    existing_actors = ActorStore.load_all
    existing_lookup = build_existing_lookup(existing_actors)
    candidates = build_candidates(actors, details, existing_lookup)
    candidates = candidates.first(@options[:limit]) if @options[:limit]

    report = build_report(candidates)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(candidates)
    return unless @options[:write]

    apply_candidates(candidates, existing_actors)
    ActorStore.save_all(existing_actors)
    puts "Applied #{candidates.count { |candidate| candidate[:action] == 'update' }} Malpedia enrichments"
  end

  def load_snapshot_payloads
    snapshot_dir = if File.directory?(@options[:snapshot])
                     @options[:snapshot]
                   else
                     File.dirname(@options[:snapshot])
                   end

    actors_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], 'actors.json') : @options[:snapshot]
    details_path = File.join(snapshot_dir, 'actor_details.json')

    actors = JSON.parse(File.read(actors_path))
    details = File.exist?(details_path) ? JSON.parse(File.read(details_path)) : {}
    [actors, details]
  rescue Errno::ENOENT => e
    warn "Snapshot file not found: #{e.message}"
    exit 1
  end

  def build_existing_lookup(existing_actors)
    existing_actors.each_with_object({}) do |actor, memo|
      keys_for_existing_actor(actor).each do |key|
        memo[key] ||= actor
      end
    end
  end

  def keys_for_existing_actor(actor)
    keys = []
    keys << normalize_key(actor['name'])
    Array(actor['aliases']).each { |alias_name| keys << normalize_key(alias_name) }
    keys << normalize_key(actor['url'].to_s.sub(%r{^/}, ''))
    keys.compact.uniq
  end

  def build_candidates(actors, details, existing_lookup)
    actor_pairs = actors.sort_by { |name, _record| name.downcase }
    actor_pairs.filter_map do |name, record|
      next if @options[:actor_filters].any? && !actor_filter_match?(name, record)

      candidate = convert_actor(name, record, details)
      next unless candidate

      match_key = @overrides[:match_overrides][candidate[:canonical_key]] || candidate[:canonical_key]
      existing_actor = existing_lookup[match_key]

      if existing_actor
        candidate[:action] = 'update'
        candidate[:existing_actor_name] = existing_actor['name']
        candidate[:existing_actor] = existing_actor
      else
        candidate[:action] = 'skip'
        candidate[:skip_reason] = 'No existing actor match; Malpedia importer is enrichment-only.'
      end

      candidate
    end
  end

  def actor_filter_match?(name, record)
    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    actor_id = record['source_actor_id'] || record['actor_id']
    filters.include?(normalize_key(name)) || filters.include?(normalize_key(actor_id))
  end

  def convert_actor(name, record, details)
    value = record['value'] || name
    return nil if value.to_s.strip.empty?

    meta = record['meta'] || {}
    actor_id = record['source_actor_id'] || details.find { |_id, payload| payload['value'] == value }&.first || @overrides[:actor_id_overrides][normalize_key(value)]
    detail = actor_id ? details[actor_id] : nil

    aliases = (Array(meta['synonyms']) + [value]).map { |entry| sanitize_text(entry) }.reject(&:empty?).uniq
    country = map_country(meta['country'], meta['cfr-suspected-state-sponsor'])
    sector_focus = normalize_string_array(meta['targeted-sector']) | normalize_string_array(meta['cfr-target-category'])
    targeted_victims = normalize_string_array(meta['cfr-suspected-victims']) | normalize_string_array(meta['suspected-victims'])
    incident_type = normalize_scalar(meta['cfr-type-of-incident']) || normalize_scalar(meta['motive'])
    refs = sanitize_refs(meta['refs'])
    malware = extract_malware_families(detail, aliases)

    {
      name: value,
      canonical_key: normalize_key(value),
      actor_id: actor_id,
      actor_uuid: record['uuid'] || detail&.dig('uuid'),
      actor_url: actor_id ? "#{SOURCE_SITE}actor/#{actor_id}" : SOURCE_SITE,
      aliases: aliases,
      country: country,
      sector_focus: sector_focus,
      targeted_victims: targeted_victims,
      incident_type: incident_type,
      refs: refs,
      malware: malware,
      description: sanitize_text(record['description'] || detail&.dig('description'))
    }
  end

  def map_country(country_code, sponsor)
    code = normalize_scalar(country_code)
    return COUNTRY_CODE_MAP[code] if code && COUNTRY_CODE_MAP.key?(code)

    normalize_scalar(sponsor)
  end

  def normalize_string_array(value)
    Array(value).flatten.filter_map do |entry|
      normalized = sanitize_text(entry)
      normalized unless normalized.empty?
    end.uniq
  end

  def normalize_scalar(value)
    normalized = sanitize_text(value)
    normalized.empty? ? nil : normalized
  end

  def sanitize_refs(value)
    Array(value).filter_map do |ref|
      ref = sanitize_text(ref)
      next unless ref.match?(%r{\Ahttps?://}i)

      ref
    end.uniq
  end

  def extract_malware_families(detail, actor_aliases)
    return [] unless detail.is_a?(Hash)

    attribution_keys = actor_aliases.map { |entry| normalize_key(entry) }.to_set
    families = detail['families'] || {}

    families.values.each_with_object([]) do |family, memo|
      next unless family.is_a?(Hash)

      attributions = Array(family['attribution']).map { |entry| normalize_key(entry) }.to_set
      next if attributions.empty? || (attributions & attribution_keys).empty?

      family_name = sanitize_text(family['common_name'])
      next if family_name.empty?

      memo << { 'name' => family_name }
    end.uniq { |entry| entry['name'].downcase }
  end

  def build_report(candidates)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      source_site: SOURCE_SITE,
      total_candidates: candidates.length,
      updates: candidates.count { |candidate| candidate[:action] == 'update' },
      skipped: candidates.count { |candidate| candidate[:action] == 'skip' },
      actions: candidates.map do |candidate|
        {
          name: candidate[:name],
          actor_id: candidate[:actor_id],
          action: candidate[:action],
          matched_actor: candidate[:existing_actor_name],
          malware_count: candidate[:malware].length,
          refs_count: candidate[:refs].length,
          skip_reason: candidate[:skip_reason]
        }
      end
    }
  end

  def print_report(candidates)
    puts "\n=== Malpedia Import Plan ==="
    puts "Total: #{candidates.length} (#{candidates.count { |candidate| candidate[:action] == 'update' }} updates, #{candidates.count { |candidate| candidate[:action] == 'skip' }} skipped)"

    candidates.each do |candidate|
      puts "\n#{candidate[:action].upcase}: #{candidate[:name]}"
      puts "  Actor ID: #{candidate[:actor_id] || 'N/A'}"
      if candidate[:action] == 'update'
        puts "  Match: #{candidate[:existing_actor_name]}"
        puts "  Aliases to merge: #{candidate[:aliases].length}"
        puts "  Malware families: #{candidate[:malware].map { |entry| entry['name'] }.first(5).join(', ')}" unless candidate[:malware].empty?
      else
        puts "  Skip reason: #{candidate[:skip_reason]}"
      end
    end

    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def apply_candidates(candidates, existing_actors)
    candidates.each do |candidate|
      next unless candidate[:action] == 'update'

      actor = candidate[:existing_actor]
      SourcePrecedence.normalize_actor!(actor)
      updates = {}
      merge_array_field(actor, 'aliases', candidate[:aliases])
      actor['country'] ||= candidate[:country] if candidate[:country]
      merge_array_field(actor, 'sector_focus', candidate[:sector_focus])
      merge_array_field(actor, 'targeted_victims', candidate[:targeted_victims])
      actor['incident_type'] ||= candidate[:incident_type] if candidate[:incident_type]
      updates = SourcePrecedence.apply_takeover!(
        updates,
        actor,
        source_name: SOURCE_NAME,
        source_attribution: SOURCE_ATTRIBUTION,
        source_record_url: candidate[:actor_url],
        source_license: LICENSE_NAME,
        source_license_url: LICENSE_URL,
        automated_description: candidate[:description],
        automated_label: candidate[:name] || SOURCE_NAME
      )
      actor.merge!(updates)
      merge_malware(actor, candidate)
      actor['provenance'] ||= {}
      actor['provenance']['malpedia'] = {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_record_id' => candidate[:actor_id],
        'source_uuid' => candidate[:actor_uuid],
        'source_dataset_url' => "#{@options[:base_url]}/api/get/actors",
        'source_record_url' => candidate[:actor_url]
      }
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
      actor['source_license'] ||= LICENSE_NAME
      actor['source_license_url'] ||= LICENSE_URL
      actor['source_record_url'] ||= candidate[:actor_url] if candidate[:actor_url]
    end
  end

  def merge_array_field(actor, field, values)
    return if values.nil? || values.empty?

    actor[field] = (Array(actor[field]) + values).map { |entry| sanitize_text(entry) }.reject(&:empty?).uniq
  end

  def merge_malware(actor, candidate)
    malware_entries = candidate[:malware]
    return if malware_entries.nil? || malware_entries.empty?

    incoming = malware_entries.map do |entry|
      SourcePrecedence.build_malware_entry(
        entry['name'],
        source_name: SOURCE_NAME,
        source_attribution: SOURCE_ATTRIBUTION,
        source_record_url: candidate[:actor_url],
        provenance: {
          'source_dataset_url' => "#{@options[:base_url]}/api/get/actors",
          'source_actor_id' => candidate[:actor_id]
        }
      )
    end
    actor['malware'] = SourcePrecedence.merge_malware_entries(actor['malware'], incoming)
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_actor_ids] = Array(payload['excluded_actor_ids']).map { |value| normalize_key(value) }.compact.uniq
    @overrides[:match_overrides] = normalize_override_hash(payload['match_overrides'])
    @overrides[:actor_id_overrides] = normalize_override_hash(payload['actor_id_overrides'], preserve_values: true)
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = normalize_key(key)
      next if normalized_key.nil? || normalized_key.empty?

      memo[normalized_key] = preserve_values ? mapped_value : normalize_key(mapped_value)
    end
  end

  def normalize_key(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]/, '')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def deep_merge(left, right)
    return left unless right.is_a?(Hash)
    return right unless left.is_a?(Hash)

    left.merge(right) do |_key, old_value, new_value|
      if old_value.is_a?(Hash) && new_value.is_a?(Hash)
        deep_merge(old_value, new_value)
      else
        new_value.nil? || new_value == '' ? old_value : new_value
      end
    end
  end

  def build_uri(path)
    URI.join(@options[:base_url], path)
  end

  def http_get_json(uri)
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
      http.request(Net::HTTP::Get.new(uri))
    end

    raise "HTTP #{response.code} for #{uri}" unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  end
end

MalpediaImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
