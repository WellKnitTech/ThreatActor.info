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

# Importer for MISP Galaxy threat actor data
# Source: https://github.com/MISP/misp-galaxy
class MispGalaxyImporter
  DEFAULT_OVERRIDES_FILE = 'data/imports/misp-galaxy/mapping_overrides.yml'.freeze
  PAGE_DIR = '_threat_actors'.freeze
  SOURCE_NAME = 'MISP Galaxy'.freeze
  SOURCE_REPOSITORY = 'https://github.com/MISP/misp-galaxy'.freeze
  SOURCE_BASE_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters'.freeze
  DEFAULT_CLUSTER = 'threat-actor.json'.freeze
  SOURCE_ATTRIBUTION = 'Data sourced from MISP Galaxy threat-actor cluster (CC0 licensed)'.freeze
  LICENSE_NAME = 'Apache 2.0 / CC0'.freeze
  LICENSE_URL = 'https://github.com/MISP/misp-galaxy/blob/main/README.md#license'.freeze

  # ISO 3166-1 alpha-2 to full country name mapping
  COUNTRY_CODE_MAP = {
    'CN' => 'China',
    'RU' => 'Russia',
    'IR' => 'Iran',
    'KP' => 'North Korea',
    'KR' => 'South Korea',
    'US' => 'United States',
    'GB' => 'United Kingdom',
    'UA' => 'Ukraine',
    'BY' => 'Belarus',
    'VN' => 'Vietnam',
    'IN' => 'India',
    'PK' => 'Pakistan',
    'BR' => 'Brazil',
    'ID' => 'Indonesia',
    'MY' => 'Malaysia',
    'TH' => 'Thailand',
    'PH' => 'Philippines',
    'SG' => 'Singapore',
    'JP' => 'Japan',
    'AU' => 'Australia',
    'NZ' => 'New Zealand',
    'CA' => 'Canada',
    'MX' => 'Mexico',
    'FR' => 'France',
    'DE' => 'Germany',
    'IT' => 'Italy',
    'ES' => 'Spain',
    'NL' => 'Netherlands',
    'BE' => 'Belgium',
    'CH' => 'Switzerland',
    'AT' => 'Austria',
    'PL' => 'Poland',
    'SE' => 'Sweden',
    'NO' => 'Norway',
    'DK' => 'Denmark',
    'FI' => 'Finland',
    'IE' => 'Ireland',
    'PT' => 'Portugal',
    'GR' => 'Greece',
    'TR' => 'Turkey',
    'IL' => 'Israel',
    'SA' => 'Saudi Arabia',
    'AE' => 'United Arab Emirates',
    'EG' => 'Egypt',
    'NG' => 'Nigeria',
'ZA' => 'South Africa',
    'KE' => 'Kenya',
    'AR' => 'Argentina',
    'CL' => 'Chile',
    'CO' => 'Colombia',
    'PE' => 'Peru',
    'BO' => 'Bolivia',
    'PY' => 'Paraguay',
    'UY' => 'Uruguay',
    'EC' => 'Ecuador',
    'DO' => 'Dominican Republic',
    'PA' => 'Panama',
    'CR' => 'Costa Rica',
    'GT' => 'Guatemala',
    'HN' => 'Honduras',
    'NI' => 'Nicaragua',
    'SV' => 'El Salvador',
    'JM' => 'Jamaica',
    'TT' => 'Trinidad and Tobago',
    'BB' => 'Barbados',
    'BS' => 'Bahamas',
    'BZ' => 'Belize',
    'GY' => 'Guyana',
    'SR' => 'Suriname'
  }.freeze

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

  # MISP fields that should NOT overwrite existing content
  PROTECTED_FIELDS = %w[name aliases description].freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      write: false,
      snapshot: nil,
      output: nil,
      clusters: [],
      actor_filters: [],
      limit: nil,
      new_only: false,
      report_json: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      force: false
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
        ruby scripts/import-misp-galaxy.rb fetch [options]
        ruby scripts/import-misp-galaxy.rb plan --snapshot PATH [options]
        ruby scripts/import-misp-galaxy.rb import --snapshot PATH [options]

      Commands:
        fetch   Download one or more MISP Galaxy cluster files for later import.
        plan    Preview changes that would be made from a snapshot.
        import  Apply a snapshot to `_data/actors/*.yml` and `_threat_actors/*.md`.

      Examples:
        ruby scripts/import-misp-galaxy.rb fetch --output data/imports/misp-galaxy/2026-04-26
        ruby scripts/import-misp-galaxy.rb fetch --output data/imports/misp-galaxy/2026-04-26 --cluster 360net --cluster microsoft-activity-group
        ruby scripts/import-misp-galaxy.rb plan --snapshot data/imports/misp-galaxy/2026-04-26
        ruby scripts/import-misp-galaxy.rb plan --snapshot data/imports/misp-galaxy/2026-04-26 --cluster 360net --cluster microsoft-activity-group
        ruby scripts/import-misp-galaxy.rb import --snapshot data/imports/misp-galaxy/2026-04-26
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-misp-galaxy.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--cluster NAME', 'Cluster filename to fetch (repeatable)') { |value| @options[:clusters] << value }
      opts.on('--limit N', Integer, 'Fetch only the first N actors') { |value| @options[:limit] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= "data/imports/misp-galaxy/#{Time.now.utc.strftime('%Y-%m-%d')}"
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-misp-galaxy.rb plan|import [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or cluster file') { |value| @options[:snapshot] = value }
      opts.on('--cluster NAME', 'Cluster filename inside snapshot dir (repeatable)') { |value| @options[:clusters] << value }
      opts.on('--write', 'Apply changes instead of previewing') { @options[:write] = true }
      opts.on('--new-only', 'Only create new actors; do not update existing') { @options[:new_only] = true }
      opts.on('--actor NAME', 'Restrict import to specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only first N candidates') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write machine-readable report') { |value| @options[:report_json] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
      opts.on('--force', 'Force overwrite of protected fields') { @options[:force] = true }
    end

    parser.parse!(@argv)
  end

  # Download MISP Galaxy cluster
  def fetch_snapshot
    output_dir = @options[:output]
    FileUtils.mkdir_p(output_dir)
    manifest_file = File.join(output_dir, 'manifest.yml')

    puts 'Fetching MISP Galaxy clusters...'

    fetched_clusters = selected_clusters.map do |cluster_name|
      source_url = cluster_url(cluster_name)
      puts "Source: #{source_url}"

      data = fetch_cluster_json(source_url)
      data['values'] = Array(data['values']).first(@options[:limit]) if @options[:limit]

      output_file = File.join(output_dir, cluster_name)
      File.write(output_file, JSON.pretty_generate(data))
      puts "Saved #{Array(data['values']).length} records to: #{output_file}"

      {
        'name' => cluster_name,
        'source_url' => source_url,
        'record_count' => Array(data['values']).length,
        'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(data))
      }
    end

    File.write(manifest_file, YAML.dump({
      'source_name' => SOURCE_NAME,
      'source_repository' => SOURCE_REPOSITORY,
      'retrieved_at' => Time.now.utc.iso8601,
      'clusters' => fetched_clusters
    }))

    puts "Saved manifest to: #{manifest_file}"
  end

  # Import a snapshot
  def import_snapshot
    snapshot_path = @options[:snapshot]
    unless snapshot_path
      puts "Error: --snapshot required"
      exit 1
    end

    cluster_files = resolve_snapshot_cluster_files(snapshot_path)
    if cluster_files.empty?
      puts "Error: No cluster files found for snapshot: #{snapshot_path}"
      exit 1
    end

    puts "Loading snapshot files: #{cluster_files.join(', ')}"
    misp_actors = load_snapshot_records(cluster_files)
    puts "Loaded #{misp_actors.length} MISP Galaxy records"

    # Load existing actors
    existing_actors = load_existing_actors
    existing_lookup, external_id_lookup, existing_by_name = build_existing_indexes(existing_actors)

    # Convert to our schema
    candidates = []
    misp_actors.each do |misp|
      next if @options[:actor_filters].any? && !@options[:actor_filters].include?(misp['value'])

      candidate = convert_misp_actor(misp)
      next unless candidate

      candidates << candidate
    end

    candidates = merge_candidates(candidates)

    candidates.each do |candidate|
      explicit_match = @overrides[:match_overrides][candidate[:record_key]]
      matched_names = if explicit_match
                        [explicit_match]
                      else
                        infer_matches(candidate, existing_lookup, external_id_lookup).to_a.sort
                      end

      candidate[:matched_actor_names] = matched_names
      candidate[:existing_actor_name] = matched_names.first
      candidate[:action] = if matched_names.empty?
                            'create'
                          elsif matched_names.length == 1 && existing_by_name.key?(matched_names.first)
                            'update'
                          else
                            'review'
                          end
      candidate[:is_new] = candidate[:action] == 'create'
    end

    candidates.select! { |candidate| !@options[:new_only] || candidate[:action] == 'create' }

    # Apply limit
    candidates = candidates.first(@options[:limit]) if @options[:limit]

    puts "Processing #{candidates.length} candidates (#{candidates.count { |c| c[:action] == 'create' }} create, #{candidates.count { |c| c[:action] == 'update' }} update, #{candidates.count { |c| c[:action] == 'review' }} review)"

    # Generate report
    report = generate_report(candidates, existing_actors)

    # Write report if requested
    if @options[:report_json]
      File.write(@options[:report_json], JSON.pretty_generate(report))
      puts "Report written to: #{@options[:report_json]}"
    end

    # Show plan or apply
    if @options[:write]
      apply_import(candidates, existing_actors)
    else
      show_plan(candidates, existing_actors)
    end
  end

  # Convert MISP Galaxy actor to our schema
  def convert_misp_actor(misp)
    name = misp['value']
    return nil unless name && !name.strip.empty?

    record_key = normalize_name(name)
    return nil if @overrides[:excluded_records].include?(record_key)

    meta = misp['meta'] || {}

    # Build aliases from synonyms
    aliases = []
    aliases |= meta['synonyms'] if meta['synonyms']
    # Keep the primary name in aliases too for searchability
    aliases |= [name]
    aliases.reject! { |value| @overrides[:alias_drop_list].include?(normalize_name(value)) }

    # Convert country code
    country_code = meta['country']
    country = COUNTRY_CODE_MAP[country_code] if country_code

    # If no country from meta, try state sponsor
    if !country && meta['cfr-suspected-state-sponsor']
      sponsor = meta['cfr-suspected-state-sponsor']
      # Map common sponsors
      country = case sponsor
               when 'China' then 'China'
               when 'Russia' then 'Russia'
               when 'Iran' then 'Iran'
               when 'North Korea' then 'North Korea'
               when 'South Korea' then 'South Korea'
               when 'United States' then 'United States'
               else sponsor
               end
    end
    country = @overrides[:country_overrides][record_key] if @overrides[:country_overrides][record_key]

    cluster_name = misp['cluster_name'] || DEFAULT_CLUSTER
    source_url = cluster_url(cluster_name)

    # Build sector_focus from targeted-sector or cfr-target-category
    sector_focus = []
    sector_focus |= meta['targeted-sector'] if meta['targeted-sector']
    sector_focus |= meta['cfr-target-category'] if meta['cfr-target-category']

    # Extract targeted victims
    targeted_victims = meta['cfr-suspected-victims'] || []

    # Extract incident type (motivation)
    incident_type = meta['cfr-type-of-incident']

    # Clean up refs - truncate long PDF URLs
    refs = []
    (meta['refs'] || []).each do |ref_url|
      next unless ref_url && ref_url =~ /^https?:/

      # Truncate long PDF URLs
      if ref_url.include?('pdf') && ref_url.length > 100
        clean = ref_url.split('#').first.split('?').first
        refs << clean if clean && clean.length > 20
      elsif ref_url.length > 200
        # Truncate very long URLs
        uri = URI.parse(ref_url)
        clean = "#{uri.scheme}://#{uri.host}#{uri.path[/^\/[^\/]{1,30}/]}..."
        refs << clean
      else
        refs << ref_url
      end
    end

    # Determine risk_level from attribution-confidence
    risk_level = nil
    if meta['attribution-confidence']
      confidence = meta['attribution-confidence'].to_i
      risk_level = if confidence >= 70
                   'Critical'
                 elsif confidence >= 50
                   'High'
                 elsif confidence >= 30
                   'Medium'
                 else
                   'Low'
                 end
    end

    # Build malware list from description
    malware_list = extract_malware_from_description(misp['description'])

    meta_keys = meta.keys.map(&:to_s).uniq.sort
    inferred_gid = infer_mitre_group_id(meta, refs, misp['description'])

    # Build URL slug
    url = "/#{name.downcase.gsub(/[^a-z0-9]/, '-').squeeze('-').gsub(/^-|-$/, '')}"

    {
      name: name,
      record_key: record_key,
      aliases: aliases,
      description: misp['description'] || '',
      url: url,
      country: country,
      risk_level: risk_level,
      sector_focus: sector_focus,
      targeted_victims: targeted_victims,
      incident_type: incident_type,
      malware: malware_list,
      refs: refs,
      misp_uuid: misp['uuid'],
      misp_meta: meta,
      source_cluster: cluster_name,
      source_clusters: [cluster_name],
      source_dataset_url: source_url,
      source_record_ids: [misp['uuid']].compact,
      meta_keys: meta_keys,
      inferred_mitre_group_id: inferred_gid
    }
  end

  # Discover ATT&CK enterprise group ID from Galaxy URLs / meta / description text.
  def infer_mitre_group_id(meta, refs_array, description = nil)
    scan_urls = Array(refs_array) + Array(meta['refs'])
    scan_urls.each do |u|
      next unless u.to_s =~ %r{\Ahttps?://}i

      m = u.to_s.match(%r{attack\.mitre\.org/groups/(G\d{4})\b}i)
      return m[1].upcase if m
    end

    %w[mitre-attack-intrusion-set mitre_attack_intrusion_set mitre_intrusion_set].each do |key|
      v = meta[key]
      next if v.nil?

      m = v.to_s.match(/\b(G\d{4})\b/)
      return m[1].upcase if m
    end

    if description
      m = description.to_s.match(%r{attack\.mitre\.org/groups/(G\d{4})\b}i)
      return m[1].upcase if m
    end

    nil
  end

  def merge_refs_into_references!(actor, refs)
    urls = Array(refs).map(&:to_s).map(&:strip).reject(&:empty?)
    return if urls.empty?

    actor['references'] ||= []
    existing_urls = actor['references'].each_with_object(Set.new) do |entry, seen|
      case entry
      when Hash
        seen << entry['url'].to_s.strip
      else
        seen << entry.to_s.strip
      end
    end

    urls.each do |u|
      next if existing_urls.include?(u)

      actor['references'] << {
        'url' => u,
        'title' => 'MISP Galaxy reference',
        'source' => SOURCE_NAME
      }
      existing_urls << u
    end
  end

  def apply_inferred_mitre!(actor, gid)
    gid = gid.to_s.strip.upcase
    return if gid.empty? || !gid.match?(/\AG\d{4}\z/)

    current = actor['mitre_id'].to_s.strip.upcase
    return if current.match?(/\AG\d{4}\z/)

    actor['mitre_id'] = gid
    actor['external_id'] = gid
    url = "https://attack.mitre.org/groups/#{gid}"
    actor['mitre_url'] ||= url
    actor['external_url'] ||= url
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
        key = normalize_name(value)
        next if key.to_s.empty?

        existing_lookup[key] << name
      end

      %w[external_id mitre_id].each do |field|
        external_id = actor[field].to_s.strip.upcase
        external_id_lookup[external_id] = name unless external_id.empty?
      end
    end

    [existing_lookup, external_id_lookup, existing_by_name]
  end

  def infer_matches(candidate, existing_lookup, external_id_lookup)
    matches = Set.new

    Array(candidate[:aliases]).each do |value|
      key = normalize_name(value)
      existing_lookup[key].each { |actor_name| matches << actor_name }
      external_id_lookup[value.to_s.strip.upcase]&.then { |actor_name| matches << actor_name }
    end

    matches
  end

  def merge_candidates(candidates)
    candidates.each_with_object({}) do |candidate, memo|
      key = normalize_name(candidate[:name])
      next unless key

      if memo[key]
        merge_candidate!(memo[key], candidate)
      else
        memo[key] = deep_dup_candidate(candidate)
      end
    end.values
  end

  def deep_dup_candidate(candidate)
    Marshal.load(Marshal.dump(candidate))
  end

  def merge_candidate!(base, extra)
    base[:aliases] = merge_string_arrays(base[:aliases], extra[:aliases])
    base[:description] = preferred_description(base[:description], extra[:description])
    base[:country] ||= extra[:country]
    base[:sector_focus] = merge_string_arrays(base[:sector_focus], extra[:sector_focus])
    base[:targeted_victims] = merge_string_arrays(base[:targeted_victims], extra[:targeted_victims])
    base[:incident_type] ||= extra[:incident_type]
    base[:malware] = merge_malware_lists(base[:malware], extra[:malware])
    base[:refs] = merge_string_arrays(base[:refs], extra[:refs])
    base[:risk_level] = higher_risk_level(base[:risk_level], extra[:risk_level])
    base[:source_clusters] = merge_string_arrays(base[:source_clusters], extra[:source_clusters])
    base[:source_record_ids] = merge_string_arrays(base[:source_record_ids], extra[:source_record_ids])
    base[:source_cluster] ||= extra[:source_cluster]
    base[:source_dataset_url] ||= extra[:source_dataset_url]
    base[:meta_keys] = merge_string_arrays(base[:meta_keys], extra[:meta_keys])
    base[:inferred_mitre_group_id] ||= extra[:inferred_mitre_group_id]
    base
  end

  def merge_string_arrays(left, right)
    Array(left).compact.map(&:to_s).reject(&:empty?) | Array(right).compact.map(&:to_s).reject(&:empty?)
  end

  def merge_malware_lists(left, right)
    combined = Array(left) + Array(right)
    seen = Set.new

    combined.each_with_object([]) do |entry, memo|
      next unless entry.is_a?(Hash)

      name = entry['name'].to_s.strip
      next if name.empty?

      key = name.downcase
      next if seen.include?(key)

      seen << key
      memo << { 'name' => name }
    end
  end

  def preferred_description(left, right)
    left_text = left.to_s.strip
    right_text = right.to_s.strip
    return right_text if left_text.empty?
    return left_text if right_text.empty?

    right_text.length > left_text.length ? right_text : left_text
  end

  def higher_risk_level(left, right)
    order = {
      'Low' => 1,
      'Medium' => 2,
      'High' => 3,
      'Critical' => 4
    }

    return right if left.to_s.empty?
    return left if right.to_s.empty?

    order.fetch(left, 0) >= order.fetch(right, 0) ? left : right
  end
  
  # Extract malware names from description by matching MITRE reference data
  def extract_malware_from_description(description)
    return [] unless description
    
    malware_list = []
    
    # Load MITRE malware reference if not cached
    @malware_names ||= begin
      Set.new.tap do |set|
        malware_file = 'data/misp-reference/malware.json'
        if File.exist?(malware_file)
          JSON.parse(File.read(malware_file))["values"].each do |v|
            set << v["value"].split(" - ").first
          end
        end
        
        rat_file = 'data/misp-reference/rat.json'
        if File.exist?(rat_file)
          JSON.parse(File.read(rat_file))["values"].each do |v|
            set << v["value"].split(" - ").first
          end
        end
      end
    end
    
    # Find malware in description
    @malware_names.each do |mw|
      mw_clean = mw.gsub(/[.\-]/, ' ').downcase
      desc_clean = description.downcase
      if desc_clean.include?(mw_clean) || mw_clean.length > 4 && desc_clean.include?(mw[0..4].downcase)
        malware_list << { 'name' => mw }
      end
    end
    
    malware_list.first(10)  # Limit to 10 malware
  end

  # Load existing actors from YAML
  def load_existing_actors
    ActorStore.load_all
  end

  # Generate import report
  def generate_report(candidates, _existing_actors)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      repository: SOURCE_REPOSITORY,
      license: LICENSE_NAME,
      total_candidates: candidates.length,
      creates: candidates.count { |c| c[:action] == 'create' },
      updates: candidates.count { |c| c[:action] == 'update' },
      review: candidates.count { |c| c[:action] == 'review' },
      actions: candidates.map do |c|
        {
          name: c[:name],
          url: c[:url],
          action: c[:action],
          is_new: c[:is_new],
          matched_actor_names: c[:matched_actor_names],
          source_clusters: c[:source_clusters]
        }
      end
    }
  end

  # Show plan (preview)
  def show_plan(candidates, _existing_actors)
    # Filter out actors with empty descriptions
    valid_candidates = candidates.reject { |c| c[:description].to_s.strip.empty? }
    skipped = candidates.length - valid_candidates.length
    
    puts "\n=== Import Plan ==="
    puts "Total: #{candidates.length} (#{candidates.count { |c| c[:action] == 'create' }} create, #{candidates.count { |c| c[:action] == 'update' }} update, #{candidates.count { |c| c[:action] == 'review' }} review)"
    puts "Skipped (empty description): #{skipped}" if skipped > 0

    valid_candidates.each do |c|
      action = c[:action].upcase
      puts "\n#{action}: #{c[:name]}"
      puts "  URL: #{c[:url]}"
      puts "  Country: #{c[:country] || 'N/A'}"
      puts "  Risk Level: #{c[:risk_level] || 'N/A'}"
      puts "  Aliases: #{c[:aliases].first(5).join(', ')}#{c[:aliases].length > 5 ? '...' : ''}"
      puts "  Matches: #{c[:matched_actor_names].join(', ')}" if c[:action] == 'review'
      puts "  Match: #{c[:existing_actor_name]}" if c[:action] == 'update'
      puts "  Description: #{c[:description][0..100]}..." if c[:description]
    end

    puts "\n=== Run with --write to apply ==="
  end

  # Apply import to YAML and create/update pages
  def apply_import(candidates, existing_actors)
    puts "\nApplying import..."

    # Filter out candidates with no description (MISP entries without meaningful data)
    candidates_to_import = candidates.reject do |c|
      c[:description].to_s.strip.empty?
    end
    review_candidates = candidates_to_import.select { |c| c[:action] == 'review' }
    candidates_to_import = candidates_to_import.reject { |c| c[:action] == 'review' }
    
    if candidates_to_import.length < candidates.length
      skipped = candidates.length - candidates_to_import.length
      puts "Skipped #{skipped} actors with empty descriptions"
    end
    puts "Skipped #{review_candidates.length} review candidates that need mapping overrides" if review_candidates.any?

    # Process each candidate
    candidates_to_import.each do |c|
      if c[:action] == 'create'
        create_new_actor(c, existing_actors)
      else
        update_existing_actor(c, existing_actors)
      end
    end

    # Save updated YAML
    save_existing_actors(existing_actors)

    puts "\nImport complete: #{candidates_to_import.length} actors processed"
  end

# Create new actor entry
  def create_new_actor(candidate, existing_actors)
    puts "Creating: #{candidate[:name]}"

    # Add to existing actors array
    actor_entry = {
      'name' => candidate[:name],
      'aliases' => candidate[:aliases],
      'description' => candidate[:description],
      'url' => candidate[:url]
    }

    actor_entry['country'] = candidate[:country] if candidate[:country]
    actor_entry['risk_level'] = candidate[:risk_level] if candidate[:risk_level]
    actor_entry['sector_focus'] = candidate[:sector_focus] if candidate[:sector_focus] && !candidate[:sector_focus].empty?
    actor_entry['targeted_victims'] = candidate[:targeted_victims] if candidate[:targeted_victims] && !candidate[:targeted_victims].empty?
    actor_entry['incident_type'] = candidate[:incident_type] if candidate[:incident_type]
    actor_entry['malware'] = candidate[:malware] if candidate[:malware] && !candidate[:malware].empty?
    actor_entry['source_name'] = SOURCE_NAME
    actor_entry['source_attribution'] = SOURCE_ATTRIBUTION

    # Add provenance
    actor_entry['provenance'] = {
      'misp_galaxy' => {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_record_id' => candidate[:misp_uuid],
        'source_record_ids' => candidate[:source_record_ids],
        'source_dataset_url' => candidate[:source_dataset_url],
        'source_cluster' => candidate[:source_cluster],
        'source_clusters' => candidate[:source_clusters],
        'meta_keys' => candidate[:meta_keys] || []
      }
    }

    merge_refs_into_references!(actor_entry, candidate[:refs])
    apply_inferred_mitre!(actor_entry, candidate[:inferred_mitre_group_id])

    existing_actors << actor_entry

    # Create page file
    create_page_file(candidate)
  end

# Update existing actor (additive only for aliases)
  def update_existing_actor(candidate, existing_actors)
    actor = if candidate[:existing_actor_name]
              existing_actors.find { |a| a['name'] == candidate[:existing_actor_name] }
            else
              existing_actors.find { |a| a['name'] == candidate[:name] || a['url'] == candidate[:url] }
            end
    return unless actor

    return if @options[:new_only]

    # Only update non-protected fields unless --force
    unless @options[:force]
      # Add new aliases (set union)
      existing_aliases = actor['aliases'] || []
      new_aliases = candidate[:aliases] - existing_aliases
      actor['aliases'] = existing_aliases | new_aliases unless new_aliases.empty?

      # Update missing fields
      actor['risk_level'] ||= candidate[:risk_level]
      actor['sector_focus'] ||= candidate[:sector_focus] if candidate[:sector_focus] && !candidate[:sector_focus].empty?
      actor['country'] ||= candidate[:country]
      actor['targeted_victims'] ||= candidate[:targeted_victims] if candidate[:targeted_victims] && !candidate[:targeted_victims].empty?
      actor['incident_type'] ||= candidate[:incident_type] if candidate[:incident_type]
      actor['malware'] ||= candidate[:malware] if candidate[:malware] && !candidate[:malware].empty?
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
      merge_misp_provenance!(actor, candidate)

      # Replace placeholder description with real data from MISP
      if candidate[:description] && !candidate[:description].strip.empty?
        is_placeholder = actor['provenance'] && actor['provenance']['placeholder_description']
        if is_placeholder || !actor['description'] || actor['description'].include?('pending cataloguing')
          actor['description'] = candidate[:description]
          # Clear placeholder provenance when real data replaces it
          if actor['provenance']
            actor['provenance'].delete('placeholder_description')
            actor['provenance'].delete('placeholder_reason')
            actor['provenance'].delete('auto_generated_at')
            actor['provenance'].compact!
          end
        end
      end

      puts "Updated (additive): #{candidate[:name]}"
    else
      # Full update with --force
      actor['aliases'] = candidate[:aliases] if candidate[:aliases]
      actor['description'] = candidate[:description] if candidate[:description] && !candidate[:description].strip.empty?
      actor['risk_level'] = candidate[:risk_level] if candidate[:risk_level]
      actor['sector_focus'] = candidate[:sector_focus] if candidate[:sector_focus] && !candidate[:sector_focus].empty?
      actor['country'] = candidate[:country] if candidate[:country]
      actor['source_name'] = SOURCE_NAME
      actor['source_attribution'] = SOURCE_ATTRIBUTION
      actor['provenance'] ||= {}
      actor['provenance']['misp_galaxy'] = {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_record_id' => candidate[:misp_uuid],
        'source_record_ids' => candidate[:source_record_ids],
        'source_dataset_url' => candidate[:source_dataset_url],
        'source_cluster' => candidate[:source_cluster],
        'source_clusters' => candidate[:source_clusters],
        'meta_keys' => candidate[:meta_keys] || []
      }
      # Clear placeholder flags on forced update
      actor['provenance'].delete('placeholder_description')
      actor['provenance'].delete('placeholder_reason')
      actor['provenance'].delete('auto_generated_at')

      puts "Updated (forced): #{candidate[:name]}"
    end

    merge_refs_into_references!(actor, candidate[:refs])
    apply_inferred_mitre!(actor, candidate[:inferred_mitre_group_id])

    # Optionally update page file (skip for now to preserve manual content)
  end

  # Create page file for new actor
  def create_page_file(candidate)
    filename = File.join(PAGE_DIR, "#{candidate[:url].gsub(/^\//, '')}.md")

    page_content = <<~YAML
      ---
      layout: threat_actor
      title: "#{candidate[:name]}"
      aliases: #{candidate[:aliases].inspect}
      description: "#{candidate[:description].gsub('"', '\\"')}"
      permalink: #{candidate[:url]}/
      ---

      ## Introduction

      #{candidate[:description]}

      ## Activities and Tactics

      Details about this threat actor's activities and tactics would go here.

      ## Notable Campaigns

      Notable campaigns attributed to this actor.

      ## Tactics, Techniques, and Procedures (TTPs)

      ## Notable Indicators of Compromise (IOCs)

      ## Malware and Tools

      ## Attribution and Evidence

      **Source:** This information is derived from MISP Galaxy, available under #{LICENSE_NAME}.

      ## References

YAML

    # Add references
    if candidate[:refs] && !candidate[:refs].empty?
      candidate[:refs].each do |ref|
        page_content += "\n- #{ref}"
      end
    end

    File.write(filename, page_content)
    puts "Created page: #{filename}"
  end

  # Save existing actors to YAML
  def save_existing_actors(actors)
    ActorStore.save_all(actors)
    puts 'Updated: _data/actors/*.yml'
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = YAML.safe_load(File.read(@options[:overrides_file]), permitted_classes: [], aliases: false) || {}
    @overrides[:excluded_records] = Array(payload['excluded_records']).map { |value| normalize_name(value) }.uniq
    @overrides[:match_overrides] = normalize_override_hash(payload['match_overrides'], preserve_values: true)
    @overrides[:country_overrides] = normalize_override_hash(payload['country_overrides'], preserve_values: true)
    @overrides[:alias_drop_list] = Array(payload['alias_drop_list']).map { |value| normalize_name(value) }.uniq
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = normalize_name(key)
      next if normalized_key.to_s.empty?

      memo[normalized_key] = preserve_values ? mapped_value : normalize_name(mapped_value)
    end
  end

  def merge_misp_provenance!(actor, candidate)
    actor['provenance'] ||= {}
    actor['provenance']['misp_galaxy'] ||= {}

    provenance = actor['provenance']['misp_galaxy']
    provenance['source_retrieved_at'] = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    provenance['source_dataset_url'] ||= candidate[:source_dataset_url]
    provenance['source_cluster'] ||= candidate[:source_cluster]
    provenance['source_clusters'] = merge_string_arrays(provenance['source_clusters'], candidate[:source_clusters])
    provenance['source_record_ids'] = merge_string_arrays(provenance['source_record_ids'], candidate[:source_record_ids])
    provenance['source_record_id'] ||= candidate[:misp_uuid]
    provenance['meta_keys'] = merge_string_arrays(provenance['meta_keys'], candidate[:meta_keys])
  end

  def selected_clusters
    clusters = @options[:clusters].empty? ? [DEFAULT_CLUSTER] : @options[:clusters]
    clusters.map { |cluster| normalize_cluster_name(cluster) }.uniq
  end

  def normalize_cluster_name(cluster_name)
    name = cluster_name.to_s.strip
    name = "#{name}.json" unless name.end_with?('.json')
    name
  end

  def cluster_url(cluster_name)
    "#{SOURCE_BASE_URL}/#{cluster_name}"
  end

  def fetch_cluster_json(source_url)
    uri = URI.parse(source_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER

    response = http.get(uri.request_uri)
    unless response.code == '200'
      puts "Error: HTTP #{response.code} for #{source_url}"
      exit 1
    end

    JSON.parse(response.body)
  end

  def resolve_snapshot_cluster_files(snapshot_path)
    return [snapshot_path] unless File.directory?(snapshot_path)

    cluster_names = if @options[:clusters].any?
                      selected_clusters
                    else
                      manifest_clusters(snapshot_path)
                    end

    cluster_names.map { |cluster_name| File.join(snapshot_path, cluster_name) }.select { |path| File.exist?(path) }
  end

  def manifest_clusters(snapshot_path)
    manifest_path = File.join(snapshot_path, 'manifest.yml')
    return [DEFAULT_CLUSTER] if File.exist?(File.join(snapshot_path, DEFAULT_CLUSTER)) && !File.exist?(manifest_path)

    if File.exist?(manifest_path)
      manifest = YAML.safe_load(File.read(manifest_path), permitted_classes: [], aliases: true) || {}
      clusters = Array(manifest['clusters']).filter_map do |entry|
        entry.is_a?(Hash) ? entry['name'] : entry
      end
      return clusters.map { |cluster| normalize_cluster_name(cluster) } unless clusters.empty?
    end

    Dir.glob(File.join(snapshot_path, '*.json')).map { |path| File.basename(path) }.sort
  end

  def load_snapshot_records(cluster_files)
    cluster_files.each_with_object([]) do |cluster_file, records|
      cluster_data = JSON.parse(File.read(cluster_file))
      cluster_name = File.basename(cluster_file)

      Array(cluster_data['values']).each do |record|
        next unless record.is_a?(Hash)

        records << record.merge('cluster_name' => cluster_name)
      end
    end
  end

  # Normalize actor name for matching
  def normalize_name(name)
    return nil unless name

    name.downcase.gsub(/[^a-z0-9]/, '').strip
  end
end

# Run the importer
if __FILE__ == $0
  MispGalaxyImporter.new(ARGV).run
end
