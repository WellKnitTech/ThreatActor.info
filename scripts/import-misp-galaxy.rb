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
  PAGE_DIR = '_threat_actors'.freeze
  SOURCE_NAME = 'MISP Galaxy'.freeze
  SOURCE_REPOSITORY = 'https://github.com/MISP/misp-galaxy'.freeze
  SOURCE_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json'.freeze
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
      actor_filters: [],
      limit: nil,
      new_only: false,
      report_json: nil,
      force: false
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
        ruby scripts/import-misp-galaxy.rb fetch [options]
        ruby scripts/import-misp-galaxy.rb plan --snapshot PATH [options]
        ruby scripts/import-misp-galaxy.rb import --snapshot PATH [options]

      Commands:
        fetch   Download MISP Galaxy threat-actor cluster for later import.
        plan    Preview changes that would be made from a snapshot.
        import  Apply a snapshot to `_data/actors/*.yml` and `_threat_actors/*.md`.

      Examples:
        ruby scripts/import-misp-galaxy.rb fetch --output data/imports/misp-galaxy/2026-04-26
        ruby scripts/import-misp-galaxy.rb plan --snapshot data/imports/misp-galaxy/2026-04-26
        ruby scripts/import-misp-galaxy.rb import --snapshot data/imports/misp-galaxy/2026-04-26
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-misp-galaxy.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--limit N', Integer, 'Fetch only the first N actors') { |value| @options[:limit] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= "data/imports/misp-galaxy/#{Time.now.utc.strftime('%Y-%m-%d')}"
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-misp-galaxy.rb plan|import [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or cluster file') { |value| @options[:snapshot] = value }
      opts.on('--write', 'Apply changes instead of previewing') { @options[:write] = true }
      opts.on('--new-only', 'Only create new actors; do not update existing') { @options[:new_only] = true }
      opts.on('--actor NAME', 'Restrict import to specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only first N candidates') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write machine-readable report') { |value| @options[:report_json] = value }
      opts.on('--force', 'Force overwrite of protected fields') { @options[:force] = true }
    end

    parser.parse!(@argv)
  end

  # Download MISP Galaxy cluster
  def fetch_snapshot
    puts "Fetching MISP Galaxy threat-actor cluster..."
    puts "Source: #{SOURCE_URL}"

    uri = URI.parse(SOURCE_URL)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER

    response = http.get(uri.request_uri)
    unless response.code == '200'
      puts "Error: HTTP #{response.code}"
      exit 1
    end

    data = JSON.parse(response.body)

    # Extract values array
    actors = data['values'] || []

    # Apply limit if specified
    actors = actors.first(@options[:limit]) if @options[:limit]

    puts "Fetched #{actors.length} threat actors"

    # Save snapshot
    output_dir = @options[:output]
    FileUtils.mkdir_p(output_dir)
    output_file = File.join(output_dir, 'threat-actor.json')
    manifest_file = File.join(output_dir, 'manifest.yml')

    File.write(output_file, JSON.pretty_generate(data))
    File.write(manifest_file, YAML.dump({
                                           'source_name' => SOURCE_NAME,
                                           'source_url' => SOURCE_URL,
                                           'retrieved_at' => Time.now.utc.iso8601,
                                           'record_count' => actors.length,
                                           'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(data)),
                                           'cluster_file' => 'threat-actor.json'
                                         }))
    puts "Saved to: #{output_file}"
  end

  # Import a snapshot
  def import_snapshot
    snapshot_path = @options[:snapshot]
    unless snapshot_path
      puts "Error: --snapshot required"
      exit 1
    end

    # Find the cluster file
    cluster_file = if File.directory?(snapshot_path)
                     File.join(snapshot_path, 'threat-actor.json')
                   else
                     snapshot_path
                   end

    unless File.exist?(cluster_file)
      puts "Error: Cluster file not found: #{cluster_file}"
      exit 1
    end

    puts "Loading snapshot: #{cluster_file}"
    cluster_data = JSON.parse(File.read(cluster_file))
    misp_actors = cluster_data['values'] || []

    puts "Loaded #{misp_actors.length} MISP Galaxy actors"

    # Load existing actors
    existing_actors = load_existing_actors
    existing_names = existing_actors.map { |a| normalize_name(a['name']) }.compact.to_set

    # Convert to our schema
    candidates = []
    misp_actors.each do |misp|
      next if @options[:actor_filters].any? && !@options[:actor_filters].include?(misp['value'])

      candidate = convert_misp_actor(misp)
      next unless candidate

      # Check if it's a new actor
      normalized = normalize_name(candidate[:name])
      candidate[:is_new] = !existing_names.include?(normalized)

      # Skip if --new-only and actor exists
      next if @options[:new_only] && !candidate[:is_new]

      candidates << candidate
    end

    # Apply limit
    candidates = candidates.first(@options[:limit]) if @options[:limit]

    puts "Processing #{candidates.length} candidates (#{candidates.count { |c| c[:is_new] }} new)"

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

    meta = misp['meta'] || {}

    # Build aliases from synonyms
    aliases = []
    aliases |= meta['synonyms'] if meta['synonyms']
    # Keep the primary name in aliases too for searchability
    aliases |= [name]

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

# Build sector_focus from targeted-sector or cfr-target-category
    sector_focus = []
    sector_focus |= meta['targeted-sector'] if meta['targeted-sector']
    sector_focus |= meta['cfr-target-category'] if meta['cfr-target-category']
    
    # Extract targeted victims
    targeted_victims = meta['cfr-suspected-victims'] || []
    
    # Extract incident type (motivation)
    incident_type = meta['cfr-type-of-incident']
    
    # Extract malware from description by matching MITRE malware/rat names
    malware_list = extract_malware_from_description(misp['description'])
    
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
    
    # Build URL slug
    url = "/#{name.downcase.gsub(/[^a-z0-9]/, '-').squeeze('-').gsub(/^-|-$/, '')}"

    {
      name: name,
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
      misp_meta: meta
    }
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
      new_actors: candidates.count { |c| c[:is_new] },
      existing_actors: candidates.length - candidates.count { |c| c[:is_new] },
      actions: candidates.map do |c|
        {
          name: c[:name],
          url: c[:url],
          action: c[:is_new] ? 'create' : 'update',
          is_new: c[:is_new]
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
    puts "Total: #{candidates.length} (#{candidates.count { |c| c[:is_new] }} new, #{candidates.count { |c| !c[:is_new] }} updates)"
    puts "Skipped (empty description): #{skipped}" if skipped > 0

    valid_candidates.each do |c|
      action = c[:is_new] ? 'CREATE' : 'UPDATE'
      puts "\n#{action}: #{c[:name]}"
      puts "  URL: #{c[:url]}"
      puts "  Country: #{c[:country] || 'N/A'}"
      puts "  Risk Level: #{c[:risk_level] || 'N/A'}"
      puts "  Aliases: #{c[:aliases].first(5).join(', ')}#{c[:aliases].length > 5 ? '...' : ''}"
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
    
    if candidates_to_import.length < candidates.length
      skipped = candidates.length - candidates_to_import.length
      puts "Skipped #{skipped} actors with empty descriptions"
    end

    # Process each candidate
    candidates_to_import.each do |c|
      if c[:is_new]
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

    # Add provenance
    actor_entry['provenance'] = {
      'misp_galaxy' => {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_record_id' => candidate[:misp_uuid],
        'source_dataset_url' => SOURCE_URL
      }
    }

    existing_actors << actor_entry

    # Create page file
    create_page_file(candidate)
  end

# Update existing actor (additive only for aliases)
  def update_existing_actor(candidate, existing_actors)
    actor = existing_actors.find { |a| a['name'] == candidate[:name] || a['url'] == candidate[:url] }
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

      puts "Updated (additive): #{candidate[:name]}"
    else
      # Full update with --force
      actor['aliases'] = candidate[:aliases] if candidate[:aliases]
      actor['risk_level'] = candidate[:risk_level] if candidate[:risk_level]
      actor['sector_focus'] = candidate[:sector_focus] if candidate[:sector_focus] && !candidate[:sector_focus].empty?
      actor['country'] = candidate[:country] if candidate[:country]
      actor['provenance'] ||= {}
      actor['provenance']['misp_galaxy'] = {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_record_id' => candidate[:misp_uuid],
        'source_dataset_url' => SOURCE_URL
      }

      puts "Updated (forced): #{candidate[:name]}"
    end

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

      **References:**

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