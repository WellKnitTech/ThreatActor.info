#!/usr/bin/env ruby
# frozen_string_literal: true

# Page Generator - Generates all threat actor pages from YAML data
#
# Usage:
#   ruby scripts/generate-pages.rb              # Generate all pages
#   ruby scripts/generate-pages.rb --force    # Overwrite existing pages
#   ruby scripts/generate-pages.rb --dry-run   # Preview without writing
#
# This script reads from _data/actors/*.yml and generates page content
# from the YAML data, preserving manually-enriched pages.

require 'fileutils'
require 'yaml'
require 'json'
require 'optparse'
require 'cgi'
require 'net/http'
require 'digest'
require_relative 'actor_store'
require_relative 'ioc_yaml_reader'

PAGE_DIR = '_threat_actors'

DESCRIPTION_SOURCE_ORDER = %w[
  mitre
  misp_galaxy
  ransomlook
  malpedia
].freeze

# Placeholder patterns - if page contains these, it's not enriched
PLACEHOLDER_PATTERNS = [
  /\*Pending\*/,
  /\*Information pending cataloguing\*/,
  /This section is pending cataloguing/,
  /Information pending cataloguing/,
  /check upstream sources for current IOCs/,
  /pending.*cataloguing/i
].freeze

# Skip these actors from regeneration (manually enriched)
SKIP_ACTORS = %w[
  Sandworm Team
  Turla
  Kimsuky
  Mustang Panda
  Fox Kitten
  Volt Typhoon
  HAFNIUM
  Andariel
  APT39
  FIN6
  MuddyWater
  Sidewinder
  Ember Bear
  Patchwork
  APT28
  APT29
  Lazarus Group
  LockBit
].freeze

options = {
  force: false,
  dry_run: false,
  verbose: false,
  actor_filters: []
}

OptionParser.new do |opts|
  opts.banner = "Usage: ruby scripts/generate-pages.rb [options]"
  opts.on("--force", "Overwrite existing pages") { |v| options[:force] = v }
  opts.on("--dry-run", "Preview only, don't write") { |v| options[:dry_run] = v }
  opts.on("--actor NAME", "Generate a specific actor by name or slug (repeatable)") { |value| options[:actor_filters] << value }
  opts.on("-v", "--verbose", "Show detailed output") { |v| options[:verbose] = v }
end.parse!

def log(msg)
  puts msg if ENV['VERBOSE'] || $VERBOSE
end

def normalize_actor_filter(value)
  value.to_s.downcase.gsub(/[^a-z0-9]+/, '')
end

# Check if a page is manually enriched (should be preserved)
def enriched_page?(page_path)
  return false unless File.exist?(page_path)
  
  content = File.read(page_path)
  
  # Check for enrichment markers
  return true if content.include?('campaign_date:')
  return true if content.include?('ioc_notes:')
  return true if content.include?('malware:')
  return true if content.include?('APT28-Specific IOCs') && content.length > 2000
  return true if content.include?('### IP Addresses') && content.include?('### File Hashes')
  
  # Check for actual campaigns (not just placeholder)
  return true if content.match?(/\d{4}.*Infiltration/) # Has dated campaign
  return true if content.match?(/\*\*[A-Z]/) && content.scan(/\*\*[A-Z]/).length > 3 # Bold names = real content
  
  # Check for IOCs that aren't just "*Pending*"
  ioc_count = content.scan(/`[a-f0-9]{32,}`|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/).length
  return true if ioc_count > 3
  
  false
end

# Build front matter YAML
def build_front_matter(actor)
  lines = []
  lines << "layout: threat_actor"
  lines << "title: \"#{actor['name']}\""
  
  # Aliases
  aliases = Array(actor['aliases']).map { |a| "\"#{a}\"" }.join(', ')
  lines << "aliases: [#{aliases}]"
  
  # Description
  if actor['description']
    lines << "description: \"#{actor['description'].gsub('"', '\\"').gsub("\n", ' ')[0..200]}\""
  end
  
  # Permalink - ensure trailing slash
  url = actor['url']&.gsub(/\/$/, '') || 'unknown'
  lines << "permalink: #{url}/"
  
  lines.join("\n")
end

# Country code to emoji flag mapping
COUNTRY_FLAGS = {
  "AF" => "🇦🇫", "AL" => "🇦🇱", "DZ" => "🇩🇿", "AR" => "🇦🇷", "AM" => "🇦🇲",
  "AU" => "🇦🇺", "AT" => "🇦🇹", "AZ" => "🇦🇿", "BD" => "🇧🇩", "BY" => "🇧🇾",
  "BE" => "🇧🇪", "BR" => "🇧🇷", "BG" => "🇧🇬", "KH" => "🇰🇭", "CM" => "🇨🇲",
  "CA" => "🇨🇦", "CL" => "🇨🇱", "CN" => "🇨🇳", "CO" => "🇨🇴", "HR" => "🇭🇷",
  "CU" => "🇨🇺", "CZ" => "🇨🇿", "DK" => "🇩🇰", "EG" => "🇪🇬", "ET" => "🇪🇹",
  "FI" => "🇫🇮", "FR" => "🇫🇷", "GE" => "🇬🇪", "DE" => "🇩🇪", "GH" => "🇬🇭",
  "GR" => "🇬🇷", "GT" => "🇬🇹", "HK" => "🇭🇰", "HU" => "🇭🇺", "IN" => "🇮🇳",
  "ID" => "🇮🇩", "IR" => "🇮🇷", "IQ" => "🇮🇶", "IE" => "🇮🇪", "IL" => "🇮🇱",
  "IT" => "🇮🇹", "JP" => "🇯🇵", "JO" => "🇯🇴", "KZ" => "🇰🇿", "KE" => "🇰🇪",
  "KP" => "🇰🇵", "KR" => "🇰🇷", "KW" => "🇰🇼", "LV" => "🇱🇻", "LB" => "🇱🇧",
  "LT" => "🇱🇹", "MY" => "🇲🇾", "MX" => "🇲🇽", "MN" => "🇲🇳", "MA" => "🇲🇦",
  "MM" => "🇲🇲", "NP" => "🇳🇵", "NL" => "🇳🇱", "NZ" => "🇳🇿", "NG" => "🇳🇬",
  "NO" => "🇳🇴", "PK" => "🇵🇰", "PS" => "🇵🇸", "PA" => "🇵🇦", "PE" => "🇵🇪",
  "PH" => "🇵🇭", "PL" => "🇵🇱", "PT" => "🇵🇹", "RO" => "🇷🇴", "RU" => "🇷🇺",
  "SA" => "🇸🇦", "RS" => "🇷🇸", "SG" => "🇸🇬", "SK" => "🇸🇰", "SI" => "🇸🇮",
  "ZA" => "🇿🇦", "ES" => "🇪🇸", "LK" => "🇱🇰", "SE" => "🇸🇪", "CH" => "🇨🇭",
  "SY" => "🇸🇾", "TW" => "🇹🇼", "TH" => "🇹🇭", "TR" => "🇹🇷", "UA" => "🇺🇦",
  "AE" => "🇦🇪", "GB" => "🇬🇧", "US" => "🇺🇸", "UZ" => "🇺🇿", "VE" => "🇻🇪",
  "VN" => "🇻🇳",
}.freeze

def get_country_flag(country)
  return "🏳️" if country.nil? || country.empty?
  
  # Try exact match first
  country_flat = country.strip
  if COUNTRY_FLAGS[country_flat]
    return COUNTRY_FLAGS[country_flat]
  end
  
  # Try case-insensitive
  upper = country_flat.upcase
  return COUNTRY_FLAGS[upper] if COUNTRY_FLAGS[upper]
  
  # Try partial name match
  name_map = {
    "russia" => "🇷🇺", "china" => "🇨🇳", "iran" => "🇮🇷", "north korea" => "🇰🇵",
    "south korea" => "🇰🇷", "united states" => "🇺🇸", "united kingdom" => "🇬🇧",
    "vietnam" => "🇻🇳", "india" => "🇮🇳", "pakistan" => "🇵🇰", "israel" => "🇮🇱",
    "turkey" => "🇹🇷", "brazil" => "🇧🇷", "ukraine" => "🇺🇦", "japan" => "🇯🇵",
    "germany" => "🇩🇪", "france" => "🇫🇷", "nigeria" => "🇳🇬", "romania" => "🇷🇴",
  }
  
  lower = country_flat.downcase
  name_map.each do |name, flag|
    return flag if lower.include?(name)
  end
  
  "🏳️"
end

def tool_matrix_observations(actor)
  provenance = actor['provenance']
  return {} unless provenance.is_a?(Hash)

  {
    'Ransomware Tool Matrix observations' => provenance['ransomware_tool_matrix'],
    'Russian APT Tool Matrix observations' => provenance['russian_apt_tool_matrix']
  }.each_with_object({}) do |(label, matrix), memo|
    next unless matrix.is_a?(Hash)

    tools_by_category = matrix['tools_by_category']
    next unless tools_by_category.is_a?(Hash)

    normalized = tools_by_category.each_with_object({}) do |(category, tools), category_memo|
      normalized_tools = Array(tools).map(&:to_s).map(&:strip).reject(&:empty?).uniq
      category_memo[category.to_s] = normalized_tools unless normalized_tools.empty?
    end
    memo[label] = normalized unless normalized.empty?
  end
end

def ransomware_vulnerability_matrix_observations(actor)
  provenance = actor['provenance']
  return {} unless provenance.is_a?(Hash)

  matrix = provenance['ransomware_vulnerability_matrix']
  return {} unless matrix.is_a?(Hash)

  vulnerabilities_by_category = matrix['vulnerabilities_by_category']
  return {} unless vulnerabilities_by_category.is_a?(Hash)

  vulnerabilities_by_category.each_with_object({}) do |(category, observations), memo|
    normalized_observations = Array(observations).filter_map do |entry|
      next unless entry.is_a?(Hash)

      cves = Array(entry['cves']).map(&:to_s).map(&:strip).reject(&:empty?).uniq
      next if cves.empty?

      {
        'vendor' => entry['vendor'].to_s.strip,
        'product' => entry['product'].to_s.strip,
        'cves' => cves
      }
    end
    memo[category.to_s] = normalized_observations unless normalized_observations.empty?
  end
end

def curated_intel_moveit_transfer_events(actor)
  provenance = actor['provenance']
  return [] unless provenance.is_a?(Hash)

  source = provenance['curated_intel_moveit_transfer']
  return [] unless source.is_a?(Hash)

  Array(source['events']).select { |event| event.is_a?(Hash) }
end

def escape_table_cell(value)
  value.to_s.gsub(/\s+/, ' ').strip.gsub('|', '&#124;')
end

def normalize_cisa_kev_entry(entry)
  return entry if entry.is_a?(Hash)
  return {} unless entry.is_a?(String)

  entry.scan(/"([^"]+)"\s*=>\s*"([^"]*)"/).to_h
end

def ransomware_vulnerability_matrix_rows(actor)
  ransomware_vulnerability_matrix_observations(actor).each_with_object({}) do |(category, observations), memo|
    observations.each do |entry|
      key = [entry['vendor'], entry['product'], entry['cves'].join(', ')]
      memo[key] ||= entry.merge('categories' => [])
      memo[key]['categories'] << category unless memo[key]['categories'].include?(category)
    end
  end.values.sort_by { |entry| [entry['vendor'], entry['product'], entry['cves'].join(', ')] }
end

# Build page body from YAML data
def build_body(actor)
  sections = []
  narrative = build_deterministic_narrative(actor)
  
  # Introduction
  sections << "## Introduction"
  sections << narrative
  sections << ""
  
  # Activities and Tactics
  sections << "## Activities and Tactics"
  if actor['country'] || actor['sector_focus'] || actor['targeted_victims'] || actor['incident_type']
    if actor['sector_focus']
      sections << "**Targeted Sectors**: #{actor['sector_focus']&.join(', ') || 'Various'}"
      sections << ""
    end
    if actor['country']
      flag = get_country_flag(actor['country'])
      sections << "**Country of Origin**: #{flag} #{actor['country']}"
      sections << ""
    end
    sections << "**Risk Level**: #{actor['risk_level'] || 'Medium'}" if actor['risk_level']
    sections << ""
    sections << "**First Seen**: #{actor['first_seen'] || 'Unknown'}" if actor['first_seen']
    sections << ""
    sections << "**Last Activity**: #{actor['last_activity'] || 'Unknown'}" if actor['last_activity']
    sections << ""
    sections << "**Incident Type**: #{actor['incident_type'] || 'Unknown'}" if actor['incident_type']
    sections << ""
    
    # Add targeted victims if present
    if actor['targeted_victims'] && actor['targeted_victims'].any?
      victims = actor['targeted_victims'].first(10)
      sections << "**Suspected Victims**: #{victims.join(', ')}#{actor['targeted_victims'].size > 10 ? '...' : ''}"
      sections << ""
    end
  else
    sections << "*Information pending cataloguing.*"
    sections << ""
  end
  
  # Notable Campaigns - from YAML if present
  sections << "## Notable Campaigns"
  moveit_events = curated_intel_moveit_transfer_events(actor)
  if moveit_events.any?
    source_name = actor.dig('provenance', 'curated_intel_moveit_transfer', 'source_name') || 'Curated Intelligence MOVEit Transfer Tracking'
    sections << "### MOVEit Transfer campaign timeline"
    sections << "#{source_name} tracks #{moveit_events.length} public events for the 2023 MOVEit Transfer hacking campaign attributed to CL0P/Lace Tempest."
    sections << ""
    sections << "| Date | Type | Event | Source |"
    sections << "|---|---|---|---|"
    moveit_events.each do |event|
      source_url = event['source_url'].to_s
      source_title = event['source_title'].to_s.empty? ? 'source' : event['source_title']
      source = source_url.empty? ? escape_table_cell(source_title) : "[#{escape_table_cell(source_title)}](#{source_url})"
      sections << "| #{escape_table_cell(event['publish_date'])} | #{escape_table_cell(event['event_type'])} | #{escape_table_cell(event['description'])} | #{source} |"
    end
  elsif actor['campaigns'] && actor['campaigns'].any?
    actor['campaigns'].each do |campaign|
      if campaign.is_a?(Hash)
        name = campaign['name'] || 'Unnamed Campaign'
        cid = campaign['campaign_id']
        curl = campaign['url']
        desc = campaign['description'].to_s
        date = campaign['date'] || ''
        if curl && !curl.to_s.empty?
          label = cid ? "#{name} (#{cid})" : name
          tail = [desc, date].reject { |x| x.to_s.strip.empty? }.join(' — ')
          sections << (tail.empty? ? "- [#{label}](#{curl})" : "- [#{label}](#{curl}): #{tail}")
        else
          sections << "- **#{name}**#{cid ? " (#{cid})" : ''} (#{date}): #{desc}"
        end
      else
        sections << "- **#{campaign}**"
      end
    end
  else
    sections << "*Information pending cataloguing.*"
  end
  sections << ""
  
  # TTPs
  sections << "## Tactics, Techniques, and Procedures (TTPs)"
  vulnerability_rows = ransomware_vulnerability_matrix_rows(actor)
  if actor['ttps'] && actor['ttps'].any?
    actor['ttps'].each do |ttp|
      # Handle both object format (with keys) and string format (e.g., "T1566 - Phishing")
      if ttp.is_a?(Hash)
        tid = ttp['technique_id'] || ''
        tname = ttp['technique_name'] || ''
        desc = ttp['description'] || ''
        url = ttp['url']
        if url && !url.to_s.empty?
          # Markdown link so generate-indexes extracts ATT&CK technique mappings
          sections << "- [#{tid} #{tname}](#{url})"
        elsif !desc.to_s.strip.empty?
          sections << "- **#{tid} #{tname}**: #{desc}"
        else
          sections << "- **#{tid} #{tname}**"
        end
      else
        # String format: "T1566 - Phishing" or just "Phishing"
        sections << "- **#{ttp}**"
      end
    end
  elsif vulnerability_rows.empty?
    sections << "*Information pending cataloguing.*"
  end

  if vulnerability_rows.any?
    sections << "" if actor['ttps'] && actor['ttps'].any?
    sections << "### Ransomware Vulnerability Matrix observations"
    sections << ""
    sections << "| Category | Vendor | Product | CVEs |"
    sections << "|---|---|---|---|"
    vulnerability_rows.each do |entry|
      sections << "| #{entry['categories'].sort.join(', ')} | #{entry['vendor']} | #{entry['product']} | #{entry['cves'].join(', ')} |"
    end
  end
  sections << ""
  
  # IOCs section header (canonical structured lists live under actor['iocs'] plus legacy top-level ips/domains/urls/hashes; see IocYamlReader)
  sections << "## Notable Indicators of Compromise (IOCs)"
  iocs = IocYamlReader.merged_iocs_sources(actor)
  ips = Array(iocs['ips']).reject { |value| value.to_s.strip.empty? }
  md5_hashes = Array(iocs['md5']).reject { |value| value.to_s.strip.empty? }
  sha1_hashes = Array(iocs['sha1']).reject { |value| value.to_s.strip.empty? }
  sha256_hashes = Array(iocs['sha256']).reject { |value| value.to_s.strip.empty? }
  domains = Array(iocs['domains']).reject { |value| value.to_s.strip.empty? }
  urls = Array(iocs['urls']).reject { |value| value.to_s.strip.empty? }
  emails = Array(iocs['emails']).reject { |value| value.to_s.strip.empty? }
  cves = Array(iocs['cves']).reject { |value| value.to_s.strip.empty? }
  atk_tech = Array(iocs['attack_techniques']).reject { |value| value.to_s.strip.empty? }

  iocs_empty = ips.empty? && md5_hashes.empty? && sha1_hashes.empty? && sha256_hashes.empty? && domains.empty? &&
              urls.empty? && emails.empty? && cves.empty? && atk_tech.empty?

  if iocs_empty
    sections << "*No curated IOCs are currently published for this actor. This section will be updated when stable, attributable indicators are available.*"
    sections << ""
  else
    if ips.any?
      sections << "### IP Addresses"
      ips.each do |ip|
        sections << "- `#{ip}`"
      end
      sections << ""
    end

    if md5_hashes.any? || sha1_hashes.any? || sha256_hashes.any?
      sections << "### File Hashes"
      md5_hashes.each { |hash| sections << "- `#{hash}` (MD5)" }
      sha1_hashes.each { |hash| sections << "- `#{hash}` (SHA1)" }
      sha256_hashes.each { |hash| sections << "- `#{hash}` (SHA256)" }
      sections << ""
    end

    if domains.any?
      sections << "### Domains"
      domains.each do |domain|
        sections << "- `#{domain}`"
      end
      sections << ""
    end

    if urls.any?
      sections << "### URLs"
      urls.each do |u|
        sections << "- `#{u}`"
      end
      sections << ""
    end

    if emails.any?
      sections << "### Email addresses"
      emails.each do |em|
        sections << "- `#{em}`"
      end
      sections << ""
    end

    if cves.any?
      sections << "### CVEs"
      cves.each do |cve|
        sections << "- `#{cve}`"
      end
      sections << ""
    end

    if atk_tech.any?
      sections << "### ATT&CK technique references"
      atk_tech.each do |tid|
        sections << "- `#{tid}`"
      end
      sections << ""
    end
  end
  
  # Malware
  sections << "## Malware and Tools"
  mal_list = actor['malware'] || []
  sw_list = actor['software'] || []
  matrix_observations = tool_matrix_observations(actor)

  if mal_list && mal_list.any?
    mal_list.each do |m|
      # Handle both object format (with keys) and string format
      if m.is_a?(Hash)
        name = m['name'] || 'Unknown'
        desc = m['description'] || ''
        sections << "- **#{name}**: #{desc}"
      else
        # String format: "ZackStealer - Custom info-stealer"
        sections << "- **#{m}**"
      end
    end
  end

  if sw_list.any?
    sections << "" if mal_list&.any?
    sections << "### MITRE ATT&CK Software"
    sw_list.each do |s|
      next unless s.is_a?(Hash)

      name = s['name'] || 'Unknown'
      sid = s['mitre_id']
      url = s['url']
      stype = s['type']
      if url && !url.to_s.empty?
        sections << "- [#{name} (#{sid}) — #{stype}](#{url})"
      else
        sections << "- **#{name}** (#{sid}, #{stype})"
      end
    end
  end

  if matrix_observations.any?
    sections << "" if (mal_list && mal_list.any?) || sw_list.any?
    matrix_observations.sort.each do |label, matrix_tools|
      sections << "### #{label}"
      sections << ""
      sections << "| Category | Observed tools |"
      sections << "|---|---|"
      matrix_tools.sort.each do |category, tools|
        sections << "| #{category} | #{tools.sort.join(', ')} |"
      end
      sections << ""
    end
    sections.pop if sections.last == ""
  elsif (!mal_list || mal_list.empty?) && sw_list.empty?
    sections << "*Information pending cataloguing.*"
  end
  sections << ""
  
  # Attribution
  sections << "## Attribution and Evidence"
  if actor['attribution']
    sections << "**Government Affiliation**: #{actor['attribution']['government_link'] ? 'State-sponsored' : 'Unknown'}"
    sections << "**Motivation**: #{actor['attribution']['motivation'] || 'Unknown'}"
  elsif actor['country']
    sections << "**Country of Origin**: #{actor['country']}"
    sections << "*Additional attribution information pending cataloguing.*"
  else
    sections << "*Information pending cataloguing.*"
  end
  sections << ""
  
  # Analyst Notes - format multi-line text with proper spacing
  if actor['analyst_notes'] && !actor['analyst_notes'].to_s.strip.empty?
    sections << "## Analyst Notes"
    # Process analyst_notes to ensure proper line breaks
    notes = actor['analyst_notes'].to_s
    # Convert literal \n to actual newlines
    notes = notes.gsub('\\n', "\n")
    # Ensure blank lines around section dividers
    notes = notes.gsub(/\n---\n/, "\n\n---\n\n")
    # Add blank line before list items that follow text
    notes = notes.gsub(/([^\n])\n(- )/, "\\1\n\n\\2")
    # Add blank line before uppercase section headers
    notes = notes.gsub(/([^\n])\n([A-Z][A-Z\s]+:)/, "\\1\n\n\\2")
    sections << notes.strip
    sections << ""
  end
  
  # Parse references and build citations
  citations = []
  citation_sources = {}  # URL -> citation ID (string keys)
  source_name_to_url = {}  # Source name -> URL mapping for Citation: format
  
  # Load references from cache if not in YAML
references_cache = nil
ref_cache_file = "_data/references.json"

# Use cached references only to keep builds deterministic/offline-safe.
if File.exist?(ref_cache_file)
  begin
    references_cache = JSON.parse(File.read(ref_cache_file))
  rescue
    references_cache = nil
  end
end

# Parse references from cache or YAML
actor_refs = actor['references'] || []
if references_cache && actor_refs.empty?
  actor_refs = references_cache[actor['name']] || []
end

if actor_refs && actor_refs.any?
    # Build citation map from references
    actor_refs.each_with_index do |ref, idx|
      next unless ref['url'] && !ref['url'].empty?
      
      ref_id = idx + 1
      url = ref['url']
      source = ref['source'] || 'source'
      desc = ref['description']
      
      # Use string keys for consistency
      citations << { 'id' => ref_id, 'source' => source, 'url' => url, 'description' => desc }
      citation_sources[url] = ref_id  # Deduplicate by URL
      source_name_to_url[source.downcase] = url  # Map source name to URL for Citation: parsing
    end
  end
  
  # Use external_url as fallback if exists
  if actor['external_url'] && !citation_sources[actor['external_url']]
    next_id = citations.size + 1
    citations << { 'id' => next_id, 'source' => 'MITRE ATT&CK', 'url' => actor['external_url'], 'description' => 'MITRE ATT&CK entry' }
    citation_sources[actor['external_url']] = next_id
    source_name_to_url['mitre-attack'] = actor['external_url']
  end
  
  description = narrative
  
  # Process (Citation: Source name) format from MITRE
  if description =~ /\(Citation:/
    # Find all Citation: patterns and map to references
    link_counter = citations.size
    
    description.gsub(/\(Citation: ([^)]+)\)/) do |match|
      source_name = $1.strip
      
      # Try to find matching source
      url = source_name_to_url[source_name.downcase]
      
      if url && citation_sources[url]
        "[#{citation_sources[url]}]"
      else
        # Add new citation using source name (won't have URL, but will reference source)
        link_counter += 1
        # Check if we can find URL by partial match
        found_url = nil
        citation_sources.each do |u, id|
          if source_name.downcase.include?(u.split('/').last.downcase) || 
             u.downcase.include?(source_name.downcase)
            found_url = u
            break
          end
        end
        
        url_to_use = found_url || "https://www.google.com/search?q=#{CGI.escape(source_name)}+threat+actor"
        citation_sources[url_to_use] = link_counter
        citations << { 
          'id' => link_counter, 
          'source' => source_name, 
          'url' => url_to_use, 
          'description' => "External citation" 
        }
        "[#{link_counter}]"
      end
    end
  end
  
  # Also convert inline markdown links to footnotes
  if description =~ /\[([^\]]+)\]\(([^)]+)\)/ 
    link_counter = citations.size
    
    description.gsub(/\[([^\]]+)\]\(([^)]+)\)/) do |match|
      text = $1
      url = $2
      
      # Skip if already in citations
      if citation_sources[url]
        "[#{citation_sources[url]}]"
      else
        # Add new citation
        link_counter += 1
        citation_sources[url] = link_counter
        citations << { 
          'id' => link_counter, 
          'source' => text,  # Use link text as source
          'url' => url, 
          'description' => "Referenced in description" 
        }
        "[#{link_counter}]"
      end
    end
  end
  
  # Replace custom citation placeholders with numbers
  # Format: {{citation:1}} or [citation:1] or {{1}}
  if citation_sources.any?
    description = description.gsub(/\{\{(?:citation:)?(\d+)\}\}/) { |m| "[#$1]" }
    description = description.gsub(/\[citation:(\d+)\]/) { |m| "[#$1]" }
  end
  
  # Rebuild Introduction with processed description
  sections[0] = "## Introduction"
  sections[1] = description
  
  # References - numbered footnotes
sections << "## References"
  if citations.any?
    citations.each do |cite|
      # Handle both symbol and string keys
      url = cite[:url] || cite["url"] || ""
      source = cite[:source] || cite["source"] || "source"
      desc = cite[:description] || cite["description"] || ""
      id_val = cite[:id] || cite["id"]
      
      next if id_val.nil? || url.empty?
      
      # Format: [1] Source: Description  
      sections << "[#{id_val}] [#{source}](#{url})"
      sections << "   #{desc}" if !desc.empty? && desc != "Referenced in description"
    end
  elsif actor['external_url']
    sections << "[1] [MITRE ATT&CK](#{actor['external_url']})"
  else
    sections << "*References pending cataloguing.*"
  end
  sections << ""
  
  # Recent News (from RSS feed)
  news_file = '_data/news_feed.yml'
  if File.exist?(news_file)
    begin
      # Try JSON format first, then YAML
      news_data = nil
      content = File.read(news_file).strip
      if content.start_with?('{')
        news_data = JSON.parse(content)
      else
        news_data = YAML.safe_load(content, permitted_classes: [], aliases: false)
      end
      
      if news_data
        actor_name = actor['name']
        
        # Use string keys
        actor_news = news_data['actor_news'] && news_data['actor_news'][actor_name]
        
        if !actor_news && news_data['actor_news']
          # Try case-insensitive match
          news_data['actor_news'].each do |k, v|
            if k.to_s.downcase == actor_name.to_s.downcase
              actor_news = v
              break
            end
          end
        end
        
        if actor_news && actor_news.any?
          sections << "## Recent News"
          sections << "*Latest articles from security news feeds mentioning this actor.*"
          sections << ""
          actor_news.each do |news_item|
            title = news_item['title'] || ''
            link = news_item['link'] || ''
            source = news_item['source'] || ''
            date = news_item['date'] || ''
            
            sections << "- [#{title}](#{link})"
            sections << "  #{source}#{date ? " - #{date[0..10]}" : ""}"
          end
          sections << ""
        end
      end
    rescue
      # Skip if news file has issues
    end
  end
  
  # CISA KEV CVEs (if present)
  if actor['cisa_kev_cves'] && actor['cisa_kev_cves'].any?
    sections << "## CISA Known Exploited Vulnerabilities (KEV)"
    sections << "*The following CVEs are known to be exploited by this actor, listed in the CISA KEV catalog.*"
    sections << ""
    sections << "| CVE ID | Vendor | Product | Date Added |"
    sections << "|-------|-------|--------|----------|"
    actor['cisa_kev_cves'].each do |entry|
      cve = normalize_cisa_kev_entry(entry)
      cve_id = cve['cve'] || cve['cve_id'] || 'N/A'
      next if cve_id == 'N/A' || cve_id == 'cve'

      vendor = cve['vendor'] || 'N/A'
      product = cve['product'] || 'N/A'
      date = cve['dateAdded'] || cve['date_added'] || 'N/A'
      sections << "| #{escape_table_cell(cve_id)} | #{escape_table_cell(vendor)} | #{escape_table_cell(product)} | #{escape_table_cell(date)} |"
    end
    sections << ""
  end
  
  sections.join("\n")
end

def build_deterministic_narrative(actor)
  normalized_description = sanitize_description(actor['description'])
  return normalized_description unless normalized_description.empty?

  # Explicit source description precedence if future importers provide source-specific fields.
  DESCRIPTION_SOURCE_ORDER.each do |source_key|
    field_name = "description_#{source_key}"
    source_description = sanitize_description(actor[field_name])
    return source_description unless source_description.empty?
  end

  build_metadata_fallback_description(actor)
end

def sanitize_description(value)
  value.to_s
       .gsub(/\s+/, ' ')
       .gsub(/\(Citation:\s*[^)]+\)/i, '')
       .strip
end

def build_metadata_fallback_description(actor)
  actor_name = actor['name'] || 'This threat actor'
  sectors = Array(actor['sector_focus']).reject { |entry| entry.to_s.strip.empty? }
  country = actor['country'].to_s.strip
  incident = actor['incident_type'].to_s.strip
  first_seen = actor['first_seen'].to_s.strip
  last_activity = actor['last_activity'].to_s.strip

  fragments = []
  fragments << "#{actor_name} is tracked in this repository based on upstream intelligence sources."
  fragments << "Primary incident classification: #{incident}." unless incident.empty?
  fragments << "Attributed country of origin: #{country}." unless country.empty?
  fragments << "Targeted sectors include #{sectors.first(5).join(', ')}." unless sectors.empty?
  if !first_seen.empty? || !last_activity.empty?
    timeline = []
    timeline << "first seen #{first_seen}" unless first_seen.empty?
    timeline << "active through #{last_activity}" unless last_activity.empty?
    fragments << "Observed timeline: #{timeline.join(', ')}."
  end
  fragments << "This profile is generated automatically and should be interpreted alongside cited source material."

  fragments.join(' ')
end

# Main execution
puts "=" * 60
puts "Threat Actor Page Generator"
puts "=" * 60

FileUtils.mkdir_p(PAGE_DIR)

# Load actor data
puts 'Loading actors from _data/actors/*.yml...'
data = ActorStore.load_all

unless data.is_a?(Array) && data.any?
  abort 'Error: No actors found in _data/actors/*.yml'
end

unless options[:actor_filters].empty?
  requested = options[:actor_filters].map { |value| value.to_s.downcase.gsub(/[^a-z0-9]+/, '') }
  data = data.select do |actor|
    name_key = actor['name'].to_s.downcase.gsub(/[^a-z0-9]+/, '')
    slug_key = actor['url'].to_s.sub(%r{^/}, '').sub(%r{/$}, '').downcase.gsub(/[^a-z0-9]+/, '')
    requested.include?(name_key) || requested.include?(slug_key)
  end
end

puts "Found #{data.length} actors"

# Process each actor
stats = { created: 0, updated: 0, skipped: 0, errors: 0 }

data.each do |actor|
  name = actor['name'] || 'Unknown'
  url = actor['url']&.gsub(/^\/|\/$/, '') || 'unknown'
  
  page_path = File.join(PAGE_DIR, "#{url}.md")
  
  # Check if we should skip (enriched page)
  if File.exist?(page_path) && !options[:force]
    if enriched_page?(page_path)
      puts "SKIP   #{name} - manually enriched page preserved"
      stats[:skipped] += 1
      next
    end
  end
  
  if options[:verbose]
    log "Processing: #{name} -> #{page_path}"
  end
  
  if options[:dry_run]
    puts "DRYRUN #{name} would write #{page_path}"
    stats[:updated] += 1
    next
  end
  
  begin
    front_matter = build_front_matter(actor)
    body = build_body(actor)
    
    content = <<~PAGE
---
#{front_matter}
---

#{body}
    PAGE
    
    action = File.exist?(page_path) ? :updated : :created
    File.write(page_path, content)
    
    puts "#{action.to_s.upcase.ljust(7)} #{name}"
    stats[action] += 1
  rescue => e
    puts "ERROR #{name}: #{e.message}"
    stats[:errors] += 1
  end
end

puts ""
puts "=" * 60
puts "Summary"
puts "=" * 60
puts "Created: #{stats[:created]}"
puts "Updated: #{stats[:updated]}"
puts "Skipped (enriched): #{stats[:skipped]}"
puts "Errors: #{stats[:errors]}"

if stats[:errors].zero?
  puts ""
  puts "Run 'bundle exec jekyll build --safe' to rebuild the site."
else
  puts ""
  puts "Warning: #{stats[:errors]} errors occurred. Check the output above."
end
