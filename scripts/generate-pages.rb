#!/usr/bin/env ruby
# frozen_string_literal: true

# Page Generator - Generates all threat actor pages from YAML data
#
# Usage:
#   ruby scripts/generate-pages.rb              # Generate all pages
#   ruby scripts/generate-pages.rb --force    # Overwrite existing pages
#   ruby scripts/generate-pages.rb --dry-run   # Preview without writing
#
# This script reads from _data/threat_actors.yml and generates page content
# from the YAML data, preserving manually-enriched pages.

require 'fileutils'
require 'yaml'
require 'optparse'

PAGE_DIR = '_threat_actors'
DATA_FILE = '_data/threat_actors.yml'

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
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "Usage: ruby scripts/generate-pages.rb [options]"
  opts.on("--force", "Overwrite existing pages") { |v| options[:force] = v }
  opts.on("--dry-run", "Preview only, don't write") { |v| options[:dry_run] = v }
  opts.on("-v", "--verbose", "Show detailed output") { |v| options[:verbose] = v }
end.parse!

def log(msg)
  puts msg if ENV['VERBOSE'] || $VERBOSE
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
  if actor['aliases'] && actor['aliases'].any?
    aliases = actor['aliases'].map { |a| "\"#{a}\"" }.join(', ')
    lines << "aliases: [#{aliases}]"
  end
  
  # Description
  if actor['description']
    lines << "description: \"#{actor['description'].gsub('"', '\\"').gsub("\n", ' ')[0..200]}\""
  end
  
  # Permalink - ensure trailing slash
  url = actor['url']&.gsub(/\/$/, '') || 'unknown'
  lines << "permalink: #{url}/"
  
  # Optional fields
  ['country', 'first_seen', 'last_activity', 'risk_level', 'external_id'].each do |field|
    lines << "#{field}: \"#{actor[field]}\"" if actor[field]
  end
  
  # Add country_flag if country exists
  if actor['country']
    flag = get_country_flag(actor['country'])
    lines << "country_flag: \"#{flag}\""
  end
  
  # Sector focus
  if actor['sector_focus'] && actor['sector_focus'].any?
    sectors = actor['sector_focus'].map { |s| "\"#{s}\"" }.join(', ')
    lines << "sector_focus: [#{sectors}]"
  end
  
  # Source attribution
  if actor['source_attribution']
    lines << "source_attribution: \"#{actor['source_attribution'].gsub('"', '\\"')}\""
  end
  
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
  "VN" => "🇻🇳", "UA" => "🇺🇦",
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

# Build page body from YAML data
def build_body(actor)
  sections = []
  
  # Introduction
  sections << "## Introduction"
  sections << actor['description'] || "No description available."
  sections << ""
  
  # Activities and Tactics
  sections << "## Activities and Tactics"
  if actor['country'] || actor['sector_focus']
    details = []
    details << "**Targeted Sectors**: #{actor['sector_focus']&.join(', ') || 'Various'}" if actor['sector_focus']
    flag = get_country_flag(actor['country'])
    details << "**Country of Origin**: #{flag} #{actor['country'] || 'Unknown'}" if actor['country']
    details << "**Risk Level**: #{actor['risk_level'] || 'Medium'}" if actor['risk_level']
    details << "**First Seen**: #{actor['first_seen'] || 'Unknown'}" if actor['first_seen']
    details << "**Last Activity**: #{actor['last_activity'] || 'Unknown'}" if actor['last_activity']
    sections << details.join("\n")
  else
    sections << "*Information pending cataloguing.*"
  end
  sections << ""
  
  # Notable Campaigns - from YAML if present
  sections << "### Notable Campaigns"
  if actor['campaigns'] && actor['campaigns'].any?
    actor['campaigns'].each do |campaign|
      name = campaign['name'] || 'Unnamed Campaign'
      date = campaign['date'] || ''
      desc = campaign['description'] || ''
      sections << "- **#{name}** (#{date}): #{desc}"
    end
  else
    sections << "*Information pending cataloguing.*"
  end
  sections << ""
  
  # TTPs
  sections << "### Tactics, Techniques, and Procedures (TTPs)"
  if actor['ttps'] && actor['ttps'].any?
    actor['ttps'].each do |ttp|
      tid = ttp['technique_id'] || ''
      tname =ttp['technique_name'] || ''
      desc = ttp['description'] || ''
      sections << "- **#{tid} #{tname}**: #{desc}"
    end
  else
    sections << "*Information pending cataloguing.*"
  end
  sections << ""
  
  # IOCs section header
  sections << "## Notable Indicators of Compromise (IOCs)"
  sections << "*This section is pending cataloguing. Check upstream sources for current IOCs.*"
  sections << ""
  sections << "### IP Addresses"
  if actor['iocs'] && actor['iocs']['ips'] && actor['iocs']['ips'].any?
    actor['iocs']['ips'].each do |ip|
      sections << "- `#{ip}`"
    end
  else
    sections << "*Pending*"
  end
  sections << ""
  sections << "### File Hashes"
  if actor['iocs'] && (actor['iocs']['md5'] || actor['iocs']['sha256'])
    actor['iocs']['md5']&.each { |h| sections << "- `#{h}` (MD5)" }
    actor['iocs']['sha256']&.each { |h| sections << "- `#{h}` (SHA256)" }
  else
    sections << "*Pending*"
  end
  sections << ""
  sections << "### Domains"
  if actor['iocs'] && actor['iocs']['domains'] && actor['iocs']['domains'].any?
    actor['iocs']['domains'].each do |d|
      sections << "- `#{d}`"
    end
  else
    sections << "*Pending*"
  end
  sections << ""
  
  # Malware
  sections << "## Malware and Tools"
  if actor['malware'] && actor['malware'].any?
    actor['malware'].each do |m|
      name = m['name'] || 'Unknown'
      desc = m['description'] || ''
      sections << "- **#{name}**: #{desc}"
    end
  else
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
  
  # References
  sections << "## References"
  if actor['references'] && actor['references'].any?
    actor['references'].each do |ref|
      url = ref['url'] || ''
      title = ref['title'] || ref['source'] || url
      date = ref['date'] || ''
      sections << "- [#{title}](#{url}) #{date}"
    end
  elsif actor['external_url']
    sections << "- [MITRE ATT&CK](#{actor['external_url']})"
  else
    sections << "*References pending cataloguing.*"
  end
  
  sections.join("\n")
end

# Main execution
puts "=" * 60
puts "Threat Actor Page Generator"
puts "=" * 60

# Check for required files
unless File.exist?(DATA_FILE)
  abort "Error: #{DATA_FILE} not found!"
end

FileUtils.mkdir_p(PAGE_DIR)

# Load actor data
puts "Loading actors from #{DATA_FILE}..."
data = YAML.safe_load(File.read(DATA_FILE), permitted_classes: [], aliases: false)

unless data.is_a?(Array) && data.any?
  abort "Error: No actors found in #{DATA_FILE}"
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