#!/usr/bin/env ruby
# MITRE ATT&CK Threat Actor Importer with Smart Merge
# 
# Imports threat actors from MITRE ATT&CK STIX 2.1 data with alias-based merging
# Source: https://github.com/mitre-attack/attack-stix-data
#
# Attribution: "© The MITRE Corporation. This work is reproduced and distributed 
#               with the permission of The MITRE Corporation."
#
# Usage:
#   ruby scripts/import-mitre.rb --dry-run     # Preview merge decisions
#   ruby scripts/import-mitre.rb --write       # Apply merges
#   ruby scripts/import-mitre.rb --overwrite   # Force overwrite existing

require 'json'
require 'yaml'
require 'fileutils'
require 'optparse'
require 'net/http'
require 'uri'
require 'time'
require_relative 'actor_store'

# Configuration
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
THREAT_ACTORS_DIR = "_threat_actors"

# Options
options = {
  write: false,
  overwrite: false,
  skip_revoked: true,
  dry_run: false,
  verbose: false
}

OptionParser.new do |opts|
  opts.banner = "Usage: ruby scripts/import-mitre.rb [options]"
  opts.on("--write", "Apply changes (without this, runs in preview mode)") { |v| options[:write] = v }
  opts.on("--overwrite", "Overwrite existing actor data (default: merge/keep existing)") { |v| options[:overwrite] = v }
  opts.on("--include-revoked", "Include revoked/deprecated groups") { |v| options[:skip_revoked] = !v }
  opts.on("--dry-run", "Preview what would be imported (default)") { |v| options[:dry_run] = v }
  opts.on("-v", "--verbose", "Show detailed output") { |v| options[:verbose] = v }
end.parse!

# ============================================================================
# Import Utilities - Shared merge logic
# ============================================================================

module ImportUtils
  # Normalize a string for matching (canonical key)
  def canonical_key(value)
    return nil if value.nil? || value.to_s.strip.empty?
    
    value.to_s
         .downcase
         .gsub(/0/, 'o')
         .gsub(/1/, 'l')
         .gsub(/3/, 'e')
         .gsub(/4/, 'a')
         .gsub(/5/, 's')
         .gsub(/[@\-_\s]+/, '')  # Remove common separators
         .strip
  end

  # Build an index of existing actors for fast alias lookup
  def build_alias_index(actors)
    index = {}
    
    actors.each_with_index do |actor, position|
      # Index by canonical name
      name_key = canonical_key(actor['name'])
      if name_key
        index[name_key] ||= []
        index[name_key] << position
      end
      
      # Index by each alias
      Array(actor['aliases']).each do |alias_name|
        alias_key = canonical_key(alias_name)
        next if alias_key.nil? || alias_key.empty?
        index[alias_key] ||= []
        index[alias_key] << position
      end
      
      # Index by URL slug
      url_slug = actor['url']&.gsub(/^\/|\/$/, '')
      if url_slug
        index[url_slug] ||= []
        index[url_slug] << position
      end
    end
    
    index
  end

  # Find existing actor matching a candidate by name or aliases
  def find_match(candidate_name, candidate_aliases, index)
    # Build list of keys to check
    keys = [canonical_key(candidate_name)]
    keys.concat(Array(candidate_aliases).map { |a| canonical_key(a) })
    keys.compact!
    keys.uniq!
    keys.reject! { |k| k.empty? }
    
    return nil if keys.empty?
    
    # Find all positions that match any key
    matches = keys.flat_map { |key| index[key] || [] }.uniq
    
    case matches.length
    when 0
      nil
    when 1
      { position: matches.first, confidence: :high }
    else
      { positions: matches, confidence: :ambiguous }
    end
  end

  # Merge existing actor with incoming data
  # Strategy: Keep existing enriched fields, add MITRE-specific fields, merge aliases
  def merge_actors(existing, incoming, source_name)
    merged = existing.dup
    
    # Merge aliases (union, deduped, sorted)
    existing_aliases = Array(existing['aliases']).map(&:to_s)
    incoming_aliases = Array(incoming['aliases']).map(&:to_s)
    combined_aliases = (existing_aliases + incoming_aliases).uniq.sort_by(&:downcase)
    merged['aliases'] = combined_aliases if combined_aliases != existing_aliases
    
    # Update last_activity if incoming is newer
    if incoming['last_activity']
      current_year = existing['last_activity']&.to_i || 0
      incoming_year = incoming['last_activity']&.to_i || 0
      if incoming_year > current_year
        merged['last_activity'] = incoming['last_activity']
      end
    end
    
    # For description: keep existing unless it's substantially longer
    if incoming['description'] && incoming['description'].length > (existing['description']&.length || 0) + 200
      merged['description'] = incoming['description']
    end
    
    # Add source-specific fields (don't overwrite existing)
    source_fields = %w[external_id external_url mitre_id mitre_url]
    source_fields.each do |field|
      if incoming[field] && !merged[field]
        merged[field] = incoming[field]
      end
    end
    
    # Add source attribution if not present
    if incoming['source_attribution'] && !merged['source_attribution']
      merged['source_attribution'] = incoming['source_attribution']
    end
    
    # Don't merge references into YAML (keeps YAML small)
    # References are processed at page generation time
    
    # Merge provenance
    existing_prov = existing['provenance'].is_a?(Hash) ? existing['provenance'] : {}
    incoming_prov = incoming['provenance'] || {}
    
    # Add source to provenance with timestamp
    source_key = source_name.downcase.gsub(/\s+/, '_')
    existing_prov[source_key] = {
      'source_retrieved_at' => Time.now.utc.iso8601,
      'source_record_id' => incoming['external_id'] || incoming['mitre_id'],
      'source_dataset_url' => MITRE_STIX_URL
    }
    
    merged['provenance'] = existing_prov
    
    merged
  end
end

include ImportUtils

# ============================================================================
# MITRE-specific functions
# ============================================================================

def slugify(name)
  return nil if name.nil? || name.empty?
  
  slug = name.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
  
  # Handle special cases: G0016 -> apt0016 style for MITRE IDs
  # BUT keep consistent with existing URLs (no trailing slash)
  if slug =~ /^g\d+$/
    "apt#{slug[1..-1]}"
  else
    slug
  end
end

def load_existing_actors
  ActorStore.load_all
end

def fetch_mitre_data
  puts "Fetching MITRE ATT&CK data..."
  
  uri = URI.parse(MITRE_STIX_URL)
  response = Net::HTTP.get_response(uri)
  
  unless response.is_a?(Net::HTTPSuccess)
    raise "Failed to fetch MITRE data: #{response.code} #{response.message}"
  end
  
  JSON.parse(response.body)
end

def extract_intrusion_sets(bundle)
  objects = bundle['objects'] || []
  
  intrusion_sets = objects.select do |obj|
    obj['type'] == 'intrusion-set'
  end
  
  puts "Found #{intrusion_sets.length} intrusion sets in STIX bundle"
  intrusion_sets
end

def parse_mitre_actor(intrusion_set, opts)
  name = intrusion_set['name']
  return nil if name.nil? || name.empty?
  
  # Skip revoked/deprecated if configured
  if opts[:skip_revoked]
    return nil if intrusion_set['revoked'] == true
    return nil if intrusion_set['x_mitre_deprecated'] == true
  end
  
  # Extract MITRE ATT&CK ID and URL
  external_id = nil
  mitre_url = nil
  
  # Extract all external references for citations
  references = []
  (intrusion_set['external_references'] || []).each do |ref|
    source = ref['source_name'] || ref['source'] || 'unknown'
    raw_url = ref['url'] || ''
    
    # Clean URLs - truncate long PDF/tracking URLs
    url = clean_ref_url(raw_url)
    
    ref_data = {
      'source' => source,
      'url' => url,
      'description' => clean_ref_description(ref['description'])
    }
    references << ref_data
    
    # Track MITRE ATT&CK specific data
    if source == 'mitre-attack'
      external_id = ref['external_id']
      mitre_url = ref['url']
    end
  end
  
  # Generate URL slug
  url_slug = slugify(external_id || name)
  
# Build actor data
  actor = {
    'name' => name,
    'aliases' => intrusion_set['aliases'] || [],
    'description' => clean_description(intrusion_set['description']),
    'url' => "/#{url_slug}/",  # Trailing slash!
    'external_id' => external_id,
    'mitre_id' => external_id,
    'external_url' => mitre_url,
    'mitre_url' => mitre_url,
    'references' => references,
    'source' => 'MITRE ATT&CK',
    'source_attribution' => "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
    'provenance' => {
      'mitre' => {
        'source_retrieved_at' => Time.now.utc.iso8601,
        'source_record_id' => external_id || name,
        'source_dataset_url' => MITRE_STIX_URL
      }
    }
  }

  actor
end

def clean_ref_description(desc)
  return nil if desc.nil? || desc.empty?
  
  # Truncate if too long
  if desc.length > 500
    desc = desc[0..497] + "..."
  end
  
  desc
end

def clean_ref_url(url)
  return nil if url.nil? || url.empty?
  
  # Clean up long PDF URLs - remove tracking parameters
  # Keep only the base URL
  if url.include?('pdf') || url.include?('#zoom')
    # Try to extract clean base URL
    base = url.split('#').first.split('?').first
    return base if base.length < url.length && base.length > 20
  end
  
  # Truncate very long URLs
  if url.length > 200
    # Keep domain + first path segment
    uri = URI.parse(url)
    short = "#{uri.scheme}://#{uri.host}#{uri.path[/^\/[^\/]{1,30}/]}"
    return short + "..." if short.length < url.length - 50
  end
  
  url
end

def clean_description(desc)
  return "" if desc.nil?
  
  # Clean up markdown links from MITRE [name](url) format
  desc = desc.gsub(/\[([^\]]+)\]\([^)]+\)/, '\1')
  
  # Clean up HTML entities
  desc = desc.gsub(/&amp;/, '&')
  desc = desc.gsub(/&lt;/, '<')
  desc = desc.gsub(/&gt;/, '>')
  desc = desc.gsub(/&quot;/, '"')
  
  # Truncate if too long
  if desc.length > 2000
    desc = desc[0..1997] + "..."
  end
  
  desc
end

# ============================================================================
# Main execution
# ============================================================================

puts "=" * 60
puts "MITRE ATT&CK Threat Actor Importer (Smart Merge)"
puts "=" * 60

# Load existing actors
existing_actors = load_existing_actors
puts "Loaded #{existing_actors.length} existing actors"

# Build alias index for matching
alias_index = build_alias_index(existing_actors)
puts "Built alias index with #{alias_index.keys.length} keys"

# Fetch MITRE data
bundle = fetch_mitre_data
intrusion_sets = extract_intrusion_sets(bundle)

# Process each intrusion set
results = {
  create: [],
  merge: [],
  skip: [],
  review: []
}

intrusion_sets.each do |intrusion_set|
  actor = parse_mitre_actor(intrusion_set, options)
  
  if actor.nil?
    results[:skip] << { name: intrusion_set['name'], reason: 'revoked/deprecated' }
    next
  end
  
  # Find match in existing actors
  match = find_match(actor['name'], actor['aliases'], alias_index)
  
  if match && match[:confidence] == :high
    # Found a match - will merge
    existing = existing_actors[match[:position]]
    results[:merge] << {
      incoming: actor,
      existing_index: match[:position],
      existing_name: existing['name'],
      url: existing['url']
    }
  elsif match && match[:confidence] == :ambiguous
    # Multiple matches - need review
    candidates = match[:positions].map { |i| existing_actors[i]['name'] }
    results[:review] << {
      incoming: actor,
      candidates: candidates
    }
  else
    # No match - create new
    results[:create] << actor
  end
end

# Display results
puts "\n" + "=" * 60
puts "MERGE DECISIONS"
puts "=" * 60

puts "\n[CREATE] New actors to create: #{results[:create].length}"
results[:create].first(10).each do |a|
  puts "  - #{a['name']} (#{a['external_id']})"
end
puts "  ... and #{results[:create].length - 10} more" if results[:create].length > 10

puts "\n[MERGE] Actors to merge (add MITRE data to existing): #{results[:merge].length}"
results[:merge].first(10).each do |m|
  puts "  - #{m[:incoming]['name']} (#{m[:incoming]['external_id']}) -> #{m[:existing_name]}#{m[:url]}"
end
puts "  ... and #{results[:merge].length - 10} more" if results[:merge].length > 10

puts "\n[REVIEW] Ambiguous matches (multiple existing actors match): #{results[:review].length}"
results[:review].first(5).each do |r|
  puts "  - #{r[:incoming]['name']} matches: #{r[:candidates].join(', ')}"
end
puts "  ... and #{results[:review].length - 5} more" if results[:review].length > 5

puts "\n[SKIP] Skipped (revoked/deprecated): #{results[:skip].length}"

# Ask for confirmation unless --write
unless options[:write]
  puts "\n--- Dry run complete. No files written. ---"
  puts "Run with --write to apply these changes."
  exit 0
end

# Apply merges and creates
puts "\nApplying changes..."

# Process merges
results[:merge].each do |m|
  existing = existing_actors[m[:existing_index]]
  merged = merge_actors(existing, m[:incoming], 'MITRE')
  existing_actors[m[:existing_index]] = merged
  puts "  [MERGE] #{m[:incoming]['name']} -> #{m[:existing_name]}"
end

# Process creates - add new entries
results[:create].each do |actor|
  existing_actors << actor
  puts "  [CREATE] #{actor['name']}"
end

# Write updated YAML
puts "\nWriting _data/actors/*.yml..."
ActorStore.save_all(existing_actors)

# Save references cache for page generation
# Extract from actors that came from MITRE (have external_id)
ref_cache = {}
ref_count = 0

existing_actors.each do |actor|
  name = actor['name']
  next unless name
  
  # Extract references from actor
  refs = actor.delete('references') || []
  if refs.any?
    ref_cache[name] = refs
    ref_count += refs.size
  end
end

# Save cache to JSON
ref_cache_file = "_data/references.json"
File.write(ref_cache_file, JSON.pretty_generate(ref_cache))
puts "Saved #{ref_cache.size} actor references (#{ref_count} total) to cache"

# Restore references to actors (for in-memory processing)
existing_actors.each do |actor|
  actor['references'] = ref_cache[actor['name']] if ref_cache[actor['name']]
end

# Create/update markdown pages for new actors
FileUtils.mkdir_p(THREAT_ACTORS_DIR)

results[:create].each do |actor|
  url = actor['url'].gsub(/^\/|\/$/, '')
  filename = File.join(THREAT_ACTORS_DIR, "#{url}.md")
  
  front_matter = {
    'layout' => 'threat_actor',
    'title' => actor['name'],
    'aliases' => actor['aliases'],
    'description' => actor['description'][0..200],
    'permalink' => actor['url'],
    'external_id' => actor['external_id'],
    'source_attribution' => actor['source_attribution']
  }
  
  # Generate YAML front matter - use proper YAML formatting
  yaml_lines = []
  yaml_lines << "layout: #{front_matter['layout']}"
  yaml_lines << "title: \"#{front_matter['title']}\""
  # Format aliases as inline YAML array
  aliases_str = front_matter['aliases'].map { |a| "\"#{a}\"" }.join(", ")
  yaml_lines << "aliases: [#{aliases_str}]"
  yaml_lines << "description: \"#{front_matter['description'].gsub('"', '\\\\"')}\""
  yaml_lines << "permalink: #{front_matter['permalink']}"
  yaml_lines << "external_id: #{front_matter['external_id']}"
  yaml_lines << "source_attribution: \"#{front_matter['source_attribution'].gsub('"', '\\\\"')}\""
  
  # Complete page with all standardized sections
  content = <<~CONTENT
---
#{yaml_lines.join("\n")}
---

## Introduction
#{actor['description']}

## Activities and Tactics
*Information pending cataloguing.*

### Notable Campaigns
*Information pending cataloguing.*

### Tactics, Techniques, and Procedures (TTPs)
*Information pending cataloguing.*

## Notable Indicators of Compromise (IOCs)
*This section is pending cataloguing. Check upstream sources for current IOCs.*

### IP Addresses
*Pending*

### File Hashes
*Pending*

### Domains
*Pending*

### URLs
*Pending*

## Malware and Tools
*Information pending cataloguing.*

## Attribution and Evidence
#{actor['source_attribution']}

### Attribution
*Information pending cataloguing.*

## References
- [MITRE ATT&CK - #{actor['name']}](#{actor['mitre_url']})
  CONTENT
  
  File.write(filename, content)
  puts "  [CREATE] #{filename}"
end

puts "\n✓ Import complete!"
puts "  Created: #{results[:create].length} new actors"
puts "  Merged: #{results[:merge].length} existing actors"
puts "  Review needed: #{results[:review].length}"

# Validation reminder
puts "\nRun validation:"
puts "  ruby scripts/validate-content.rb"
puts "  bundle exec jekyll build --safe"