# frozen_string_literal: true

require_relative 'lib/alias_resolver'

# Shared merge utilities for threat actor importers (MITRE, etc.)
module ImportUtils
  module_function

  def canonical_key(value)
    AliasResolver.canonical_key(value)
  end

  def build_alias_index(actors)
    AliasResolver.build_alias_index(actors)
  end

  def find_match(candidate_name, candidate_aliases, index, mitre_id: nil, external_id: nil)
    AliasResolver.find_match_extended(candidate_name, candidate_aliases, index,
                                      mitre_id: mitre_id, external_id: external_id)
  end

  # dataset_urls: Hash like { 'enterprise' => url, ... } or a single URL string
  def merge_actors(existing, incoming, source_name, dataset_urls = nil)
    merged = existing.dup

    existing_aliases = Array(existing['aliases']).map(&:to_s)
    incoming_aliases = Array(incoming['aliases']).map(&:to_s)
    combined_aliases = (existing_aliases + incoming_aliases).uniq.sort_by(&:downcase)
    merged['aliases'] = combined_aliases if combined_aliases != existing_aliases

    if incoming['last_activity']
      current_year = existing['last_activity']&.to_i || 0
      incoming_year = incoming['last_activity']&.to_i || 0
      merged['last_activity'] = incoming['last_activity'] if incoming_year > current_year
    end

    if incoming['description'] && incoming['description'].length > (existing['description']&.length || 0) + 200
      merged['description'] = incoming['description']
    end

    %w[external_id external_url mitre_id mitre_url].each do |field|
      merged[field] ||= incoming[field] if incoming[field]
    end

    merged['source_attribution'] ||= incoming['source_attribution'] if incoming['source_attribution']

    source_key = source_name.downcase.gsub(/\s+/, '_')
    existing_prov = existing['provenance'].is_a?(Hash) ? existing['provenance'].dup : {}
    mitre_block = existing_prov[source_key].is_a?(Hash) ? existing_prov[source_key].dup : {}

    mitre_block['source_retrieved_at'] = Time.now.utc.iso8601
    mitre_block['source_record_id'] = incoming['external_id'] || incoming['mitre_id'] || mitre_block['source_record_id']

    case dataset_urls
    when Hash
      mitre_block['source_dataset_urls'] = dataset_urls
      mitre_block['source_dataset_url'] ||= dataset_urls.values.compact.first
    when String
      mitre_block['source_dataset_url'] = dataset_urls
    end

    if incoming['provenance'].is_a?(Hash) && incoming['provenance'][source_key].is_a?(Hash)
      mitre_block.merge!(incoming['provenance'][source_key])
    end

    existing_prov[source_key] = mitre_block
    merged['provenance'] = existing_prov

    merged['ttps'] = incoming['ttps'] if incoming.key?('ttps')
    merged['software'] = incoming['software'] if incoming.key?('software')
    merged['campaigns'] = incoming['campaigns'] if incoming.key?('campaigns')

    merged['attck_techniques'] = incoming['attck_techniques'] if incoming.key?('attck_techniques')
    merged['attck_software'] = incoming['attck_software'] if incoming.key?('attck_software')

    if incoming['attck_references'].is_a?(Array) && incoming['attck_references'].any?
      merged['attck_references'] = merge_attck_reference_lists(merged['attck_references'], incoming['attck_references'])
    end

    if incoming['sources'].is_a?(Array) && incoming['sources'].any?
      merged['sources'] = merge_source_entries(merged['sources'], incoming['sources'])
    end

    %w[victim_countries targeted_sectors].each do |field|
      next unless incoming[field].is_a?(Array) && incoming[field].any?

      merged[field] = (Array(merged[field]) + incoming[field]).map(&:to_s).uniq.sort
    end

    if incoming.key?('iocs_count') && incoming['iocs_count'].to_i.positive?
      prev = merged['iocs_count'].to_i
      merged['iocs_count'] = [prev, incoming['iocs_count'].to_i].max
    end

    merged['confidence'] = incoming['confidence'] if incoming.key?('confidence') && !incoming['confidence'].nil?

    if incoming['references'].is_a?(Array) && incoming['references'].any?
      merged['references'] = merge_actor_reference_lists(existing['references'], incoming['references'])
    end

    merged
  end

  def merge_source_entries(existing, incoming)
    seen = {}
    out = []
    Array(existing).concat(Array(incoming)).each do |row|
      next unless row.is_a?(Hash)

      src = row['source'].to_s.strip
      at = row['imported_at'].to_s.strip
      next if src.empty? || at.empty?

      sig = "#{src}\t#{at}"
      next if seen[sig]

      seen[sig] = true
      out << row
    end
    out
  end

  def merge_attck_reference_lists(existing, incoming)
    seen = {}
    out = []
    Array(existing).concat(Array(incoming)).each do |r|
      next unless r.is_a?(Hash)

      sig = r['url'].to_s.empty? ? "#{r['source']}\t#{r['external_id']}" : r['url'].to_s
      next if sig.strip.empty?
      next if seen[sig]

      seen[sig] = true
      out << r
    end
    out
  end

  def merge_actor_reference_lists(existing, incoming)
    ex = Array(existing)
    inc = Array(incoming)
    seen = {}
    out = []
    (ex + inc).each do |r|
      next unless r.is_a?(Hash)

      url = r['url'].to_s
      src = (r['source'] || r['source_name']).to_s
      sig = url.empty? ? "#{src}\t#{r['description']}" : url
      next if sig.strip.empty?
      next if seen[sig]

      seen[sig] = true
      out << r
    end
    out
  end
end
