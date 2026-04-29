# frozen_string_literal: true

# Shared merge utilities for threat actor importers (MITRE, etc.)
module ImportUtils
  module_function

  def canonical_key(value)
    return nil if value.nil? || value.to_s.strip.empty?

    value.to_s
         .downcase
         .gsub(/0/, 'o')
         .gsub(/1/, 'l')
         .gsub(/3/, 'e')
         .gsub(/4/, 'a')
         .gsub(/5/, 's')
         .gsub(/[@\-_\s]+/, '')
         .strip
  end

  def build_alias_index(actors)
    index = {}

    actors.each_with_index do |actor, position|
      name_key = canonical_key(actor['name'])
      if name_key
        index[name_key] ||= []
        index[name_key] << position
      end

      Array(actor['aliases']).each do |alias_name|
        alias_key = canonical_key(alias_name)
        next if alias_key.nil? || alias_key.empty?

        index[alias_key] ||= []
        index[alias_key] << position
      end

      url_slug = actor['url']&.gsub(%r{^/|/$}, '')
      if url_slug
        index[url_slug] ||= []
        index[url_slug] << position
      end
    end

    index
  end

  def find_match(candidate_name, candidate_aliases, index)
    keys = [canonical_key(candidate_name)]
    keys.concat(Array(candidate_aliases).map { |a| canonical_key(a) })
    keys.compact!
    keys.uniq!
    keys.reject!(&:empty?)

    return nil if keys.empty?

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

    if incoming['references'].is_a?(Array) && incoming['references'].any?
      merged['references'] = merge_actor_reference_lists(existing['references'], incoming['references'])
    end

    merged
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
