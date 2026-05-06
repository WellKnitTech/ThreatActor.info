# frozen_string_literal: true

require 'yaml'

# Shared actor name / alias resolution for importers (MITRE, MISP Galaxy, ThreatFox, etc.).
# Builds the same normalized index as legacy ImportUtils callers expect, with optional
# cross-source hints from data/imports/alias_synonyms.yml.
module AliasResolver
  module_function

  SYNONYMS_PATH = File.expand_path('../../data/imports/alias_synonyms.yml', __dir__).freeze

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

  def build_alias_index(actors, synonym_path: SYNONYMS_PATH)
    index = {}

    Array(actors).each_with_index do |actor, position|
      next unless actor.is_a?(Hash)

      add_actor_keys!(index, actor, position)
    end

    merge_synonym_entries!(index, actors, synonym_path) if synonym_path && File.file?(synonym_path)

    index
  end

  def find_match(candidate_name, candidate_aliases, index)
    find_match_extended(candidate_name, candidate_aliases, index)
  end

  def find_match_extended(candidate_name, candidate_aliases, index, mitre_id: nil, external_id: nil)
    keys = [canonical_key(candidate_name)]
    keys.concat(Array(candidate_aliases).map { |a| canonical_key(a) })
    [mitre_id, external_id].compact.each do |id|
      k = id_index_key(id)
      keys << k if k && !keys.include?(k)
    end
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

  # Resolve a name (+ optional aliases) to a canonical actor slug and match quality.
  # actors: array of actor hashes (e.g. ActorStore.load_all)
  def resolve(candidate_name, candidate_aliases, actors, synonym_path: SYNONYMS_PATH)
    index = build_alias_index(actors, synonym_path: synonym_path)
    m = find_match(candidate_name, candidate_aliases, index)
    return { slug: nil, position: nil, confidence: :none, candidates: [] } if m.nil?

    if m[:confidence] == :ambiguous
      names = Array(m[:positions]).map { |i| actors[i]&.dig('name') }.compact
      return { slug: nil, position: nil, confidence: :ambiguous, candidates: names }
    end

    pos = m[:position]
    actor = actors[pos]
    slug = url_slug(actor)
    { slug: slug, position: pos, confidence: :high, candidates: [] }
  end

  def url_slug(actor)
    return nil unless actor.is_a?(Hash)

    s = actor['url'].to_s.sub(%r{^/|/$}, '')
    s.empty? ? nil : s
  end

  def boost_confidence_from_provenance!(actor)
    return unless actor.is_a?(Hash)

    prov = actor['provenance']
    return unless prov.is_a?(Hash)

    has_mitre = prov.key?('mitre') || prov.key?(:mitre)
    other = prov.keys.map(&:to_s) - %w[mitre]
    return unless has_mitre && other.any?

    cur = actor['confidence']
    return if cur.to_s.downcase == 'high'

    actor['confidence'] = 'high'
  end

  def add_actor_keys!(index, actor, position)
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

    slug = actor['url']&.gsub(%r{^/|/$}, '')
    if slug
      index[slug] ||= []
      index[slug] << position
    end

    %w[mitre_id external_id].each do |field|
      key = id_index_key(actor[field])
      next if key.nil? || key.empty?

      index[key] ||= []
      index[key] << position
    end
  end

  # MITRE-style IDs must not use leet-style canonicalization (e.g. G0034 would break).
  def id_index_key(value)
    s = value.to_s.strip.downcase.gsub(/\s+/, '')
    s.empty? ? nil : s
  end

  def merge_synonym_entries!(index, actors, synonym_path)
    data = YAML.safe_load(File.read(synonym_path), permitted_classes: [], aliases: true) || {}
    entries = data['entries'] || data[:entries] || []
    return unless entries.is_a?(Array)

    url_to_position = {}
    actors.each_with_index do |actor, i|
      next unless actor.is_a?(Hash)

      s = url_slug(actor)
      url_to_position[s] = i if s && !s.empty?
    end

    entries.each do |entry|
      next unless entry.is_a?(Hash)

      alias_str = entry['alias'] || entry[:alias]
      url = entry['url'] || entry[:url]
      next if alias_str.to_s.strip.empty? || url.to_s.strip.empty?

      slug = url.to_s.strip.sub(%r{\A/}, '').sub(%r{/\z}, '')
      pos = url_to_position[slug]
      next unless pos

      k = canonical_key(alias_str)
      next if k.nil? || k.empty?

      index[k] ||= []
      index[k] << pos
      index[k].uniq!
    end
  end
end
