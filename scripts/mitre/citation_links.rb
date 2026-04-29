# frozen_string_literal: true

require 'uri'

# Builds global citation-label → URL maps from MITRE ATT&CK STIX external_references
# and replaces inline `(Citation: Label)` markers with Markdown links.
module MitreCitationLinks
  CITATION_MARKER = /\((?:Citation|citation):\s*([^)]+)\)/

  TARGET_TYPES = %w[
    intrusion-set attack-pattern malware tool course-of-action campaign x-mitre-tactic
  ].freeze

  module_function

  def normalize_label(label)
    label.to_s.gsub(/\s+/, ' ').strip
  end

  def normalize_key(label)
    normalize_label(label).downcase
  end

  def extract_citation_label_from_ref_description(desc)
    return nil if desc.nil? || desc.to_s.empty?

    m = desc.to_s.match(CITATION_MARKER)
    m ? normalize_label(m[1]) : nil
  end

  def merge_url(existing, new_url)
    return new_url if existing.nil? || existing.to_s.empty?
    return existing if existing == new_url
    return new_url if existing.start_with?('http://') && new_url.start_with?('https://')
    return existing if new_url.start_with?('http://') && existing.start_with?('https://')

    new_url.length > existing.length ? new_url : existing
  end

  def register_keys!(map, labels, url)
    return if url.nil? || url.to_s.strip.empty?

    u = url.to_s.strip
    return unless u.match?(/\Ahttps?:\/\//i)

    Array(labels).compact.each do |lbl|
      lbl = normalize_label(lbl.to_s)
      next if lbl.empty?

      k = normalize_key(lbl)
      map[k] = merge_url(map[k], u)
    end
  end

  # @param objects_hash [Hash] MitreRelationshipResolver#objects (id => STIX object)
  # @return [Hash<String, String>] normalized lowercase label => https URL
  def build_citation_url_map(objects_hash)
    map = {}

    objects_hash.each_value do |obj|
      next unless obj.is_a?(Hash)
      next unless TARGET_TYPES.include?(obj['type'])

      Array(obj['external_references']).each do |ref|
        next unless ref.is_a?(Hash)

        url = ref['url'].to_s.strip
        next if url.empty?
        next unless url.match?(/\Ahttps?:\/\//i)

        source = ref['source_name'].to_s
        next if source == 'mitre-attack'

        labels = []
        labels << normalize_label(source) unless source.empty?

        desc = ref['description'].to_s
        if (cl = extract_citation_label_from_ref_description(desc))
          labels << cl
        elsif !desc.empty? && !desc.include?('Citation:')
          labels << normalize_label(desc)
        end

        register_keys!(map, labels.uniq, url)
      end
    end

    map
  end

  # Replace MITRE-style `(Citation: Label)` with `[Label](url)` when map has a URL.
  def linkify_mitre_citations(text, map)
    return text if text.nil? || map.nil? || map.empty?

    s = text.to_s
    return s unless s.include?('(Citation:')

    s.gsub(CITATION_MARKER) do
      raw_label = Regexp.last_match(1)
      label_disp = normalize_label(raw_label)
      key = normalize_key(raw_label)
      url = map[key]

      if url && !url.to_s.empty?
        safe_url = sanitize_url_for_markdown(url.to_s.strip)
        "[#{label_disp}](#{safe_url})"
      else
        "(Citation: #{raw_label})"
      end
    end
  end

  def sanitize_url_for_markdown(url)
    u = url.to_s.strip
    parsed = URI.parse(u)
    scheme = parsed.scheme.to_s.downcase
    return u if scheme == 'http' || scheme == 'https'

    u
  rescue URI::InvalidURIError
    u
  end

  def citation_map_to_json_object(map)
    map.keys.sort.each_with_object({}) { |k, h| h[k] = map[k] }
  end
end
