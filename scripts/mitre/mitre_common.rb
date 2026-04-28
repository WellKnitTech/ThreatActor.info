# frozen_string_literal: true

# Shared helpers for MITRE ATT&CK STIX import.
# Source: https://github.com/mitre-attack/attack-stix-data

module MitreCommon
  SOURCE_ATTRIBUTION = '© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.'.freeze
  RAW_BASE = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master'.freeze
  INDEX_JSON_URL = "#{RAW_BASE}/index.json".freeze

  DOMAIN_FILES = {
    'enterprise' => { folder: 'enterprise-attack', file: 'enterprise-attack.json' },
    'mobile' => { folder: 'mobile-attack', file: 'mobile-attack.json' },
    'ics' => { folder: 'ics-attack', file: 'ics-attack.json' }
  }.freeze

  module_function

  def bundle_url(domain_key)
    info = DOMAIN_FILES[domain_key] || raise(ArgumentError, "Unknown domain: #{domain_key}")
    "#{RAW_BASE}/#{info[:folder]}/#{info[:file]}"
  end

  def mitre_external_id(obj)
    return nil unless obj.is_a?(Hash)

    (obj['external_references'] || []).each do |ref|
      next unless ref.is_a?(Hash)

      name = ref['source_name'] || ref['source']
      next unless name.to_s == 'mitre-attack'

      eid = ref['external_id']
      return eid if eid && !eid.to_s.empty?
    end
    nil
  end

  def mitre_external_url(obj)
    return nil unless obj.is_a?(Hash)

    (obj['external_references'] || []).each do |ref|
      next unless ref.is_a?(Hash)

      name = ref['source_name'] || ref['source']
      next unless name.to_s == 'mitre-attack'

      url = ref['url']
      return url if url && !url.to_s.empty?
    end
    nil
  end

  def clean_description(desc)
    return '' if desc.nil?

    out = desc.to_s.gsub(/\[([^\]]+)\]\([^)]+\)/, '\1')
    out = out.gsub(/&amp;/, '&').gsub(/&lt;/, '<').gsub(/&gt;/, '>').gsub(/&quot;/, '"')
    out = "#{out[0..1997]}..." if out.length > 2000
    out
  end

  # Stable slug from MITRE group id (G#### -> apt####) or name
  def slugify_group(external_id, name)
    token = external_id || name
    return nil if token.nil? || token.to_s.strip.empty?

    slug = token.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
    if slug =~ /^g\d+$/
      "apt#{slug[1..]}"
    else
      slug
    end
  end

  def technique_slug_from_id(tid)
    return nil if tid.nil? || tid.empty?

    tid.gsub('.', '-').downcase
  end

  def infer_domain_key_from_object(obj)
    domains = obj['x_mitre_domains'] || obj['x_mitre_domain'] || []
    domains = [domains] unless domains.is_a?(Array)
    out = []
    domains.each do |d|
      case d.to_s.downcase
      when /enterprise|windows|azure|office 365|google workspace/i
        out << 'enterprise'
      when /mobile/i
        out << 'mobile'
      when /ics|industrial/i
        out << 'ics'
      end
    end
    out.uniq
  end

  def software_type_label(obj)
    case obj['type']
    when 'malware' then 'malware'
    when 'tool' then 'tool'
    else 'software'
    end
  end

  # MITRE web URLs for techniques (including sub-techniques)
  def technique_url(external_id)
    return nil if external_id.nil? || external_id.empty?

    tid = external_id.upcase
    if tid.include?('.')
      base, sub = tid.split('.', 2)
      "https://attack.mitre.org/techniques/#{base}/#{sub}/"
    else
      "https://attack.mitre.org/techniques/#{tid}/"
    end
  end
end
