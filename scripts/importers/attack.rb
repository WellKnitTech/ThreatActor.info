# frozen_string_literal: true

# MITRE ATT&CK group denormalization helpers used by scripts/import-mitre.rb.
module MitreAttackGroupEnrichment
  module_function

  MITRE_REF_SOURCES = %w[
    mitre-attack
    mitre-attack-pre
    mitre-attack-mobile
    mitre-attack-ics
  ].freeze

  def apply!(actor, intrusion_set:, dataset_url: nil)
    actor['attck_techniques'] = technique_ids_from_ttps(actor['ttps'])
    actor['attck_software'] = software_tokens_from_software(actor['software'])
    actor['attck_references'] = attck_references_from_intrusion(intrusion_set)
    append_source!(actor, 'mitre-attack', dataset_url: dataset_url)
    actor
  end

  def technique_ids_from_ttps(ttps)
    Array(ttps).filter_map do |ttp|
      case ttp
      when Hash
        tid = ttp['technique_id'].to_s.upcase.strip
        tid if tid.match?(/\AT\d{4}(\.\d{3})?\z/)
      when String
        s = ttp.to_s.upcase.strip
        s if s.match?(/\AT\d{4}(\.\d{3})?\z/)
      end
    end.uniq.sort
  end

  def software_tokens_from_software(software)
    Array(software).filter_map do |s|
      next unless s.is_a?(Hash)

      mid = s['mitre_id'].to_s.strip
      name = s['name'].to_s.strip
      token = mid.match?(/\AS\d+\z/i) ? mid.upcase : name
      token unless token.empty?
    end.uniq.sort_by(&:downcase)
  end

  def attck_references_from_intrusion(intrusion_set)
    refs = []
    (intrusion_set['external_references'] || []).each do |ref|
      next unless ref.is_a?(Hash)

      source = (ref['source_name'] || ref['source']).to_s.downcase
      raw_url = ref['url'].to_s
      next if raw_url.empty? && ref['external_id'].to_s.empty?

      next unless MITRE_REF_SOURCES.include?(source) || raw_url.include?('attack.mitre.org')

      row = {
        'source' => ref['source_name'] || ref['source'] || 'mitre-attack',
        'url' => raw_url.empty? ? nil : raw_url,
        'external_id' => ref['external_id'],
        'description' => ref['description'].to_s[0..500]
      }.compact
      refs << row
    end
    dedupe_attck_references(refs)
  end

  def dedupe_attck_references(rows)
    seen = {}
    out = []
    rows.each do |r|
      sig = r['url'].to_s.empty? ? "#{r['source']}\t#{r['external_id']}" : r['url'].to_s
      next if sig.strip.empty?

      next if seen[sig]

      seen[sig] = true
      out << r
    end
    out
  end

  def append_source!(actor, source_key, imported_at: nil, dataset_url: nil)
    imported_at ||= Time.now.utc.iso8601
    actor['sources'] ||= []
    entry = { 'source' => source_key, 'imported_at' => imported_at }
    entry['dataset_url'] = dataset_url if dataset_url && !dataset_url.to_s.empty?

    sig = "#{entry['source']}\t#{entry['imported_at']}"
    return if actor['sources'].any? { |s| "#{s['source']}\t#{s['imported_at']}" == sig }

    actor['sources'] << entry
    actor
  end
end
