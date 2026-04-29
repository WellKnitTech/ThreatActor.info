# frozen_string_literal: true

# Normalizes actor YAML (`iocs` plus legacy top-level IOC lists) into rows for index generation.
# Align headings with scripts/generate-pages.rb so `ioc_type_for` resolves correctly.
#
# Curated IPs/domains/hashes/CVEs belong here or legacy top-level IOC keys. CISA KEV CVE lists on
# actors (`cisa_kev_cves`) are surfaced in the dedicated KEV section on actor pages, not merged here,
# unless editors also duplicate CVEs under `iocs.cves` intentionally.
module IocYamlReader
  module_function

  # Normalize nested iocs keys (e.g. md5_hashes from docs/schema) to canonical keys used by generate-pages.
  NESTED_KEY_ALIASES = {
    'md5_hashes' => 'md5',
    'sha256_hashes' => 'sha256',
    'sha1_hashes' => 'sha1'
  }.freeze

  # @return [Array<Hash>] each hash has :heading (String), :value (String), :inferred_type (String)
  def indicator_rows_from_actor(actor)
    merged = merged_iocs_sources(actor)
    rows = []

    append_simple(rows, merged, 'ips', 'IP Addresses', 'ip_address')
    append_simple(rows, merged, 'domains', 'Domains', 'domain')
    append_simple(rows, merged, 'urls', 'URLs', 'url')
    append_simple(rows, merged, 'emails', 'Email addresses', 'email')
    append_simple(rows, merged, 'cves', 'CVEs', 'cve')
    append_simple(rows, merged, 'md5', 'MD5', 'md5')
    append_simple(rows, merged, 'sha1', 'SHA1', 'sha1')
    append_simple(rows, merged, 'sha256', 'SHA256', 'sha256')

    Array(merged['attack_techniques']).each do |v|
      s = v.to_s.strip.upcase
      next if s.empty?

      rows << { heading: 'ATT&CK techniques', value: s, inferred_type: 'attack_technique' }
    end

    rows
  end

  def merged_iocs_sources(actor)
    out = {}

    nested = actor['iocs']
    copy_nested_into(out, nested) if nested.is_a?(Hash)

    merge_into(out, 'ips', actor['ips'])
    merge_into(out, 'domains', actor['domains'])
    merge_into(out, 'urls', actor['urls'])
    merge_into(out, 'emails', actor['emails'])
    merge_into(out, 'cves', actor['cves'])

    Array(actor['hashes']).each do |raw|
      s = raw.to_s.strip
      next if s.empty?

      t = infer_hash_type(s)
      merge_into(out, t, [s]) if t
    end

    %w[ips domains urls emails cves md5 sha1 sha256 attack_techniques].each do |k|
      next unless out[k]

      out[k] = Array(out[k]).map(&:to_s).map(&:strip).reject(&:empty?).uniq
    end

    out
  end

  def copy_nested_into(out, nested)
    nested.each do |key, values|
      k = NESTED_KEY_ALIASES[key.to_s] || key.to_s
      merge_into(out, k, values)
    end
  end

  def append_simple(rows, merged, key, heading, inferred_type)
    Array(merged[key]).each do |v|
      s = v.to_s.strip
      next if s.empty?

      rows << { heading: heading, value: s, inferred_type: inferred_type }
    end
  end

  def merge_into(out, key, extra)
    return if extra.nil?

    extra_arr = extra.is_a?(Array) ? extra : [extra]
    cur = Array(out[key])
    out[key] = (cur + extra_arr).map(&:to_s).map(&:strip).reject(&:empty?).uniq
  end

  def infer_hash_type(s)
    return 'md5' if s.match?(/\A[a-fA-F0-9]{32}\z/)
    return 'sha1' if s.match?(/\A[a-fA-F0-9]{40}\z/)
    return 'sha256' if s.match?(/\A[a-fA-F0-9]{64}\z/)

    nil
  end
end
