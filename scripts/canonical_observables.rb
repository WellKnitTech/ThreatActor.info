# frozen_string_literal: true

require 'digest'
require 'ipaddr'
require 'uri'

# Canonical, fail-closed Observable v1 implementation. Legacy readers remain
# separate; this module is the migration seam used by importers and fixtures.
module CanonicalObservables
  VERSION = 'ioc-observable-v1'
  TYPES = %w[ip_address domain url email md5 sha1 sha256 sha512 file_path registry_key mutex certificate cve attack_technique].freeze
  STATUSES = %w[active deprecated false_positive quarantined].freeze
  HASH_LENGTHS = { 'md5' => 32, 'sha1' => 40, 'sha256' => 64, 'sha512' => 128 }.freeze
  TYPE_ALIASES = { 'vulnerability' => 'cve' }.freeze

  module_function

  def canonicalize(observation)
    input = stringify(observation)
    type = TYPE_ALIASES.fetch(input.fetch('type').to_s.downcase, input.fetch('type').to_s.downcase)
    value = normalize(type, input.fetch('value'), input)
    validate_metadata!(input)
    output = input.merge('type' => type, 'value' => value, 'normalized_value' => value,
                         'canonical_value' => value, 'atomic' => true,
                         'status' => input.fetch('status', 'active'),
                         'id' => "obs_v1_#{Digest::SHA256.hexdigest([type, value].join("\0"))}")
    output['display_value'] ||= display_value(type, value)
    if conflicting_attribution?(output['relationships'])
      output['status'] = 'quarantined'
      output['quarantine_reason'] = 'conflicting_attribution'
    end
    output
  rescue KeyError => e
    raise ArgumentError, "missing_required_field: #{e.key}"
  end

  def canonicalize_all(observations)
    observations.each_with_object({}) do |observation, grouped|
      record = canonicalize(observation)
      key = [record['type'], record['normalized_value']]
      if grouped[key]
        grouped[key]['sources'] = (grouped[key]['sources'] + record['sources']).uniq
        grouped[key]['relationships'] = (Array(grouped[key]['relationships']) + Array(record['relationships'])).uniq
      else
        grouped[key] = record
      end
    end.values.sort_by { |record| [record['type'], record['normalized_value']] }
  end

  def public?(record)
    record['atomic'] == true && %w[active deprecated].include?(record['status']) &&
      Array(record['sources']).any? { |source| source.fetch('status', 'active') == 'active' }
  end

  def normalize(type, raw, input = {})
    raise ArgumentError, 'unregistered_subtype' if type == 'other'
    raise ArgumentError, 'unsupported_type' unless TYPES.include?(type)
    value = raw.to_s.strip
    raise ArgumentError, 'empty_value' if value.empty?
    return normalize_ip(value) if type == 'ip_address'
    return normalize_domain(value, input['defanged']) if type == 'domain'
    return normalize_url(value, input['defanged']) if type == 'url'
    return value.downcase if type == 'email' && value.match?(/\A[^\s@]+@[^\s@]+\.[^\s@]+\z/)
    return value.downcase if HASH_LENGTHS[type] && value.match?(/\A[a-fA-F0-9]{#{HASH_LENGTHS[type]}}\z/)
    return value.upcase if type == 'cve' && value.match?(/\ACVE-\d{4}-\d{4,}\z/i)
    return value.upcase if type == 'attack_technique' && value.match?(/\AT\d{4}(?:\.\d{3})?\z/i)
    return normalize_registry(value) if type == 'registry_key'
    return normalize_path(value) if type == 'file_path'
    return value if type == 'mutex'
    return value.downcase if type == 'certificate' && input['algorithm'].to_s.downcase.match?(/\A(?:sha1|sha256)\z/) && value.match?(/\A[a-fA-F0-9]{#{input['algorithm'].to_s.downcase == 'sha1' ? 40 : 64}}\z/)

    raise ArgumentError, reason_for(type, value, input)
  end

  def validate_metadata!(input)
    raise ArgumentError, 'source_required' unless input['sources'].is_a?(Array) && !input['sources'].empty?
    input['sources'].each do |source|
      raise ArgumentError, 'source_required' unless source.is_a?(Hash) && source['source'].to_s != '' && source['retrieved_at'].to_s != ''
      raise ArgumentError, 'invalid_retrieved_at' unless rfc3339?(source['retrieved_at'])
    end
    %w[first_seen last_seen].each do |field|
      next unless input[field]

      raise ArgumentError, "invalid_#{field}" unless rfc3339?(input[field])
    end
    raise ArgumentError, 'invalid_status' unless STATUSES.include?(input.fetch('status', 'active'))
    if input['status'] == 'false_positive' && !input['false_positive'].is_a?(Hash)
      raise ArgumentError, 'false_positive_reason_required'
    end
  end

  def conflicting_attribution?(relationships)
    actor_targets = Array(relationships).select { |row| row['target_kind'] == 'actor' && row.fetch('status', 'active') == 'active' }
    actor_targets.map { |row| [row['role'], row['target_id']] }.uniq.group_by(&:first).values.any? { |rows| rows.map(&:last).uniq.length > 1 }
  end

  def normalize_ip(value)
    raise ArgumentError, 'cidr_not_atomic' if value.include?('/')
    IPAddr.new(value).to_s
  rescue IPAddr::InvalidAddressError
    raise ArgumentError, 'invalid_ip_address'
  end

  def normalize_domain(value, defanged)
    value = defang(value) if defanged
    value = value.downcase.sub(/\.$/, '')
    raise ArgumentError, 'invalid_domain' unless value.match?(/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/)
    value
  end

  def normalize_url(value, defanged)
    value = defang(value) if defanged
    uri = URI.parse(value)
    raise ArgumentError, 'invalid_url' unless %w[http https].include?(uri.scheme&.downcase) && uri.host
    raise ArgumentError, 'url_credentials_forbidden' if uri.user || uri.password
    uri.scheme = uri.scheme.downcase
    uri.host = uri.host.downcase
    uri.port = nil if (uri.scheme == 'http' && uri.port == 80) || (uri.scheme == 'https' && uri.port == 443)
    uri.fragment = nil
    uri.to_s
  rescue URI::InvalidURIError
    raise ArgumentError, 'invalid_url'
  end

  def normalize_registry(value)
    value = value.gsub(%r{[/\\]+}, '\\').sub(/\A([^\\]+)\\/) { "#{$1.upcase}\\" }
    raise ArgumentError, 'invalid_registry_key' unless value.match?(/\A(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^=]+\z/i)
    value
  end

  def normalize_path(value)
    prefix = value.match?(/\A[A-Za-z]:[\\\/]/) ? value[0, 3] : ''
    parts = value.delete_prefix(prefix).split(/[\\\/]/)
    clean = parts.each_with_object([]) do |part, out|
      next if part.empty? || part == '.'
      part == '..' ? out.pop : out << part
    end
    prefix + clean.join('\\')
  end

  def rfc3339?(value)
    value.to_s.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\z/)
  end

  def defang(value)
    value.gsub(/\[\.\]|\(\.\)/, '.').sub(/\Ahxxps/, 'https').sub(/\Ahxxp/, 'http')
  end

  def display_value(type, value)
    %w[domain url email].include?(type) ? value.gsub('.', '[.]') : value
  end

  def reason_for(type, value, input)
    return 'invalid_email' if type == 'email'
    return 'invalid_hash_length' if HASH_LENGTHS[type]
    return 'certificate_material_forbidden' if type == 'certificate' && value.include?('BEGIN CERTIFICATE')
    return 'invalid_certificate_fingerprint' if type == 'certificate'
    return 'unregistered_subtype' if input.fetch('type', '') == 'other'
    "invalid_#{type}"
  end

  def stringify(value)
    value.each_with_object({}) { |(key, item), out| out[key.to_s] = item }
  end
end