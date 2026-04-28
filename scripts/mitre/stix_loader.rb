# frozen_string_literal: true

require 'json'
require_relative 'mitre_common'

# Loads and merges MITRE ATT&CK STIX 2.1 bundle JSON files.
module MitreStixLoader
  module_function

  # @param bundle_paths [Hash<String, String>] domain_key => filesystem path to JSON
  # @return [Hash] :objects (id => obj), :relationships (Array), :domains_by_id (id => Array of domain keys)
  def load_and_merge(bundle_paths)
    objects = {}
    domains_by_id = Hash.new { |h, k| h[k] = [] }
    relationships = []

    bundle_paths.each do |domain_key, path|
      next unless File.exist?(path)

      data = JSON.parse(File.read(path))
      Array(data['objects']).each do |obj|
        next unless obj.is_a?(Hash)

        if obj['type'] == 'relationship'
          relationships << obj.merge('_mitre_bundle_domain' => domain_key)
        else
          merge_object!(objects, domains_by_id, obj, domain_key)
        end
      end
    end

    { objects: objects, relationships: relationships, domains_by_id: domains_by_id }
  end

  def merge_object!(objects, domains_by_id, obj, domain_key)
    id = obj['id']
    return if id.nil? || id.empty?

    inferred = MitreCommon.infer_domain_key_from_object(obj)
    tag = inferred.include?(domain_key) ? domain_key : domain_key

    if objects[id]
      existing = objects[id]
      domains_by_id[id] << tag unless domains_by_id[id].include?(tag)
      # Prefer longer description; merge aliases on intrusion-set
      if obj['description'].to_s.length > existing['description'].to_s.length
        existing['description'] = obj['description']
      end
      if obj['type'] == 'intrusion-set' && obj['aliases'].is_a?(Array)
        existing['aliases'] = (Array(existing['aliases']) + obj['aliases']).uniq
      end
      %w[revoked x_mitre_deprecated].each do |k|
        existing[k] = obj[k] if obj.key?(k)
      end
    else
      objects[id] = obj.dup
      domains_by_id[id] << tag unless domains_by_id[id].include?(tag)
    end
  end
  private_class_method :merge_object!
end
