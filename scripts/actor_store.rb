#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'set'
require 'yaml'

module ActorStore
  ACTORS_DIR = '_data/actors'
  LEGACY_DATA_FILE = '_data/threat_actors.yml'
  FIELD_ORDER = %w[
    name
    aliases
    description
    url
    country
    sector_focus
    targeted_victims
    incident_type
    first_seen
    last_activity
    risk_level
    external_id
    external_url
    mitre_id
    mitre_url
    source_name
    source_attribution
    source_record_url
    source_license
    source_license_url
    operations
    malware
    cisa_kev_cves
    provenance
  ].freeze

  module_function

  def load_all
    if Dir.exist?(ACTORS_DIR)
      actors = Dir.glob(File.join(ACTORS_DIR, '*.yml')).sort.map do |path|
        safe_load_yaml_file(path)
      end.compact
      return actors unless actors.empty?
    end

    return [] unless File.exist?(LEGACY_DATA_FILE)

    Array(safe_load_yaml_file(LEGACY_DATA_FILE))
  end

  def save_all(actors)
    FileUtils.mkdir_p(ACTORS_DIR)
    desired_paths = []

    Array(actors)
      .sort_by { |actor| actor['name'].to_s.downcase }
      .each do |actor|
      next if actor['url'].to_s.empty?

      path = File.join(ACTORS_DIR, "#{slug_for(actor['url'])}.yml")
      desired_paths << path
      next if unchanged_actor_file?(path, actor)

      File.write(path, serialize_actor(actor))
    end

    delete_stale_shards(desired_paths)
  end

  def unchanged_actor_file?(path, actor)
    return false unless File.exist?(path)

    canonical_actor(safe_load_yaml_file(path)) == canonical_actor(actor)
  rescue StandardError
    false
  end

  def canonical_actor(value)
    case value
    when Hash
      value.each_with_object({}) do |(key, child_value), memo|
        canonical_value = canonical_actor(child_value)
        next if blank_value?(canonical_value)

        memo[key.to_s] = canonical_value
      end.sort.to_h
    when Array
      value.map { |entry| canonical_actor(entry) }.reject { |entry| blank_value?(entry) }
    else
      value
    end
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
  end

  def slug_for(url)
    url.to_s.sub(%r{^/}, '').sub(%r{/$}, '')
  end

  def serialize_actor(actor)
    normalized = normalize_actor(actor)
    lines = []

    FIELD_ORDER.each do |key|
      next unless normalized.key?(key)

      value = normalized[key]
      next if value.nil? || value == '' || value == []

      lines.concat(serialize_field(key, value, 0))
    end

    remaining_keys = normalized.keys - FIELD_ORDER
    remaining_keys.sort.each do |key|
      value = normalized[key]
      next if value.nil? || value == '' || value == []

      lines.concat(serialize_field(key, value, 0))
    end

    lines.join("\n") + "\n"
  end

  def normalize_actor(actor)
    actor.each_with_object({}) do |(key, value), memo|
      memo[key.to_s] = value
    end
  end

  def serialize_field(key, value, indent)
    prefix = '  ' * indent
    if value.is_a?(Hash)
      rows = ["#{prefix}#{key}:"]
      value.keys.sort.each do |child_key|
        child_value = value[child_key]
        next if child_value.nil? || child_value == '' || child_value == []

        rows.concat(serialize_field(child_key.to_s, child_value, indent + 1))
      end
      rows
    elsif value.is_a?(Array)
      serialize_array_field(key, value, indent)
    else
      ["#{prefix}#{key}: #{value.to_json}"]
    end
  end

  def serialize_array_field(key, value, indent)
    prefix = '  ' * indent
    compact_value = value.reject { |entry| entry.nil? || entry == '' || entry == [] || entry == {} }
    return [] if compact_value.empty?

    if compact_value.none? { |entry| entry.is_a?(Hash) || entry.is_a?(Array) }
      return ["#{prefix}#{key}: #{compact_value.map(&:to_s).uniq.to_json}"]
    end

    rows = ["#{prefix}#{key}:"]
    compact_value.each do |entry|
      rows.concat(serialize_array_entry(entry, indent + 1))
    end
    rows
  end

  def serialize_array_entry(entry, indent)
    prefix = '  ' * indent
    case entry
    when Hash
      serialize_hash_array_entry(entry, indent)
    when Array
      ["#{prefix}- #{entry.to_json}"]
    else
      ["#{prefix}- #{entry.to_json}"]
    end
  end

  def serialize_hash_array_entry(entry, indent)
    prefix = '  ' * indent
    normalized = normalize_actor(entry)
    keys = normalized.keys.sort.reject do |child_key|
      value = normalized[child_key]
      value.nil? || value == '' || value == [] || value == {}
    end
    return [] if keys.empty?

    rows = []
    keys.each_with_index do |child_key, index|
      child_value = normalized[child_key]
      if child_value.is_a?(Hash) || child_value.is_a?(Array)
        rows << "#{index.zero? ? "#{prefix}-" : "#{'  ' * (indent + 1)}"} #{child_key}:"
        rows.concat(serialize_nested_value(child_value, indent + 2))
      else
        rows << if index.zero?
                  "#{prefix}- #{child_key}: #{child_value.to_json}"
                else
                  "#{'  ' * (indent + 1)}#{child_key}: #{child_value.to_json}"
                end
      end
    end
    rows
  end

  def serialize_nested_value(value, indent)
    case value
    when Hash
      value.keys.sort.flat_map do |child_key|
        child_value = value[child_key]
        next [] if child_value.nil? || child_value == '' || child_value == [] || child_value == {}

        serialize_field(child_key.to_s, child_value, indent)
      end
    when Array
      value.flat_map { |entry| serialize_array_entry(entry, indent) }
    else
      ["#{'  ' * indent}#{value.to_json}"]
    end
  end

  def blank_value?(value)
    value.nil? || value == '' || value == [] || value == {}
  end

  def delete_stale_shards(desired_paths)
    desired = desired_paths.to_set
    Dir.glob(File.join(ACTORS_DIR, '*.yml')).each do |path|
      next if desired.include?(path)

      File.delete(path)
    end
  end
end
