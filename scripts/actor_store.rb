#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'json'
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
    last_updated
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
    ttps
    cisa_kev_cves
    urls
    domains
    ips
    hashes
    campaigns
    provenance
    analyst_notes
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
    clear_existing_shards

    Array(actors)
      .sort_by { |actor| actor['name'].to_s.downcase }
      .each do |actor|
      next if actor['url'].to_s.empty?

      path = File.join(ACTORS_DIR, "#{slug_for(actor['url'])}.yml")
      File.write(path, serialize_actor(actor))
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
      if value.any? { |entry| entry.is_a?(Hash) || entry.is_a?(Array) }
        serialized = value.map do |entry|
          entry.is_a?(Hash) ? normalize_actor(entry) : entry
        end
        rows = ["#{prefix}#{key}:"]
        rows.concat(serialized.to_yaml.lines[1..].map { |line| "#{prefix}#{line.chomp}" })
        rows
      else
        ["#{prefix}#{key}: #{value.map(&:to_s).uniq.to_json}"]
      end
    else
      ["#{prefix}#{key}: #{value.to_json}"]
    end
  end

  def clear_existing_shards
    Dir.glob(File.join(ACTORS_DIR, '*.yml')).each do |path|
      File.delete(path)
    end
  end
end
