# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module SourceImport
  # Small, source-neutral cache metadata format. Secrets never belong in a
  # manifest: callers provide only public validators and stable record data.
  module CacheManifest
    SCHEMA_VERSION = '1.0'.freeze

    module_function

    def record_hashes(records, id_keys: %w[id uuid source_record_id url name])
      Array(records).each_with_index.each_with_object({}) do |(record, index), result|
        value = record.is_a?(Hash) ? record : { 'value' => record }
        id = id_keys.map { |key| value[key] || value[key.to_sym] }.find { |candidate| !candidate.to_s.empty? }
        id = "index:#{index}" if id.to_s.empty?
        result[id.to_s] = Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
      end
    end

    def build(source_key:, retrieved_at:, records: [], source_version: nil, validators: {}, freshness: 'fresh',
              schema_version: SCHEMA_VERSION, transform_version: '1.0', metrics: {}, **extra)
      {
        'cache_schema_version' => SCHEMA_VERSION,
        'source_key' => source_key.to_s,
        'source_version' => source_version,
        'request_validators' => validators.each_with_object({}) do |(key, value), result|
          result[key.to_s] = value.to_s if %w[etag last_modified].include?(key.to_s) && !value.to_s.empty?
        end,
        'record_hashes' => record_hashes(records),
        'record_count' => Array(records).length,
        'retrieved_at' => Time.parse(retrieved_at.to_s).utc.iso8601,
        'freshness' => freshness.to_s,
        'schema_version' => schema_version.to_s,
        'transform_version' => transform_version.to_s,
        'metrics' => { 'request_count' => 0, 'response_bytes' => 0 }.merge(metrics),
        'secrets_present' => false
      }.merge(extra.each_with_object({}) { |(key, value), result| result[key.to_s] = value })
    end

    def load(path)
      value = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
      return nil unless value.is_a?(Hash) && value['cache_schema_version'] == SCHEMA_VERSION
      return nil unless value['secrets_present'] == false

      value
    rescue Errno::ENOENT, Psych::Exception
      nil
    end

    def write_atomic(path, manifest)
      FileUtils.mkdir_p(File.dirname(path))
      temporary = "#{path}.tmp-#{Process.pid}"
      File.write(temporary, YAML.dump(manifest))
      File.rename(temporary, path)
    ensure
      FileUtils.rm_f(temporary) if temporary
    end

    def canonical(value)
      case value
      when Hash
        value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
          original = value.key?(key) ? key : key.to_sym
          result[key] = canonical(value[original])
        end
      when Array then value.map { |item| canonical(item) }
      else value
      end
    end
  end
end
