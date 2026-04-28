#!/usr/bin/env ruby

require 'bundler/setup'
require 'json'
require 'json_schemer'
require 'yaml'

class JsonSchemaValidator
  ACTOR_SCHEMA_PATH = 'schemas/threat-actor.schema.json'.freeze
  GENERATED_ARRAY_SCHEMA_PATH = 'schemas/generated-array.schema.json'.freeze
  GENERATED_OBJECT_SCHEMA_PATH = 'schemas/generated-object.schema.json'.freeze
  ACTOR_DATA_PATTERN = '_data/actors/*.yml'.freeze
  ARRAY_PAYLOADS = %w[
    _data/generated/threat_actors.json
    _data/generated/iocs.json
    _data/generated/campaigns.json
    _data/generated/malware.json
    _data/generated/attack_mappings.json
    _data/generated/references.json
    _data/generated/recently_updated.json
    _data/generated/techniques.json
    _data/generated/tactics.json
    _data/generated/mitigations.json
    _data/generated/campaigns_mitre.json
  ].freeze
  OBJECT_PAYLOADS = %w[
    _data/generated/facets.json
    _data/generated/ioc_lookup.json
    _data/generated/ioc_types.json
    _data/generated/malware_index.json
    _data/generated/actors_by_technique.json
    _data/generated/software_by_actor.json
    _data/generated/search_index.json
  ].freeze

  def initialize
    @errors = []
  end

  def validate_all
    puts 'Validating JSON Schemas...'
    validate_actor_data
    validate_generated_payloads
    print_results
    exit(@errors.empty? ? 0 : 1)
  end

  private

  def validate_actor_data
    schema = load_schema(ACTOR_SCHEMA_PATH)

    Dir.glob(ACTOR_DATA_PATTERN).sort.each do |path|
      payload = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
      validate_payload(schema, path, payload)
    rescue StandardError => e
      add_error(path, "Unable to validate actor YAML: #{e.message}")
    end
  end

  def validate_generated_payloads
    array_schema = load_schema(GENERATED_ARRAY_SCHEMA_PATH)
    object_schema = load_schema(GENERATED_OBJECT_SCHEMA_PATH)

    ARRAY_PAYLOADS.each { |path| validate_json_file(array_schema, path) }
    OBJECT_PAYLOADS.each { |path| validate_json_file(object_schema, path) }
    Dir.glob('_data/generated/iocs_by_type/*.json').sort.each { |path| validate_json_file(object_schema, path) }
  end

  def validate_json_file(schema, path)
    payload = JSON.parse(File.read(path))
    validate_payload(schema, path, payload)
  rescue StandardError => e
    add_error(path, "Unable to validate JSON: #{e.message}")
  end

  def validate_payload(schema, path, payload)
    schema.validate(payload).each do |error|
      pointer = error.fetch('data_pointer', '')
      location = pointer.empty? ? '<root>' : pointer
      add_error(path, "#{location}: #{error['type']}")
    end
  end

  def load_schema(path)
    JSONSchemer.schema(JSON.parse(File.read(path)))
  rescue StandardError => e
    warn "Unable to load schema #{path}: #{e.message}"
    exit 1
  end

  def add_error(path, message)
    @errors << { path: path, message: message }
  end

  def print_results
    if @errors.empty?
      puts 'JSON Schema validation completed successfully.'
      return
    end

    puts "JSON Schema validation failed with #{@errors.length} error(s):"
    @errors.each do |error|
      puts "- #{error[:path]}: #{error[:message]}"
    end
  end
end

JsonSchemaValidator.new.validate_all if __FILE__ == $PROGRAM_NAME
