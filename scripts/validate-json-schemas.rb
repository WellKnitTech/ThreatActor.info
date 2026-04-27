#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'yaml'

begin
  require 'json_schemer'
rescue LoadError
  require 'bundler/setup'
  require 'json_schemer'
end

VALIDATIONS = [
  {
    label: 'actor metadata',
    schema: 'schemas/actor.schema.json',
    files: '_data/actors/*.yml',
    parser: :yaml
  },
  {
    label: 'generated API payload',
    schema: 'schemas/generated-api.schema.json',
    files: '_data/generated/*.json',
    parser: :json
  }
].freeze

errors = []

def violation_message(error)
  case error.fetch('type')
  when 'required'
    "missing required property #{error.fetch('details').fetch('missing_keys').join(', ')}"
  when 'schema'
    "value must match #{error.fetch('schema_pointer')}"
  when 'format'
    "invalid #{error.fetch('details').fetch('format')} format"
  else
    "#{error.fetch('type')} schema violation"
  end
end

def load_payload(path, parser)
  case parser
  when :yaml
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
  when :json
    JSON.parse(File.read(path))
  else
    raise "Unsupported parser: #{parser}"
  end
end

VALIDATIONS.each do |validation|
  schema_path = validation.fetch(:schema)
  unless File.exist?(schema_path)
    errors << "#{schema_path}: schema file missing"
    next
  end

  schemer = JSONSchemer.schema(JSON.parse(File.read(schema_path)))
  files = Dir.glob(validation.fetch(:files)).sort
  if files.empty?
    errors << "#{validation.fetch(:files)}: no #{validation.fetch(:label)} files found"
    next
  end

  files.each do |path|
    payload = load_payload(path, validation.fetch(:parser))
    schemer.validate(payload).each do |error|
      pointer = error.fetch('data_pointer', '')
      location = pointer.empty? ? '/' : pointer
      errors << "#{path}#{location}: #{violation_message(error)}"
    end
  rescue JSON::ParserError, Psych::SyntaxError => e
    errors << "#{path}: parse error: #{e.message}"
  rescue StandardError => e
    errors << "#{path}: validation error: #{e.message}"
  end
end

if errors.empty?
  puts 'JSON Schema validation passed.'
  exit 0
end

puts 'JSON Schema validation failed:'
errors.each { |error| puts "- #{error}" }
exit 1
