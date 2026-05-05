# frozen_string_literal: true

# Helpers for embedding values in Markdown front matter so Psych can round-trip
# parse them. JSON-encoded scalars and arrays are valid YAML tokens (same pattern
# as import-etda-thaicert.rb / import-ransomlook.rb write_page).

require 'json'

module FrontMatterYaml
  module_function

  def json_scalar_line(key, value)
    "#{key}: #{value.to_json}"
  end

  def json_array_line(key, values)
    "#{key}: #{Array(values).map(&:to_s).uniq.to_json}"
  end
end
