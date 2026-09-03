#!/usr/bin/env ruby

# Contract check for the two public entry points and their single runner.
require "yaml"

root = File.expand_path("..", __dir__)
weekly = File.join(root, ".github/workflows/weekly-data.yml")
legacy = File.join(root, ".github/workflows/import-sources.yml")
pipeline = File.join(root, ".github/workflows/import-pipeline.yml")
files = [weekly, legacy, pipeline]
missing = files.reject { |path| File.file?(path) }
abort "Missing workflow: #{missing.join(', ')}" unless missing.empty?

text = files.to_h { |path| [path, File.read(path)] }
failures = []

failures << "canonical pipeline must be reusable" unless text[pipeline].match?(/workflow_call:/)
failures << "canonical pipeline must own concurrency" unless text[pipeline].match?(/concurrency:\s*\n\s+group:/)
failures << "canonical job must have an explicit timeout" unless text[pipeline].match?(/timeout-minutes:\s*45/)
failures << "weekly workflow must be the only scheduled import entry point" unless text[weekly].match?(/schedule:/) && !text[legacy].match?(/schedule:/)
[weekly, legacy].each do |path|
  body = text[path]
  failures << "#{File.basename(path)} must call the canonical pipeline" unless body.match?(/uses:\s+\.\/\.github\/workflows\/import-pipeline\.yml/)
  failures << "#{File.basename(path)} must inherit secrets" unless body.match?(/secrets:\s+inherit/)
  failures << "#{File.basename(path)} must expose source and phase inputs" unless body.match?(/source:/) && body.match?(/phase:/)
end

weekly_inputs = %w[source phase].select { |input| text[weekly].match?(/^\s+#{input}:\s*$/) }
legacy_inputs = %w[source phase].select { |input| text[legacy].match?(/^\s+#{input}:\s*$/) }
failures << "schedule and manual entry points must expose the same source/phase contract" unless weekly_inputs == %w[source phase] && legacy_inputs == %w[source phase]

if failures.empty?
  puts "Import workflow contract checks passed."
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end
