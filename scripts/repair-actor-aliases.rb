#!/usr/bin/env ruby
# frozen_string_literal: true

# Ensures every _data/actors/*.yml has a non-empty aliases array (validate-content.rb).
# Usage: ruby scripts/repair-actor-aliases.rb [--dry-run]

require 'yaml'

ROOT = File.expand_path('..', __dir__)
ACTORS_DIR = File.join(ROOT, '_data', 'actors')

dry_run = ARGV.include?('--dry-run')
fixed = 0

Dir.glob(File.join(ACTORS_DIR, '*.yml')).sort.each do |path|
  data = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  next unless data.is_a?(Hash)

  aliases = data['aliases']
  next if aliases.is_a?(Array) && !aliases.empty?

  name = data['name'].to_s
  data['aliases'] = name.empty? ? ['unknown'] : [name]

  if dry_run
    warn "[dry-run] would fix aliases in #{path}"
    fixed += 1
    next
  end

  File.write(path, YAML.dump(data))
  fixed += 1
end

puts dry_run ? "Dry-run: #{fixed} file(s) need aliases repair." : "Repaired aliases in #{fixed} file(s)."
