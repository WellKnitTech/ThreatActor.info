#!/usr/bin/env ruby
# frozen_string_literal: true

# Ensures every _data/actors/*.yml has a non-empty aliases array (validate-content.rb).
# Prefer text edits for `aliases: []` so the rest of the file formatting is preserved.
# Usage: ruby scripts/repair-actor-aliases.rb [--dry-run]

require 'yaml'

ROOT = File.expand_path('..', __dir__)
ACTORS_DIR = File.join(ROOT, '_data', 'actors')

dry_run = ARGV.include?('--dry-run')
fixed = 0

Dir.glob(File.join(ACTORS_DIR, '*.yml')).sort.each do |path|
  raw = File.read(path)
  data = YAML.safe_load(raw, permitted_classes: [], aliases: false)
  next unless data.is_a?(Hash)

  aliases = data['aliases']
  next if aliases.is_a?(Array) && !aliases.empty?

  name = data['name'].to_s
  filler = name.empty? ? 'unknown' : name
  aliases_yaml = "[#{filler.inspect}]"

  updated = raw.dup

  if updated.match?(/^aliases:\s*\[\]\s*(?:#.*)?$/m)
    updated.sub!(/^aliases:\s*\[\]\s*(?:#.*)?$/m, "aliases: #{aliases_yaml}")
  elsif updated !~ /^aliases:\s/m
    subst = +"aliases: #{aliases_yaml}\n"
    unless updated.sub!(/^(name:\s*.+)$/m) { |line| "#{line}\n#{subst.chomp}" }
      data['aliases'] = name.empty? ? ['unknown'] : [name]
      updated.replace(YAML.dump(data))
    end
  else
    data['aliases'] = name.empty? ? ['unknown'] : [name]
    updated.replace(YAML.dump(data))
  end

  next if updated == raw

  if dry_run
    warn "[dry-run] would fix aliases in #{path}"
    fixed += 1
    next
  end

  File.write(path, updated)
  fixed += 1
end

puts dry_run ? "Dry-run: #{fixed} file(s) need aliases repair." : "Repaired aliases in #{fixed} file(s)."
