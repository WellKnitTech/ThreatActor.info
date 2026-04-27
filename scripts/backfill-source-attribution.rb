#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'

actors_dir = '_data/actors'
updated = 0
skipped = 0

Dir.glob("#{actors_dir}/*.yml").each do |path|
  actor = YAML.safe_load(File.read(path))
  
  # Skip if already has source_attribution
  next unless actor['source_attribution'].to_s.strip.empty?
  
  # Check if has other source (source_name or source_record_url set)
  has_other_source = !actor['source_name'].to_s.empty? || 
                  !actor['source_record_url'].to_s.empty?
  
  # Only misp_galaxy-provenance actors with no other source should get auto-attribution
  next unless actor['provenance'].is_a?(Hash)
  next unless actor['provenance']['misp_galaxy']
  next if has_other_source
  
  # Add source_attribution
  actor['source_attribution'] = 'Contains data derived from MISP Galaxy, used under Apache 2.0 / CC0. Source: https://github.com/MISP/misp-galaxy'
  actor['source_name'] = 'MISP Galaxy' unless actor['source_name']
  
  # Write back
  File.write(path, YAML.dump(actor))
  updated += 1
end

puts "Updated #{updated} actors (source_attribution added)"
puts "Skipped #{skipped} actors (already had source)"