#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'optparse'
require_relative 'actor_store'
require_relative 'lib/actor_duplicate_audit'

options = { output: nil }
OptionParser.new do |opts|
  opts.banner = 'Usage: ruby scripts/audit-actor-duplicates.rb [--output PATH]'
  opts.on('--output PATH', 'Write JSON report instead of stdout') { |path| options[:output] = path }
end.parse!

actor_paths = Dir.glob(File.join(ActorStore::ACTORS_DIR, '*.yml')).sort
actors = if actor_paths.any?
           actor_paths.filter_map do |path|
             actor = ActorStore.safe_load_yaml_file(path)
             actor['_source_file'] = path if actor.is_a?(Hash)
             actor
           end
         else
           ActorStore.load_all
         end

json = JSON.pretty_generate(ActorDuplicateAudit.report(actors)) + "\n"
if options[:output]
  File.write(options[:output], json)
else
  print json
end
