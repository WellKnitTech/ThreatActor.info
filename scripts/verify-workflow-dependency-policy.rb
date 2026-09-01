#!/usr/bin/env ruby
# frozen_string_literal: true

# ruby/setup-ruby with bundler-cache performs the bundle install and cache
# restore. Keep workflows from paying for a second dependency resolution.

workflow_dir = ARGV.fetch(0) { File.expand_path('../.github/workflows', __dir__) }
failures = []

Dir.glob(File.join(workflow_dir, '*.{yml,yaml}')).sort.each do |path|
  workflow = File.read(path)
  next unless workflow.match?(/uses:\s+ruby\/setup-ruby@/)
  next unless workflow.match?(/bundler-cache:\s*true/)

  failures << "#{File.basename(path)} must not run bundle install when bundler-cache is enabled" if workflow.match?(/(?:run:\s*|\n\s*)bundle install\b/)
  failures << "#{File.basename(path)} must not request a full checkout without an explicit history requirement" if workflow.match?(/fetch-depth:\s*0/)
end

if failures.empty?
  puts 'Workflow dependency policy checks passed.'
else
  warn failures.map { |failure| "FAIL: #{failure}" }
  exit 1
end
