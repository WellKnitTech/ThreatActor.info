#!/usr/bin/env ruby
# frozen_string_literal: true

# Contract checks for the daily security-news workflow: GITHUB_TOKEN pushes must
# dispatch Pages + Validation only when a commit was actually pushed.

workflow_path = ARGV.fetch(0) { File.expand_path('../.github/workflows/daily-news.yml', __dir__) }
pages_path = File.expand_path('../.github/workflows/pages.yml', __dir__)
validate_path = File.expand_path('../.github/workflows/validate.yml', __dir__)

workflow = File.read(workflow_path)
pages = File.read(pages_path)
validate = File.read(validate_path)
failures = []

failures << 'daily-news must grant actions: write for post-push workflow dispatch' unless workflow.match?(/actions:\s*write/)
failures << 'daily-news must grant contents: write' unless workflow.match?(/contents:\s*write/)
failures << 'daily-news must run scripts/fetch-news.rb' unless workflow.match?(/ruby\s+scripts\/fetch-news\.rb/)
failures << 'daily-news commit step must record changed=true|false' unless workflow.match?(/changed=true/) && workflow.match?(/changed=false/)
failures << 'daily-news push step must only run when commit changed' unless workflow.match?(/steps\.commit\.outputs\.changed\s*==\s*'true'/)
failures << 'daily-news must dispatch Deploy GitHub Pages after a news push' unless workflow.match?(/gh\s+workflow\s+run\s+\"Deploy GitHub Pages\"\s+--ref\s+main/)
failures << 'daily-news must dispatch Content Validation after a news push' unless workflow.match?(/gh\s+workflow\s+run\s+\"Content Validation\"\s+--ref\s+main/)
failures << 'daily-news dispatch must only run after a successful push' unless workflow.match?(/steps\.push\.outputs\.pushed\s*==\s*'true'/)
failures << 'pages.yml must accept workflow_dispatch' unless pages.match?(/workflow_dispatch:/)
failures << 'validate.yml must accept workflow_dispatch' unless validate.match?(/workflow_dispatch:/)

if failures.any?
  warn failures.join("\n")
  exit 1
end

puts 'Daily news workflow checks passed.'
