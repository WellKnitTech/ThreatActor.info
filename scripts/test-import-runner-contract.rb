#!/usr/bin/env ruby
# frozen_string_literal: true

runner = File.read(File.expand_path('import-automated-sources.rb', __dir__))
workflow = File.read(File.expand_path('../.github/workflows/import-sources.yml', __dir__))
pipeline = File.read(File.expand_path('../.github/workflows/import-pipeline.yml', __dir__))
workflow_text = "#{workflow}\n#{pipeline}"

abort 'runner does not track failed sources' unless runner.include?('failed_sources = Set.new')
abort 'runner can apply a source whose fetch/plan failed' unless runner.include?('selected.reject { |source| failed_sources.include?(source.key) }')
abort 'production workflow still enables stale-snapshot continuation' if workflow_text.include?('--continue-on-error')
abort 'production workflow does not use report-backed runner' unless workflow_text.include?('--report-dir "$IMPORT_REPORT_DIR"')
abort 'production workflow does not retain import reports' unless workflow_text.include?('${{ env.IMPORT_REPORT_DIR }}/**')
abort 'production workflow does not invoke quality-gated runner' unless runner.include?('SnapshotQualityGate.validate!')

puts 'automated import runner contract checks passed'
