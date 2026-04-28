#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'open3'
require 'optparse'
require 'time'

Source = Struct.new(
  :key,
  :label,
  :script,
  :snapshot_root,
  :report_name,
  :fetch_limit,
  keyword_init: true
)

SOURCES = [
  Source.new(
    key: 'misp-galaxy',
    label: 'MISP Galaxy',
    script: 'scripts/import-misp-galaxy.rb',
    snapshot_root: 'data/imports/misp-galaxy',
    report_name: 'misp-galaxy-report.json',
    fetch_limit: true
  ),
  Source.new(
    key: 'ransomlook',
    label: 'RansomLook',
    script: 'scripts/import-ransomlook.rb',
    snapshot_root: 'data/imports/ransomlook',
    report_name: 'ransomlook-report.json',
    fetch_limit: true
  ),
  Source.new(
    key: 'etda-thaicert',
    label: 'ETDA / ThaiCERT Threat Group Cards',
    script: 'scripts/import-etda-thaicert.rb',
    snapshot_root: 'data/imports/etda-thaicert',
    report_name: 'etda-thaicert-report.json',
    fetch_limit: true
  ),
  Source.new(
    key: 'malpedia',
    label: 'Malpedia',
    script: 'scripts/import-malpedia.rb',
    snapshot_root: 'data/imports/malpedia',
    report_name: 'malpedia-report.json',
    fetch_limit: true
  ),
  Source.new(
    key: 'apt-groups-operations',
    label: 'APT Groups & Operations',
    script: 'scripts/import-apt-groups-operations.rb',
    snapshot_root: 'data/imports/apt-groups-operations',
    report_name: 'apt-groups-operations-report.json',
    fetch_limit: false
  ),
  Source.new(
    key: 'aptnotes',
    label: 'APTnotes',
    script: 'scripts/import-aptnotes.rb',
    snapshot_root: 'data/imports/aptnotes',
    report_name: 'aptnotes-report.json',
    fetch_limit: true
  ),
  Source.new(
    key: 'ransomware-tool-matrix',
    label: 'BushidoUK Ransomware Tool Matrix',
    script: 'scripts/import-ransomware-tool-matrix.rb',
    snapshot_root: 'data/imports/ransomware-tool-matrix',
    report_name: 'ransomware-tool-matrix-report.json',
    fetch_limit: false
  )
].freeze

options = {
  apply: false,
  date: Time.now.utc.strftime('%Y-%m-%d'),
  selected_sources: [],
  skipped_sources: [],
  fetch: true,
  plan: true,
  regenerate: true,
  report_dir: 'tmp/import-reports',
  limit: nil,
  continue_on_error: false
}

parser = OptionParser.new do |opts|
  opts.banner = 'Usage: ruby scripts/import-automated-sources.rb [options]'

  opts.on('--apply', 'Apply imports; default only fetches and plans') { options[:apply] = true }
  opts.on('--date DATE', 'Snapshot directory name; default is today in UTC') { |value| options[:date] = value }
  opts.on('--source KEY', 'Run one source; repeatable') { |value| options[:selected_sources] << value }
  opts.on('--skip-source KEY', 'Skip one source; repeatable') { |value| options[:skipped_sources] << value }
  opts.on('--no-fetch', 'Use existing snapshots instead of fetching new ones') { options[:fetch] = false }
  opts.on('--plan-only', 'Only plan from existing snapshots') do
    options[:fetch] = false
    options[:apply] = false
    options[:plan] = true
    options[:regenerate] = false
  end
  opts.on('--fetch-only', 'Only fetch snapshots') do
    options[:plan] = false
    options[:apply] = false
    options[:regenerate] = false
  end
  opts.on('--no-regenerate', 'Skip page/index regeneration and validation checks') { options[:regenerate] = false }
  opts.on('--report-dir DIR', 'Directory for JSON plan/import reports') { |value| options[:report_dir] = value }
  opts.on('--limit N', Integer, 'Pass a record limit to source fetchers that support it') { |value| options[:limit] = value }
  opts.on('--continue-on-error', 'Continue with later sources after a failure') { options[:continue_on_error] = true }
  opts.on('--list-sources', 'List automated sources and exit') do
    SOURCES.each { |source| puts "#{source.key}\t#{source.label}" }
    exit
  end
end

parser.parse!

def selected_sources(options)
  selected = SOURCES
  unless options[:selected_sources].empty?
    wanted = options[:selected_sources]
    unknown = wanted - SOURCES.map(&:key)
    abort "Unknown source(s): #{unknown.join(', ')}" unless unknown.empty?

    selected = selected.select { |source| wanted.include?(source.key) }
  end

  unless options[:skipped_sources].empty?
    unknown = options[:skipped_sources] - SOURCES.map(&:key)
    abort "Unknown source(s): #{unknown.join(', ')}" unless unknown.empty?

    selected = selected.reject { |source| options[:skipped_sources].include?(source.key) }
  end

  selected
end

def run_command(command)
  puts "→ #{command.join(' ')}"
  stdout, stderr, status = Open3.capture3(*command)
  puts stdout unless stdout.empty?
  warn stderr unless stderr.empty?
  return if status.success?

  raise "Command failed with exit #{status.exitstatus}: #{command.join(' ')}"
end

def snapshot_path(source, date)
  File.join(source.snapshot_root, date)
end

def report_path(options, source, mode)
  FileUtils.mkdir_p(options[:report_dir])
  File.join(options[:report_dir], "#{mode}-#{source.report_name}")
end

def fetch_source(source, snapshot, options)
  command = ['ruby', source.script, 'fetch', '--output', snapshot]
  command += ['--limit', options[:limit].to_s] if options[:limit] && source.fetch_limit
  run_command(command)
end

def plan_source(source, snapshot, options)
  command = ['ruby', source.script, 'plan', '--snapshot', snapshot, '--report-json', report_path(options, source, 'plan')]
  run_command(command)
end

def import_source(source, snapshot, options)
  command = ['ruby', source.script, 'import', '--snapshot', snapshot, '--report-json', report_path(options, source, 'import')]
  run_command(command)
end

def regenerate_outputs
  run_command(['ruby', 'scripts/generate-pages.rb', '--force'])
  run_command(['ruby', 'scripts/generate-indexes.rb'])
  run_command(['ruby', 'scripts/validate-content.rb'])
end

failures = []

selected_sources(options).each do |source|
  snapshot = snapshot_path(source, options[:date])
  puts "\n== #{source.label} =="

  begin
    fetch_source(source, snapshot, options) if options[:fetch]
    plan_source(source, snapshot, options) if options[:plan]
    import_source(source, snapshot, options) if options[:apply]
  rescue StandardError => e
    failures << "#{source.key}: #{e.message}"
    raise unless options[:continue_on_error]

    warn "Continuing after #{source.key} failure: #{e.message}"
  end
end

regenerate_outputs if options[:apply] && options[:regenerate] && failures.empty?

unless failures.empty?
  warn "\nImport run completed with failures:"
  failures.each { |failure| warn "- #{failure}" }
  exit 1
end

puts "\nAutomated import run complete."
