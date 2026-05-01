#!/usr/bin/env ruby
# frozen_string_literal: true

# After a local --apply, commit importer and generator outputs together: _data/actors,
# _threat_actors, _data/generated, api, and _malware when touched. See docs/keeping-actor-pages-current.md.

require 'fileutils'
require 'open3'
require 'optparse'
require 'time'

Source = Struct.new(
  :priority,
  :key,
  :label,
  :script,
  :snapshot_root,
  :report_name,
  :fetch_args,
  :fetch_limit,
  keyword_init: true
)

# Each source has a `priority` integer; `SOURCES` is sorted at load time. Lower runs first.
# Policy: MITRE first; then STIX/JSON/static feeds; tabular; markdown-derived; HTML scrapers last.
# See docs/importers.md (Automation Policy).
SOURCES_UNSORTED = [
  Source.new(
    priority: 1,
    key: 'mitre-attack',
    label: 'MITRE ATT&CK',
    script: 'scripts/import-mitre.rb',
    snapshot_root: 'data/imports/mitre-attack',
    report_name: 'mitre-attack-report.json',
    fetch_args: %w[],
    fetch_limit: false
  ),
  Source.new(
    priority: 2,
    key: 'wiz-cloud-threat-landscape',
    label: 'Wiz Cloud Threat Landscape',
    script: 'scripts/import-wiz-cloud-threat-landscape.rb',
    snapshot_root: 'data/imports/wiz-cloud-threat-landscape',
    report_name: 'wiz-cloud-threat-landscape-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 3,
    key: 'misp-galaxy',
    label: 'MISP Galaxy',
    script: 'scripts/import-misp-galaxy.rb',
    snapshot_root: 'data/imports/misp-galaxy',
    report_name: 'misp-galaxy-report.json',
    fetch_args: %w[
      --cluster threat-actor
      --cluster 360net
      --cluster microsoft-activity-group
      --cluster tidal-groups
      --cluster ransomware
      --cluster intelligence-agencies
      --cluster mitre-ics-groups
    ],
    fetch_limit: true
  ),
  Source.new(
    priority: 4,
    key: 'etda-thaicert',
    label: 'ETDA / ThaiCERT Threat Group Cards',
    script: 'scripts/import-etda-thaicert.rb',
    snapshot_root: 'data/imports/etda-thaicert',
    report_name: 'etda-thaicert-report.json',
    fetch_limit: true
  ),
  Source.new(
    priority: 5,
    key: 'malpedia',
    label: 'Malpedia',
    script: 'scripts/import-malpedia.rb',
    snapshot_root: 'data/imports/malpedia',
    report_name: 'malpedia-report.json',
    fetch_limit: true
  ),
  Source.new(
    priority: 6,
    key: 'aptmap',
    label: 'APTmap',
    script: 'scripts/import-aptmap.rb',
    snapshot_root: 'data/imports/aptmap',
    report_name: 'aptmap-report.json',
    fetch_limit: true
  ),
  Source.new(
    priority: 7,
    key: 'eternal-liberty',
    label: 'EternalLiberty',
    script: 'scripts/import-eternal-liberty.rb',
    snapshot_root: 'data/imports/eternal-liberty',
    report_name: 'eternal-liberty-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 8,
    key: 'microsoft-threat-actor-list',
    label: 'Microsoft Threat Actor List',
    script: 'scripts/import-microsoft-threat-actor-list.rb',
    snapshot_root: 'data/imports/microsoft-threat-actor-list',
    report_name: 'microsoft-threat-actor-list-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 9,
    key: 'apt-groups-operations',
    label: 'APT Groups & Operations',
    script: 'scripts/import-apt-groups-operations.rb',
    snapshot_root: 'data/imports/apt-groups-operations',
    report_name: 'apt-groups-operations-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 10,
    key: 'aptnotes',
    label: 'APTnotes',
    script: 'scripts/import-aptnotes.rb',
    snapshot_root: 'data/imports/aptnotes',
    report_name: 'aptnotes-report.json',
    fetch_limit: true
  ),
  Source.new(
    priority: 11,
    key: 'rapid7-aba-detections',
    label: 'Rapid7 ABA Detections',
    script: 'scripts/import-rapid7-aba-detections.rb',
    snapshot_root: 'data/imports/rapid7-aba-detections',
    report_name: 'rapid7-aba-detections-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 12,
    key: 'ransomlook',
    label: 'RansomLook',
    script: 'scripts/import-ransomlook.rb',
    snapshot_root: 'data/imports/ransomlook',
    report_name: 'ransomlook-report.json',
    fetch_limit: true
  ),
  Source.new(
    priority: 13,
    key: 'reddrip7-apt-digital-weapon',
    label: 'RedDrip7 APT_Digital_Weapon',
    script: 'scripts/import-reddrip7-apt-digital-weapon.rb',
    snapshot_root: 'data/imports/reddrip7-apt-digital-weapon',
    report_name: 'reddrip7-apt-digital-weapon-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 14,
    key: 'ransomware-tool-matrix',
    label: 'BushidoUK Ransomware Tool Matrix',
    script: 'scripts/import-ransomware-tool-matrix.rb',
    snapshot_root: 'data/imports/ransomware-tool-matrix',
    report_name: 'ransomware-tool-matrix-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 15,
    key: 'ransomware-vulnerability-matrix',
    label: 'BushidoUK Ransomware Vulnerability Matrix',
    script: 'scripts/import-ransomware-vulnerability-matrix.rb',
    snapshot_root: 'data/imports/ransomware-vulnerability-matrix',
    report_name: 'ransomware-vulnerability-matrix-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 16,
    key: 'russian-apt-tool-matrix',
    label: 'BushidoUK Russian APT Tool Matrix',
    script: 'scripts/import-russian-apt-tool-matrix.rb',
    snapshot_root: 'data/imports/russian-apt-tool-matrix',
    report_name: 'russian-apt-tool-matrix-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 17,
    key: 'bushido-breach-reports',
    label: 'BushidoToken Breach Reports',
    script: 'scripts/import-bushido-breach-reports.rb',
    snapshot_root: 'data/imports/bushido-breach-reports',
    report_name: 'bushido-breach-reports-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 18,
    key: 'curated-intel-moveit-transfer',
    label: 'Curated Intelligence MOVEit Transfer Tracking',
    script: 'scripts/import-curated-intel-moveit-transfer.rb',
    snapshot_root: 'data/imports/curated-intel-moveit-transfer',
    report_name: 'curated-intel-moveit-transfer-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 19,
    key: 'sophos-threat-profiles',
    label: 'Sophos Threat Profiles',
    script: 'scripts/import-sophos-threat-profiles.rb',
    snapshot_root: 'data/imports/sophos-threat-profiles',
    report_name: 'sophos-threat-profiles-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 20,
    key: 'google-cloud-apt-groups',
    label: 'Google Cloud APT Groups',
    script: 'scripts/import-google-cloud-apt-groups.rb',
    snapshot_root: 'data/imports/google-cloud-apt-groups',
    report_name: 'google-cloud-apt-groups-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 21,
    key: 'breach-hq-threat-actors',
    label: 'BreachHQ Threat Actors',
    script: 'scripts/import-breach-hq-threat-actors.rb',
    snapshot_root: 'data/imports/breach-hq-threat-actors',
    report_name: 'breach-hq-threat-actors-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 22,
    key: 'dragos-threat-groups',
    label: 'Dragos Threat Groups',
    script: 'scripts/import-dragos-threat-groups.rb',
    snapshot_root: 'data/imports/dragos-threat-groups',
    report_name: 'dragos-threat-groups-report.json',
    fetch_limit: false
  ),
  Source.new(
    priority: 23,
    key: 'unit42-threat-actor-groups',
    label: 'Unit 42 Threat Actor Groups',
    script: 'scripts/import-unit42-threat-actor-groups.rb',
    snapshot_root: 'data/imports/unit42-threat-actor-groups',
    report_name: 'unit42-threat-actor-groups-report.json',
    fetch_limit: false
  )
].freeze

SOURCES = SOURCES_UNSORTED.sort_by(&:priority).freeze

priorities = SOURCES.map(&:priority)
if priorities.uniq.size != priorities.size
  abort 'import-automated-sources.rb: duplicate priority values in SOURCES_UNSORTED'
end
unless SOURCES.first&.key == 'mitre-attack' && SOURCES.first&.priority == 1
  abort 'import-automated-sources.rb: mitre-attack must have priority 1 and sort first'
end

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
  opts.banner = 'Usage: ruby scripts/import-automated-sources.rb [options]

When using --apply locally, commit _data/actors, _threat_actors, _data/generated, api (and _malware if changed).
See docs/keeping-actor-pages-current.md.'

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
  command += Array(source.fetch_args)
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
