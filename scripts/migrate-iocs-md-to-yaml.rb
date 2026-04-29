#!/usr/bin/env ruby
# frozen_string_literal: true

# Migrates extractable IOC bullets from ## Notable Indicators of Compromise (IOCs)
# into each actor's `iocs:` map in _data/actors/<slug>.yml, using the same extraction
# logic as scripts/generate-indexes.rb (ThreatActorIndexGenerator#extract_iocs).
#
# Usage:
#   ruby scripts/migrate-iocs-md-to-yaml.rb --dry-run
#   ruby scripts/migrate-iocs-md-to-yaml.rb --apply
#   ruby scripts/migrate-iocs-md-to-yaml.rb --apply --actor apt28
#
# After --apply, regenerate Markdown IOC sections if desired:
#   ruby scripts/generate-pages.rb --force --actor <slug>

require_relative 'actor_store'
require_relative 'generate-indexes'
require_relative 'ioc_yaml_reader'

RECORD_TYPE_TO_IOCS_KEY = {
  'ip_address' => 'ips',
  'domain' => 'domains',
  'url' => 'urls',
  'email' => 'emails',
  'cve' => 'cves',
  'md5' => 'md5',
  'sha1' => 'sha1',
  'sha256' => 'sha256',
  'attack_technique' => 'attack_techniques'
}.freeze

# Exclude ambiguous prose/backtick blobs (same headings often carry labels after " - ").
URL_SCHEMA_PATTERN = /\Ahttps?:\/\/[^\s<>`]+\z/i.freeze
DOMAIN_LABEL_PATTERN = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/i.freeze

def ipv4_octets_valid?(val)
  parts = val.split('.')
  parts.length == 4 && parts.all? { |p| p.to_i.to_s == p && p.to_i.between?(0, 255) }
end

def acceptable_for_yaml_migration?(rec)
  val = rec[:normalized_value].to_s.strip
  return false if val.empty?

  case rec[:type].to_s
  when 'url'
    val.match?(URL_SCHEMA_PATTERN)
  when 'domain'
    !val.match?(/\s/) && val.match?(DOMAIN_LABEL_PATTERN)
  when 'ip_address'
    val.match?(ThreatActorIndexGenerator::IPV4_PATTERN) && ipv4_octets_valid?(val)
  else
    true
  end
end

def usage
  warn <<~USAGE
    Usage: #{$PROGRAM_NAME} [--dry-run | --apply] [--actor SLUG]

    Merges Markdown IOC bullets into actor YAML under `iocs:` (union with existing values).
    Only atomic extractions (same as index generation) are migrated.
  USAGE
end

def normalize_iocs_hash(actor)
  raw = actor['iocs']
  return {} unless raw.is_a?(Hash)

  raw.each_with_object({}) do |(k, v), h|
    h[k.to_s] = v
  end
end

# Same unified IOC view as generate-indexes / validate (nested `iocs:` plus legacy lists).
def baseline_iocs(actor)
  IocYamlReader.merged_iocs_sources(actor).transform_values do |vals|
    Array(vals).map(&:to_s).map(&:strip).reject(&:empty?)
  end
end

# Returns [delta Hash (yaml_key => [new values]), merged_nested_iocs Hash]
def compute_iocs_merge(actor, records)
  baseline = baseline_iocs(actor).transform_values do |v|
    Array(v).map(&:to_s).map(&:strip).reject(&:empty?)
  end

  iocs = normalize_iocs_hash(actor).transform_values do |v|
    v.is_a?(Array) ? v.map(&:to_s) : v
  end
  delta = Hash.new { |h, k| h[k] = [] }

  records.each do |rec|
    next unless rec[:atomic]
    next unless acceptable_for_yaml_migration?(rec)

    yaml_key = RECORD_TYPE_TO_IOCS_KEY[rec[:type].to_s]
    next unless yaml_key

    val = rec[:normalized_value].to_s.strip
    next if val.empty?

    val = val.upcase if yaml_key == 'attack_techniques'

    base_vals = baseline[yaml_key] || []
    next if base_vals.any? { |e| e.casecmp?(val) }

    nested = Array(iocs[yaml_key]).map(&:to_s).map(&:strip)
    iocs[yaml_key] = nested + [val]
    baseline[yaml_key] = base_vals + [val]
    delta[yaml_key] << val
  end

  [delta, iocs]
end

def actor_slug(actor)
  ActorStore.slug_for(actor['url'])
end

def normalize_actor_slug(filter)
  filter.to_s.sub(%r{\A/}, '').sub(%r{/\z}, '')
end

def parse_args(argv)
  apply = argv.include?('--apply')
  dry_run = !apply

  unknown = argv.select { |a| a.start_with?('--') } - %w[--dry-run --apply --actor --help -h]
  unless unknown.empty?
    unknown.each { |o| warn "Unknown option: #{o}" }
    usage
    exit 2
  end

  actor_filter = nil
  if (i = argv.index('--actor'))
    actor_filter = argv[i + 1]
    if actor_filter.nil? || actor_filter.start_with?('--')
      warn '--actor requires a slug'
      exit 2
    end

    actor_filter = normalize_actor_slug(actor_filter)
  end

  [dry_run, apply, actor_filter]
end

def main(argv)
  if argv.include?('--help') || argv.include?('-h')
    usage
    exit 0
  end

  dry_run, apply, actor_filter = parse_args(argv)

  generator = ThreatActorIndexGenerator.new
  updated = 0

  generator.instance_variable_get(:@actors).each do |actor|
    slug = actor_slug(actor)
    next if actor_filter && slug != actor_filter

    page_path = generator.send(:page_path_for, actor['url'])
    page = generator.instance_variable_get(:@pages)[page_path]
    unless page
      warn "skip #{slug}: no page #{page_path}" if actor_filter
      next
    end

    section = generator.send(:extract_section, page[:body], ThreatActorIndexGenerator::REQUIRED_IOC_HEADING)
    records = generator.send(:extract_iocs, actor, page, section)
    next if records.empty?

    delta, merged_iocs = compute_iocs_merge(actor, records)
    next if delta.empty?

    parts = delta.map { |k, vals| "#{k}(#{vals.size})" }.join(', ')
    line = "#{slug}: merged #{parts}"

    if dry_run
      puts line
      updated += 1
    elsif apply
      actor['iocs'] = merged_iocs
      ActorStore.save_actor(actor)
      puts "#{line} -> wrote _data/actors/#{slug}.yml"
      updated += 1
    end
  end

  if updated.zero?
    msg = 'migrate-iocs-md-to-yaml: no YAML updates needed (Markdown IOC bullets already covered by nested `iocs:` and/or legacy IOC fields).'
    dry_run ? puts(msg) : warn(msg)
  end

  exit 0
end

main(ARGV) if __FILE__ == $PROGRAM_NAME
